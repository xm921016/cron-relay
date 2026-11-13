# -*- coding: utf-8 -*-
"""号主邮件派发（2026-11-06 新增）：登记成功通知 + 到期提醒。

解决什么问题
------------
登记成功时客户收不到任何确认，只能靠客服口头转告；账号快到期也没有任何提醒，
到期就静默降级成公益号。这两类邮件现在统一走 mail_queue 队列：
  worker 排队（/api/join_manual 成功后排 reg；/api/mail_scan 每天扫一遍到期档位）
  → 本脚本领取（/api/mail_pending）→ notify.notify_reg_ok / notify.notify_expire 发信
  → 回写（/api/mail_sent）。

去重与作废口径（都在 worker 侧做，这里只管发）
  唯一键 (pool,uid,kind,ref)：reg 的 ref=登记日、exp 的 ref=到期日。
  续费（exp/added 变了）→ ref 对不上 → worker 标 skipped/dropped，不发。
  群号在 /api/mail_pending 发放时按最新 reg_cfg 现查 → 客服在控制台改群号立即生效。

为什么挂在 notify-dead 旁边每 30 分钟跑一次
  登记邮件越快越好；到期邮件一天一封足够。队列领取是幂等的（claimed 状态 + 2 小时超时），
  跑密一点只是多几次空查询，不发重。D1 闸门保证到期扫描每天最多一次全表。

环境变量（GitHub Secret 注入）：WORKER_URL / ASSIGN_PASS / EMAIL_FROM / EMAIL_AUTH_CODE
用法：
  python notify_mail.py           # 扫描（每天一次）+ 领取 + 发送 + 回写
  python notify_mail.py --dry     # 只查询不发送（不动状态）
  python notify_mail.py --noscan  # 跳过扫描（只想清积压时用）
"""
import json
import os
import re
import sys
import time

import requests

WORKER = (os.environ.get("WORKER_URL", "") or "https://xx1031.xyz").strip().rstrip("/")
PASS = (os.environ.get("ASSIGN_PASS", "") or os.environ.get("NB_PASS", "")).strip()
DRY = "--dry" in sys.argv
NOSCAN = "--noscan" in sys.argv
LIMIT = int(os.environ.get("MAIL_LIMIT", "50") or 50)

# 邮箱粗校验（2026-11-07 新增）：只挡「明显不可能存在」的地址，不做 RFC 级严格校验，
# 免得把少见但合法的写法误杀。起因：客户把邮箱填成 1363273659.@qq.com（本地部分末尾
# 多了一个点），QQ 回 550 recipient non-existent，一条坏数据把整班 workflow 打成红的。
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


def email_ok(addr):
    s = (addr or "").strip()
    if not s or len(s) > 254 or not _EMAIL_RE.match(s):
        return False
    local, _, domain = s.partition("@")
    # 首尾带点、连续点都是 SMTP 必然拒收的形态（".a@x.com" / "a.@x.com" / "a..b@x.com"）
    if local.startswith(".") or local.endswith(".") or ".." in s:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    return True


def call(path, payload, timeout=60):
    r = requests.post(WORKER + path, json=payload, timeout=timeout)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"message": (r.text or "")[:200]}


def main():
    if not PASS:
        print("[notify-mail] 缺 ASSIGN_PASS，退出")
        return 1

    # ① 到期扫描（worker 内置 KV 每日闸门，多跑也只扫一次）
    if not NOSCAN:
        code, d = call("/api/mail_scan", {"pass": PASS, "dry": DRY})
        if code != 200 or not d.get("ok"):
            print(f"[notify-mail] 到期扫描失败 HTTP {code}: {d.get('message')}")
            return 1
        if d.get("skipped"):
            print(f"[notify-mail] 到期扫描：{d.get('message')}")
        else:
            print(f"[notify-mail] 到期扫描：扫 {d.get('scanned')} 号，入队 {d.get('will_enqueue')} 条"
                  + (f"，作废旧提醒 {d.get('dropped_stale')} 条" if d.get("dropped_stale") is not None else ""))

    # ② 领取待发（循环清队列：CF 发令腿只有每小时一班，一班内尽量多发；
    #    每轮领 ≤50、每封间隔 8 秒，80 封 ≈ 13 分钟，卡在 workflow 15 分钟超时内）
    all_sent, all_failed = [], []
    all_bad = []   # 邮箱格式非法、根本没进 SMTP 的条数（不计入失败，见文件末尾退出码说明）
    while True:
        # 上限检查必须在 claim 之前 —— 否则领完 50 条才发现到量，直接 break 会把
        # 这批挂在 claimed 等 2 小时超时（2026-11-06 实测连留三班 150 条的教训）
        if len(all_sent) + len(all_failed) >= 80:
            print("[notify-mail] 已发满 80 封/班（≈13 分钟，留足 workflow 超时余量），剩余下一班继续")
            break
        code, data = call("/api/mail_pending", {"pass": PASS, "limit": LIMIT, "dry": DRY})
        if code != 200 or not data.get("ok"):
            msg = str(data.get("message") or "")
            # 2026-11-08：D1 免费读额度打满时 /api/mail_pending 必回 503（读 mail_queue 失败）。
            # 此时队列行仍是 pending、没被 claim（claimed_at 为空），额度重置后下一班自动补发，不丢件。
            # 这种错误会连续复现十几班，若照旧 return 1，GitHub 会连发十几封「Run failed」告警邮件，
            # 把真正的故障淹没。故只打 warning 不判死（与 run.py「可播号不足一半只告警」同一口径）。
            if "row read limit" in msg or "exceeded D1" in msg:
                print("::warning::[notify-mail] D1 读额度已打满，本轮跳过；队列未动，额度重置后自动补发")
                return 0
            print(f"[notify-mail] 领取失败 HTTP {code}: {msg}")
            return 1
        todo = data.get("to_send") or []
        skipped = data.get("skipped") or []
        print(f"[notify-mail] 本轮待发 {len(todo)} 条，判定不发 {len(skipped)} 条")
        for s in skipped:
            print(f"   - 不发 {s.get('name') or s.get('uid')} [{s.get('kind')}]: {s.get('why')}")

        if not todo:
            break
        if DRY:
            for t in todo:
                print(f"   [dry] {t.get('kind')} → {t.get('email')}（{t.get('name') or t.get('uid')}，群 {t.get('group') or '无'}）")
            return 0

        import notify
        if not notify.mail_ready():
            print("[notify-mail] EMAIL_FROM/EMAIL_AUTH_CODE 未配置，跳过（状态保持 claimed，2 小时后自动回退）")
            return 1

        sent, failed, bad = [], [], []   # 每轮单独一份（跑完随轮回写清空）

        for idx, t in enumerate(todo):
            # 2026-11-06：QQ SMTP 对高频连发直接断连（实测连续 19 封后全部 Connection unexpectedly
            # closed），每封之间强制间隔 8 秒。失败的照旧退回 pending，下一班自动重试，不丢件。
            if idx or all_sent or all_failed:
                time.sleep(8)
            who = str(t.get("name") or t.get("uid") or "")
            if who.startswith("manual:"):
                who = who[7:] or str(t.get("uid") or "")
            kind = str(t.get("kind") or "")
            # 2026-11-07：格式非法的邮箱不进 SMTP（一定 550，只会白烧一封的配额 + 把班次打红）。
            # 仍然按 retry 回写，让 attempts 正常累加，3 次后由 worker 自动标 dropped。
            email = (t.get("email") or "").strip()
            if not email_ok(email):
                bad.append(t)
                all_bad.append(t)
                print(f"   [{who}] 邮箱格式非法，不发（{email or '空'}）")
                continue
            try:
                if kind == "reg":
                    ok = notify.notify_reg_ok(t.get("email"), "", who, t.get("group") or "")
                elif kind.startswith("exp"):
                    days = int(kind[3:]) if kind[3:].isdigit() else 30
                    ok = notify.notify_expire(t.get("email"), "", who, t.get("group") or "",
                                              t.get("exp") or t.get("ref") or "", days)
                elif kind == "songfix":
                    # 2026-11-13 新增：共创歌不计入任务的换歌提醒（ref=歌曲 id，仅用于去重）
                    ok = notify.notify_songfix(t.get("email"), "", who, t.get("group") or "")
                else:
                    print(f"   [{who}] 未知类型 {kind}，跳过")
                    ok = False
            except Exception as e:
                print(f"   [{who}] 发信异常：{e}")
                ok = False
            if ok:
                sent.append(t)
                all_sent.append(t)
                print(f"   [{who}] 已直邮 {t.get('email')}（{kind}，群 {t.get('group') or '无'}）")
            else:
                failed.append(t)
                all_failed.append(t)
                print(f"   [{who}] 发信失败（{kind}）")

        # 回写：成功标 sent；失败退回 pending 下轮再试
        if sent:
            code, d = call("/api/mail_sent", {"pass": PASS, "result": "sent", "items": [
                {"pool": x["pool"], "uid": x["uid"], "kind": x["kind"], "ref": x["ref"]} for x in sent]})
            print(f"[notify-mail] 已标记 sent {len(sent)} 条（HTTP {code} {d.get('updated')}）")
        if failed or bad:
            retry_items = failed + bad
            code, d = call("/api/mail_sent", {"pass": PASS, "result": "retry", "items": [
                {"pool": x["pool"], "uid": x["uid"], "kind": x["kind"], "ref": x["ref"]} for x in retry_items]})
            dp = d.get("dropped") or 0
            msg = (f"[notify-mail] 失败 {len(failed)} 条 + 非法邮箱 {len(bad)} 条已回写（HTTP {code}）："
                   f"退回 {len(retry_items) - dp} 条重试")
            if dp:
                msg += f"，放弃 {dp} 条（连续失败 3 次 / 非法邮箱累计 3 次，标 dropped 不再试）"
            print(msg)
        sent, failed, bad = [], [], []

    print(f"[notify-mail] 完成：成功 {len(all_sent)} / 失败 {len(all_failed)}"
          + (f" / 非法邮箱 {len(all_bad)}" if all_bad else ""))
    # 2026-11-07 改退出码：原来「有一条失败就 exit 1」，一个客户把邮箱填错（1363273659.@qq.com）
    # 就让整班 workflow 变红，GitHub 每小时发一封失败邮件，真故障反而被淹掉。改成只有
    # 「一封都没发成功、而且确实有失败」才判 1；局部失败交给日志 + 队列自动重试兜。
    if all_failed and not all_sent:
        print("[notify-mail] 全部失败，判为真故障")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

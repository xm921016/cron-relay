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
import sys

import requests

WORKER = (os.environ.get("WORKER_URL", "") or "https://xx1031.xyz").strip().rstrip("/")
PASS = (os.environ.get("ASSIGN_PASS", "") or os.environ.get("NB_PASS", "")).strip()
DRY = "--dry" in sys.argv
NOSCAN = "--noscan" in sys.argv
LIMIT = int(os.environ.get("MAIL_LIMIT", "50") or 50)


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

    # ② 领取待发
    code, data = call("/api/mail_pending", {"pass": PASS, "limit": LIMIT, "dry": DRY})
    if code != 200 or not data.get("ok"):
        print(f"[notify-mail] 领取失败 HTTP {code}: {data.get('message')}")
        return 1
    todo = data.get("to_send") or []
    skipped = data.get("skipped") or []
    print(f"[notify-mail] 待发 {len(todo)} 条，判定不发 {len(skipped)} 条")
    for s in skipped:
        print(f"   - 不发 {s.get('name') or s.get('uid')} [{s.get('kind')}]: {s.get('why')}")

    if not todo:
        print("[notify-mail] 没有待发邮件，结束")
        return 0
    if DRY:
        for t in todo:
            print(f"   [dry] {t.get('kind')} → {t.get('email')}（{t.get('name') or t.get('uid')}，群 {t.get('group') or '无'}）")
        return 0

    import notify
    if not notify.mail_ready():
        print("[notify-mail] EMAIL_FROM/EMAIL_AUTH_CODE 未配置，跳过（状态保持 claimed，2 小时后自动回退）")
        return 1

    sent, failed = [], []
    for t in todo:
        who = str(t.get("name") or t.get("uid") or "")
        if who.startswith("manual:"):
            who = who[7:] or str(t.get("uid") or "")
        kind = str(t.get("kind") or "")
        try:
            if kind == "reg":
                ok = notify.notify_reg_ok(t.get("email"), "", who, t.get("group") or "")
            elif kind.startswith("exp"):
                days = int(kind[3:]) if kind[3:].isdigit() else 30
                ok = notify.notify_expire(t.get("email"), "", who, t.get("group") or "",
                                          t.get("exp") or t.get("ref") or "", days)
            else:
                print(f"   [{who}] 未知类型 {kind}，跳过")
                ok = False
        except Exception as e:
            print(f"   [{who}] 发信异常：{e}")
            ok = False
        if ok:
            sent.append(t)
            print(f"   [{who}] 已直邮 {t.get('email')}（{kind}，群 {t.get('group') or '无'}）")
        else:
            failed.append(t)
            print(f"   [{who}] 发信失败（{kind}）")

    # ③ 回写：成功标 sent；失败退回 pending 下轮再试
    if sent:
        code, d = call("/api/mail_sent", {"pass": PASS, "result": "sent", "items": [
            {"pool": x["pool"], "uid": x["uid"], "kind": x["kind"], "ref": x["ref"]} for x in sent]})
        print(f"[notify-mail] 已标记 sent {len(sent)} 条（HTTP {code} {d.get('updated')}）")
    if failed:
        code, d = call("/api/mail_sent", {"pass": PASS, "result": "retry", "items": [
            {"pool": x["pool"], "uid": x["uid"], "kind": x["kind"], "ref": x["ref"]} for x in failed]})
        print(f"[notify-mail] 已退回 pending {len(failed)} 条（HTTP {code} {d.get('updated')}）")

    print(f"[notify-mail] 完成：成功 {len(sent)} / 失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())

# -*- coding: utf-8 -*-
"""笔记「发完延时删」A/B 实验（2026-11-05）

要回答的问题：笔记任务是「30 天内发布图文笔记的天数 >= 4」（进度封顶 4）。
如果发完就把这条动态删掉，网易还会不会算这一天？

做法（一次 job 内跑完，不占 relay 并发）：
  1. 对每个实验号：查 vip/info 拿笔记任务进度 -> 发一条 -> 再查一次
  2. 等 DELAY（默认 3600 秒 = 1 小时）
  3. A 组（ARM_DEL）把自己刚发的那条删掉，确认列表里真的没了，再查一次进度
  4. B 组只发不删，作为对照 —— 用来确认「发一条到底会不会让进度 +1」这个前提
  5. 打印 / 落盘结果，第二天再看一次进度就能判定删除有没有副作用

环境变量：
  UIDS      逗号分隔，本次要处理的 uid
  ARM_DEL   逗号分隔，其中哪些要删（其余只发不删）
  DELAY     等待秒数，默认 3600
  NB_PASS / ASSIGN_PASS   /api/assign 口令（下发明文 CK 的接口）
  WORKER_URL 默认 https://xx1031.xyz

⚠ 只用于实验：不写 D1、不动 notes.py 的生产路径。
"""
import json
import os
import random
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import notes as N  # 复用发布/列表/删除实现，行为与生产完全一致

WORKER_URL = (os.environ.get("WORKER_URL") or "https://xx1031.xyz").rstrip("/")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
NOTE_MISSION = "mission_code_musician_notebook_publish"
RESULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "notes_exp_result.json")


def bj_now():
    return datetime.now(timezone.utc) + timedelta(hours=8)


def bj_str(ms):
    try:
        return (datetime.utcfromtimestamp(ms / 1000) + timedelta(hours=8)).strftime("%m-%d %H:%M")
    except Exception:
        return "-"


def sleep_with_log(sec, step=600):
    left = int(sec)
    while left > 0:
        s = min(step, left)
        time.sleep(s)
        left -= s
        print("[exp] 剩余等待 %d 秒（%s）" % (left, bj_now().strftime("%H:%M")), flush=True)


def fetch_ck(uids):
    """从 /api/assign 拿全池（jobs=1 即全部分给 job=0），只保留需要的 uid。"""
    pw = (os.environ.get("ASSIGN_PASS") or os.environ.get("NB_PASS") or "").strip()
    if not pw:
        print("[exp] 缺口令 ASSIGN_PASS / NB_PASS，无法取号")
        return {}
    want = set(str(u) for u in uids)
    out = {}
    for job, jobs in ((0, 1),):
        params = {"job": job, "jobs": jobs, "pass": pw}
        url = WORKER_URL + "/api/assign?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            d = json.loads(r.read().decode("utf-8"))
        if not d.get("ok"):
            print("[exp] /api/assign 失败：%s" % d.get("message"))
            return {}
        accs = list(d.get("accounts") or []) + list(d.get("idle") or [])
        for a in accs:
            uid = str(a.get("uid") or "")
            if uid in want and (a.get("ck") or "").strip():
                out[uid] = a
        print("[exp] assign 全池 %s 号（m=%s），命中 %d/%d" % (len(accs), d.get("m"), len(out), len(want)))
    return out


def note_progress(client):
    """读笔记任务实时进度（进度封顶 4，拿不到返回 None）。"""
    try:
        r = client._eapi_post("/api/nmusician/workbench/special/right/vip/info", {})
    except Exception as e:
        print("  vip/info 异常: %s" % str(e)[:80])
        return None
    if r.get("code") != 200:
        print("  vip/info code=%s" % r.get("code"))
        return None
    kids = ((r.get("data") or {}).get("furtherTask") or {}).get("children") or []
    for k in kids:
        if str(k.get("missionCode") or "") == NOTE_MISSION:
            try:
                return int(k.get("progressRate"))
            except Exception:
                return None
    return None


def today_events(client):
    """今天（北京）已经发过、且命中我们文案库的事件。"""
    out = []
    today = bj_now().strftime("%m-%d")
    for e in client.list_events(15):
        if bj_str(e.get("eventTime") or 0)[:5] != today:
            continue
        body = e.get("json")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except Exception:
                body = {}
        msg = str((body or {}).get("msg") or "")
        if len(msg) >= 6 and any(q.startswith(msg[:20]) for q in N.QUOTES):
            out.append(e)
    return out


def pick_text():
    text = random.choice(N.QUOTES)
    if "\n" not in text and len(text) > 52:
        for i in range(52, 34, -1):
            if text[i - 1] in "，。、；！？,.!?…":
                text = text[:i]
                break
    return text


def main():
    uids = [x.strip() for x in (os.environ.get("UIDS") or "").split(",") if x.strip()]
    arm_del = set(x.strip() for x in (os.environ.get("ARM_DEL") or "").split(",") if x.strip())
    delay = int(os.environ.get("DELAY") or "3600")
    if not uids:
        print("[exp] 没给 UIDS")
        sys.exit(1)

    print("[exp] 开始 %s | 实验号 %d 个（删 %d）| 等待 %d 秒"
          % (bj_now().strftime("%Y-%m-%d %H:%M:%S"), len(uids), len(arm_del), delay), flush=True)

    pool = fetch_ck(uids)
    rows = []

    # ---- 阶段 1：发 ----
    for uid in uids:
        arm = "A(删)" if uid in arm_del else "B(留)"
        acc = pool.get(uid)
        if not acc:
            rows.append({"uid": uid, "arm": arm, "state": "无CK/未分到", "before": None})
            print("[%s] %s 取不到 CK，跳过" % (uid, arm))
            continue
        row = {"uid": uid, "name": str(acc.get("name") or ""), "arm": arm,
               "before": None, "after_pub": None, "after_del": None,
               "event_id": None, "msg": None, "t_pub": None, "t_del": None, "state": "init"}
        rows.append(row)
        client = N.NeteaseClient(acc.get("ck") or "")
        try:
            if not client.login_check(uid):
                row["state"] = "CK失效"
                print("[%s] CK 失效，跳过" % uid)
                continue
            row["before"] = note_progress(client)
            print("[%s] %s 发前进度=%s" % (uid, arm, row["before"]))

            already = today_events(client)
            if already:
                row["state"] = "今天已发过，跳过"
                print("[%s] 今天已有一条我们发的（id=%s），跳过" % (uid, already[0].get("id")))
                continue

            time.sleep(random.uniform(5, 15))
            text = pick_text()
            img = N.random_local_image(text)
            pic = client.upload_image(img)
            resp = client.publish_event(text, pic)
            code = resp.get("code", -1)
            print("[%s] 发布 code=%s" % (uid, code))
            if code != 200:
                row["state"] = "发布失败 code=%s" % code
                continue
            ev = resp.get("event") or {}
            eid = str(ev.get("id") or "")
            if not eid:
                for e in client.list_events(5):
                    if bj_str(e.get("eventTime") or 0)[:5] == bj_now().strftime("%m-%d"):
                        eid = str(e.get("id") or "")
                        break
            row["event_id"] = eid
            row["msg"] = text
            row["t_pub"] = bj_now().strftime("%Y-%m-%d %H:%M:%S")
            row["state"] = "已发布"
            time.sleep(random.uniform(3, 8))
            row["after_pub"] = note_progress(client)
            print("[%s] 发布后进度=%s event=%s" % (uid, row["after_pub"], eid))
        except Exception as e:
            row["state"] = "异常 %s" % str(e)[:120]
            print("[%s] 异常：%s" % (uid, e))

    published = [r for r in rows if r.get("event_id")]
    dump(rows, "阶段1 已发布 %d 条" % len(published))

    # ---- 阶段 2：等 ----
    if published:
        sleep_with_log(delay)
    else:
        print("[exp] 一条都没发成功，跳过等待与删除")

    # ---- 阶段 3：删（只 A 组）----
    for row in published:
        uid = row["uid"]
        try:
            acc = pool.get(uid) or {}
            client = N.NeteaseClient(acc.get("ck") or "")
            client.login_check(uid)
            if uid in arm_del:
                ok = client.delete_event(row["event_id"])
                row["t_del"] = bj_now().strftime("%Y-%m-%d %H:%M:%S")
                left = [str(e.get("id") or "") for e in client.list_events(15)]
                row["deleted"] = bool(ok)
                row["gone"] = row["event_id"] not in left
                row["state"] = "已删" if (ok and row["gone"]) else "删除失败(delete=%s gone=%s)" % (ok, row["gone"])
                print("[%s] 删除 event=%s -> %s，列表里是否还在=%s"
                      % (uid, row["event_id"], ok, not row["gone"]))
                time.sleep(random.uniform(3, 8))
                row["after_del"] = note_progress(client)
                print("[%s] 删除后进度=%s" % (uid, row["after_del"]))
            else:
                row["after_del"] = note_progress(client)
                row["state"] = "保留(对照)"
                print("[%s] 对照组保留，当前进度=%s" % (uid, row["after_del"]))
        except Exception as e:
            row["state"] = "收尾异常 %s" % str(e)[:120]
            print("[%s] 收尾异常：%s" % (uid, e))

    dump(rows, "实验结束")

    # ---- 汇总表 ----
    print("\n================ 实验汇总 ================", flush=True)
    print("%-12s %-7s %-8s %-8s %-8s %-16s %s"
          % ("uid", "分组", "发前", "发后", "删后", "事件id", "状态"))
    for r in rows:
        print("%-12s %-7s %-8s %-8s %-8s %-16s %s"
              % (r.get("uid"), r.get("arm"), r.get("before"), r.get("after_pub"),
                 r.get("after_del"), r.get("event_id") or "-", r.get("state")))
    print("判定：明天再看这 %d 个号的实时进度 —— A 组若仍 >= 发后值（+1 没掉），说明删了不影响"
          % len(published), flush=True)


def dump(rows, tag):
    try:
        payload = {"at": bj_now().strftime("%Y-%m-%d %H:%M:%S"), "tag": tag, "rows": rows}
        with open(RESULT_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=1)
        print("[exp] %s，已写 %s" % (tag, RESULT_FILE), flush=True)
    except Exception as e:
        print("[exp] 落盘失败：%s" % e)


if __name__ == "__main__":
    main()

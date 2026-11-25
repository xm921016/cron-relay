# -*- coding: utf-8 -*-
"""VIP 赠送小号池 —— 号池里「黑胶 V2+ 且本月从未赠送」的号，排队依次生成赠送链接。

设计（2026-11-24，配合号体检网页版）：
  - 状态落盘 tmp/vip_gift_pool.json（month/账号表/预留额度/最近使用时刻）
  - 探测复用签到同款 Android eapi 会话（signin.NeteaseClient），只读接口 page/info
  - 月度口径：官方额度每月重置、token 当月月底作废 → 跨月自动全量重探
  - 自动加新号：增量探测 = 镜像 accounts 里有而池里没有的 uid
  - 生成链接 take(n)：按轮换序取号 → 现场复核剩余额度 → token/create → 生成领取链接
  - 预留(reserved)：生成 1 张卡先按 7 天记账，refresh 重探时以官方 left 为准自动对账
  - 安全：本模块只调 page/info + token/create，绝不调 accept（不替任何人领会员）

CLI:
  python cron-relay/vip_gift_pool.py status           # 池概况
  python cron-relay/vip_gift_pool.py refresh [--full] # 增量/全量探测
  python cron-relay/vip_gift_pool.py take 3           # 生成 3 张赠送链接
"""
import json
import os
import random
import re
import sqlite3
import string
import sys
import threading
import time
from datetime import datetime, timezone, timedelta

CR = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(CR)
sys.path.insert(0, CR)

BJ = timezone(timedelta(hours=8))
STATE_F = os.path.join(PROJ, "tmp", "vip_gift_pool.json")
TOKENS_F = os.path.join(PROJ, "tmp", "vip_gift_tokens.json")
PAGEINFO_URL = "https://interface3.music.163.com/eapi/vipactivity/app/vip/invitation/page/info"
TOKENCREATE_URL = "https://interface3.music.163.com/eapi/vipactivity/app/vip/invitation/token/create"
DETAIL_URL = "https://interface3.music.163.com/eapi/vipactivity/app/vip/invitation/detail/info/get"
# 每张卡先按 7 天预留（实测 accept 返回 duration 由官方定，refresh 时对账）
RESERVE_DAYS = 7
# 领取页 URL 形态（2026-11-24 实测样本：https://y.music.163.com/g/vip-invite-cashier/radsjl245?token=...）
LINK_TPL = "https://y.music.163.com/g/vip-invite-cashier/{slug}?token={token}"
# 短链接口（2026-11-24 实测：/eapi/middle/shorturl/generate，仅支持 *.163.com/*.126.net）
SHORTURL_URL = "https://music.163.com/eapi/middle/shorturl/generate"

_LOCK = threading.RLock()


def now_month():
    return datetime.now(BJ).strftime("%Y-%m")


def month_end_ms():
    """当月最后一天 23:59:59.999（token 官方作废时刻，实测 = 月底）。"""
    now = datetime.now(BJ)
    if now.month == 12:
        nxt = now.replace(year=now.year + 1, month=1, day=1)
    else:
        nxt = now.replace(month=now.month + 1, day=1)
    nxt = nxt.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(nxt.timestamp() * 1000) - 1


# ---------------------------------------------------------------- 状态
def load_state():
    with _LOCK:
        if os.path.exists(STATE_F):
            with open(STATE_F, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"month": now_month(), "updated_at": "", "accounts": {}}


def save_state(st):
    with _LOCK:
        st["updated_at"] = datetime.now(BJ).strftime("%Y-%m-%d %H:%M:%S")
        tmp = STATE_F + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False)
        os.replace(tmp, STATE_F)


def load_tokens():
    with _LOCK:
        if os.path.exists(TOKENS_F):
            with open(TOKENS_F, "r", encoding="utf-8") as f:
                return json.load(f)
        return []


def save_tokens(tokens):
    with _LOCK:
        tmp = TOKENS_F + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(tokens, f, ensure_ascii=False)
        os.replace(tmp, TOKENS_F)


# ---------------------------------------------------------------- 探测
def _client(ck):
    from signin import NeteaseClient
    return NeteaseClient(ck)


def probe_one(ck):
    """只读查一个号的赠送资格页。返回统一字段。"""
    cli = _client(ck)
    page = cli.eapi_post(PAGEINFO_URL, {"checktoken": ""})
    d = page.get("data") or {}
    if not isinstance(d, dict):
        d = {}
    out = {
        "page_code": page.get("code", -1),
        "vip_level": d.get("vipLevel", 0) or 0,
        "can_send_vip": d.get("canSendVip", 0) or 0,
        "send_total": d.get("sendVipDayTotal", 0) or 0,
        "send_left": d.get("sendVipDayLeft", 0) or 0,
    }
    try:
        out["never_gifted"] = 1 if (int(out["vip_level"]) >= 2
                                    and int(out["can_send_vip"]) == 1
                                    and int(out["send_total"]) > 0
                                    and int(out["send_left"]) == int(out["send_total"])) else 0
    except (TypeError, ValueError):
        out["never_gifted"] = 0
    return out


def mirror_uids():
    """从最新镜像拿全量在池账号（uid → ck/pool/name/email）。"""
    import acc_health
    dbf, _how = acc_health.ensure_mirror(False)
    con = sqlite3.connect(dbf)
    rows = con.execute(
        "SELECT uid, name, ck, pool, email FROM accounts WHERE ck!=''").fetchall()
    con.close()
    return {str(r[0]): {"ck": r[2], "pool": r[3], "name": r[1], "email": r[4] or ""} for r in rows}


def probe(full=False, progress_cb=None, stop_flag=None):
    """增量（默认）/全量探测。返回 (done, total)。跨月自动全量。"""
    st = load_state()
    full = full or (st.get("month") != now_month())
    meta = mirror_uids()
    if full:
        todo = sorted(meta.keys())
    else:
        todo = sorted(u for u in meta if u not in st["accounts"])
    total = len(todo)
    done = 0
    for uid in todo:
        if stop_flag and stop_flag.get("stop"):
            break
        m = meta[uid]
        try:
            r = probe_one(m["ck"])
            r["ok"] = True
        except Exception as e:
            r = {"page_code": "EXC", "vip_level": 0, "can_send_vip": 0,
                 "send_total": 0, "send_left": 0, "never_gifted": 0,
                 "ok": False, "err": str(e)[:80]}
        old = st["accounts"].get(uid) or {}
        st["accounts"][uid] = {
            "name": m["name"], "pool": m["pool"], "email": m["email"],
            "vip_level": r["vip_level"], "can_send_vip": r["can_send_vip"],
            "send_total": r["send_total"], "send_left": r["send_left"],
            "never_gifted": r["never_gifted"],
            "ok": r["ok"], "page_code": r["page_code"],
            "reserved": 0 if full else old.get("reserved", 0),
            "last_used": old.get("last_used", ""),
            "probed_at": datetime.now(BJ).strftime("%Y-%m-%d %H:%M:%S"),
        }
        done += 1
        if progress_cb:
            progress_cb(done, total, uid, r)
        time.sleep(random.uniform(1.5, 3.0))
    st["month"] = now_month()
    save_state(st)
    return done, total


def reconcile(uid):
    """生成链接后对账：现场复核官方剩余额度，修正本地预留。返回修正后的 left。"""
    st = load_state()
    a = st["accounts"].get(uid)
    if not a:
        return None
    meta = mirror_uids().get(uid)
    if not meta:
        return None
    r = probe_one(meta["ck"])
    a["send_left"] = r["send_left"]
    a["send_total"] = r["send_total"]
    a["vip_level"] = r["vip_level"]
    a["never_gifted"] = r["never_gifted"]
    # 官方 left 是唯一事实：预留字段清零重建
    a["reserved"] = max(0, a.get("reserved", 0) - RESERVE_DAYS)
    save_state(st)
    return a["send_left"]


# ---------------------------------------------------------------- 池视图与轮换
def eligible(st=None):
    """可提取的 donor 队列（轮换序）：
    1) 本月没用过的号优先（never_gifted=1 且 reserved=0）
    2) 再按最近使用时刻从旧到新（LRU 轮换，雨露均沾）
    3) 同刻按剩余额度大者在前（额度厚，够扣）"""
    st = st or load_state()
    out = []
    for uid, a in st["accounts"].items():
        if not a.get("ok"):
            continue
        try:
            if int(a.get("vip_level") or 0) < 2 or int(a.get("can_send_vip") or 0) != 1:
                continue
            left = int(a.get("send_left") or 0)
            resv = int(a.get("reserved") or 0)
        except (TypeError, ValueError):
            continue
        if left - resv < RESERVE_DAYS:
            continue
        fresh = 0 if (a.get("never_gifted") == 1 and resv == 0) else 1
        out.append((fresh, a.get("last_used") or "", -left, uid, a))
    out.sort(key=lambda x: (x[0], x[1], x[2]))
    return out


def stats():
    st = load_state()
    v2 = never = avail_days = 0
    ok_cnt = 0
    for a in st["accounts"].values():
        if not a.get("ok"):
            continue
        ok_cnt += 1
        try:
            if int(a.get("vip_level") or 0) >= 2 and int(a.get("can_send_vip") or 0) == 1:
                v2 += 1
                if a.get("never_gifted") == 1:
                    never += 1
                    avail_days += int(a.get("send_left") or 0)
        except (TypeError, ValueError):
            pass
    return {"month": st.get("month"), "probed": ok_cnt, "known": len(st["accounts"]),
            "v2": v2, "never_gifted": never, "avail_days": avail_days,
            "queue": len(eligible(st)), "updated_at": st.get("updated_at", "")}


# ---------------------------------------------------------------- 生成赠送链接
def _slug(n=9):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def make_link(token):
    return LINK_TPL.format(slug=_slug(), token=token)


def take(n=1, progress_cb=None):
    """按轮换序生成 n 张赠送链接（token/create）。
    每张：选号 → 现场复核 left → 发卡 → 记账（last_used/reserved/tokens.json）。
    返回 list[dict(token, link, donor_uid, donor_name, expire_ms, note)]"""
    st = load_state()
    meta = mirror_uids()
    results = []
    for i in range(n):
        q = eligible(st)
        picked = None
        for _fresh, _lu, _negleft, uid, a in q:
            m = meta.get(uid)
            if not m:
                continue
            picked = (uid, a, m)
            break
        if not picked:
            results.append({"error": "池里没有可提取的号（剩余额度都不足 %d 天或未探测）" % RESERVE_DAYS})
            break
        uid, a, m = picked
        cli = _client(m["ck"])
        # 1) 现场复核剩余额度（以官方为准，防本地账虚）
        live = cli.eapi_post(PAGEINFO_URL, {"checktoken": ""})
        d = live.get("data") or {}
        left_now = int(d.get("sendVipDayLeft") or 0)
        if live.get("code") != 200 or int(d.get("canSendVip") or 0) != 1 or left_now < RESERVE_DAYS:
            a["send_left"] = left_now
            a["reserved"] = 0
            a["never_gifted"] = 0
            save_state(st)
            results.append({"error": "跳过 %s(%s)：官方剩余=%s（已记账，换下一个）" % (uid, a.get("name"), left_now)})
            continue
        # 2) 发卡（token/create 只生成卡，不扣额度；额度在别人 accept 时才扣）
        resp = cli.eapi_post(TOKENCREATE_URL, {})
        data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
        tok = str(data.get("token") or "").strip()
        if resp.get("code") != 200 or not tok:
            results.append({"error": "token/create 失败 uid=%s code=%s msg=%s" % (
                uid, resp.get("code"), str(resp.get("message", ""))[:60])})
            continue
        tok = resp["data"]["token"]
        link = make_link(tok)
        # 2.5) 官方短链（best-effort，失败不影响发卡）
        short_url = ""
        try:
            sr = cli.eapi_post(SHORTURL_URL, {"url": link})
            short_url = str(((sr.get("data") or {}) if isinstance(sr.get("data"), dict) else {}).get("shortUrl") or "")
        except Exception:
            pass
        expire = month_end_ms()
        rec = {"token": tok, "link": link, "short_url": short_url, "donor_uid": uid, "donor_name": a.get("name"),
               "vip_level": a.get("vip_level"), "month": now_month(),
               "expire_ms": expire, "created_at": datetime.now(BJ).strftime("%Y-%m-%d %H:%M:%S"),
               "status": "created"}
        # 3) 记账：预留 7 天 + 最近使用时刻
        a["reserved"] = int(a.get("reserved") or 0) + RESERVE_DAYS
        a["last_used"] = rec["created_at"]
        a["never_gifted"] = 0
        save_state(st)
        toks = load_tokens()
        toks.insert(0, rec)
        save_tokens(toks)
        results.append(rec)
        if progress_cb:
            progress_cb(i + 1, n, rec)
        time.sleep(random.uniform(2.0, 4.0))
    return results


# ---------------------------------------------------------------- CLI
def _cli():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status":
        s = stats()
        print(json.dumps(s, ensure_ascii=False, indent=1))
        q = eligible()[:15]
        if q:
            print("\n队列前 15（轮换序）：")
            for _f, _lu, _nl, uid, a in q:
                print("  %s %s V%s left=%s reserved=%s last_used=%s" % (
                    uid, a.get("pool"), a.get("vip_level"), a.get("send_left"),
                    a.get("reserved"), a.get("last_used") or "本月未用"))
    elif cmd == "refresh":
        full = "--full" in sys.argv
        done, total = probe(full=full, progress_cb=lambda d, t, u, r: print(
            "\r[%d/%d] %s vip=%s left=%s" % (d, t, u, r.get("vip_level"), r.get("send_left")),
            end="", flush=True))
        print("\n完成 %d/%d" % (done, total))
    elif cmd == "take":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        for r in take(n):
            if r.get("error"):
                print("!!", r["error"])
            else:
                print("✅ %s (V%s, uid=%s)  有效期至 %s" % (
                    r["donor_name"], r["vip_level"], r["donor_uid"],
                    datetime.fromtimestamp(r["expire_ms"] / 1000, BJ).strftime("%Y-%m-%d %H:%M")))
                print("   短链: %s" % (r.get("short_url") or "（生成失败，用长链）"))
                print("   长链: %s" % r["link"])
    else:
        print(__doc__)


if __name__ == "__main__":
    _cli()

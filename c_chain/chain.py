# -*- coding: utf-8 -*-
r"""C 组 40~42s 下探 — 每日链路驱动（GitHub Actions 版，2026-11-18 建）。

由 c_chain.yml 每日北京 10:30（UTC 02:30）触发，亦可 workflow_dispatch 手动跑。
用户预授权（2026-11-18）：整条链自动判定、自动执行、事后邮件汇报，不需用户拍板。

链路：
  AB 阶段（未终态时）：核验 55~60s 实验组 vs 对照组增量（NIGHTS，延长自动续）→
    成立：Secret POOL_PLAY_SECONDS=55,60 + 清 AB_EXP_SONGS → 启动 C 组（存活复核→配 C_EXP_SONGS）
    不成立：清 AB_EXP_SONGS，C 作废；延长：不动；数据无效：冻结+邮件
  C 阶段（active 时）：核验 40~42s C 组 vs 对照组（3 夜）→
    成立：POOL_PLAY_SECONDS=40,42 + 清 C_EXP_SONGS → 终态 done
    不成立：清 C_EXP_SONGS → 终态 done；延长：不动
状态：c_chain/state.json（本工作流每次跑完提交回仓库，幂等幂源）。
报告：c_chain/last_report.md + 判定/异常日邮件（EMAIL_FROM → ALERT_TO）。
"""
import base64
import json
import os
import smtplib
import statistics
import sys
import traceback
import urllib.request
from datetime import date, datetime, timedelta
from email.mime.text import MIMEText

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(REPO_DIR, "c_chain", "state.json")
REPORT_PATH = os.path.join(REPO_DIR, "c_chain", "last_report.md")

CF_ACCOUNT = os.environ.get("CF_ACCOUNT_ID", "")
CF_TOK = os.environ.get("CF_API_TOKEN", "")
GH_TOK = os.environ.get("C_CHAIN_TOKEN", "")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "")
EMAIL_CODE = os.environ.get("EMAIL_AUTH_CODE", "")
ALERT_TO = os.environ.get("ALERT_TO", "")
D1_UUID = "54f742fc-5f56-4723-a7a0-a832953d38c7"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"

AB_EXP_UIDS = [529089967, 8396050087, 14077643005, 7976216478, 332772066, 1994659192,
               13207039578, 295730066, 79362221, 1634212411, 5162804579, 612981144,
               1735345272, 5180640602, 591607592]
CTRL_UIDS = [9313657858, 13940777310, 1802028541, 1797624388, 1789374879, 13587854361,
             14011292479, 52048019, 3247578565, 430327861, 13887739006, 600339306,
             13527029251, 8032955991, 552212953]
AB_NIGHTS0 = ["2026-11-17", "2026-11-18", "2026-11-19"]

C_UIDS = [1354177974, 433977774, 258620751, 1483806427, 1850920613, 8032860349,
          5018360396, 565925501, 574857486, 132454472, 618957842, 14132048618,
          348858579, 1742090652, 8559202332]
C_BACKUPS = [(1896685887, 3413342285), (3726003971, 3411710242), (2097554985, 2620663238),
             (76580530, 3358904376), (350803634, 3410061733), (532698334, 1901575447),
             (8059202174, 3413252342), (5114054050, 3369499784), (1766928732, 3331090511),
             (467348852, 3392201275)]

_rep = []


def log(s=""):
    print(s)
    _rep.append(str(s))


def bj_today():
    return (datetime.utcnow() + timedelta(hours=8)).date()


def d1(sql, params=None):
    body = {"sql": sql, "params": params or []}
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT}/d1/database/{D1_UUID}/query",
        data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": "Bearer " + CF_TOK, "User-Agent": UA,
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.loads(r.read().decode())
    if not d.get("success"):
        raise RuntimeError("D1 query failed: " + json.dumps(d.get("errors", []))[:300])
    return d["result"][0]["results"]


def measure(day, exp_uids, ctrl_uids):
    prev = (date.fromisoformat(day) - timedelta(days=1)).isoformat()
    all_uids = [str(u) for u in exp_uids + ctrl_uids]
    rows = d1(f"SELECT day,uid,rpc30,at FROM snapshots WHERE pool='hz' "
              f"AND day>=? AND day<=? AND uid IN ({','.join('?'*len(all_uids))})",
              [prev, day] + all_uids)
    by = {}
    for r in rows:
        by.setdefault(r["day"], {})[int(r["uid"])] = r
    if any(d not in by for d in (prev, day)):
        return None
    stale = sum(1 for r in by[day].values() if not r.get("at") or r["at"] < f"{day}T01:00:00")
    out = {"suspect": stale > 5, "missing": [], "exp": {}, "ctrl": {}}
    for kind, uids in (("exp", exp_uids), ("ctrl", ctrl_uids)):
        for uid in uids:
            a, b = by[prev].get(int(uid)), by[day].get(int(uid))
            if not a or not b:
                out["missing"].append(uid)
                out[kind][str(uid)] = None
            else:
                out[kind][str(uid)] = (b["rpc30"] or 0) - (a["rpc30"] or 0)
    return out


def summarize(m):
    e = [v for v in m["exp"].values() if v is not None]
    c = [v for v in m["ctrl"].values() if v is not None]
    return {"exp_sum": sum(e), "ctrl_sum": sum(c),
            "exp_pos": sum(1 for v in e if v > 0), "ctrl_pos": sum(1 for v in c if v > 0),
            "missing": m["missing"], "suspect": m["suspect"]}


def verdict(res_by_day, nights):
    """看板预授权标准（80%~95% 边界带延长 3 夜，二次边界保守判不成立）。"""
    window = [d for d in nights if d in res_by_day]
    if len(window) < 3:
        return None
    if len(window) >= 6:
        window = window[:6]
    es = sum(res_by_day[d]["exp_sum"] for d in window)
    cs = sum(res_by_day[d]["ctrl_sum"] for d in window)
    ep = min(res_by_day[d]["exp_pos"] for d in window)
    if cs <= 0:
        return "数据无效", f"对照合计 {cs}<=0，两组同时异常，冻结判定先排障"
    ratio = es / cs if cs else 0
    tag = "50秒" if nights[0] == AB_NIGHTS0[0] else "40秒"
    if ratio >= 0.95 and ep >= 12:
        return f"{tag}口径成立", f"合计比 {ratio:.0%}（实验 {es}/对照 {cs}），最差日正增长 {ep}/15"
    if ratio < 0.80 or ep <= 8:
        return f"{tag}口径不成立", f"合计比 {ratio:.0%}（实验 {es}/对照 {cs}），最差日正增长 {ep}/15"
    if len(window) >= 6:
        return f"{tag}口径不成立", f"延长 6 夜仍边界（合计比 {ratio:.0%}）→ 保守判不成立"
    return "延长实验", f"3 夜合计比 {ratio:.0%} 处于边界带 → 续观 3 夜"


def gh_secret_set(name, value):
    from nacl import encoding, public
    H = {"Authorization": "Bearer " + GH_TOK, "User-Agent": "curl/8",
         "Accept": "application/vnd.github+json"}
    pk = json.loads(urllib.request.urlopen(
        urllib.request.Request(f"{REPO_API}/public-key", headers=H), timeout=30).read())
    sealed = public.SealedBox(public.PublicKey(pk["key"].encode(), encoding.Base64Encoder()))
    enc = base64.b64encode(sealed.encrypt(value.encode())).decode()
    body = json.dumps({"encrypted_value": enc, "key_id": pk["key_id"]}).encode()
    req = urllib.request.Request(f"{REPO_API}/{name}", data=body,
                                 headers={**H, "Content-Type": "application/json"}, method="PUT")
    urllib.request.urlopen(req, timeout=30)
    # 回读校验必须 per_page=100：仓内 secret 已 66 个，默认 30 条只显示第一页（铁律同款坑，11-19 实锤误报）
    r = json.loads(urllib.request.urlopen(urllib.request.Request(REPO_API + "?per_page=100", headers=H), timeout=30).read())
    ok = name in [s["name"] for s in r["secrets"]]
    log(f"  Secret {name} ← '{value or '(空)'}' 回读在列={ok}")
    if not ok:
        raise RuntimeError(f"Secret {name} 回读失败")


REPO_API = "https://api.github.com/repos/xm921016/cron-relay/actions/secrets"


def mail(subject, lines):
    if not (EMAIL_FROM and EMAIL_CODE and ALERT_TO):
        log("  ⚠ 邮箱凭据缺失，邮件未发")
        return
    msg = MIMEText("\n".join(lines), "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = ALERT_TO
    with smtplib.SMTP_SSL("smtp.qq.com", 465, timeout=60) as s:
        s.login(EMAIL_FROM, EMAIL_CODE)
        s.sendmail(EMAIL_FROM, [x.strip() for x in ALERT_TO.split(",") if x.strip()], msg.as_string())
    log(f"  📧 已发: {subject}")


def c_alive_check():
    uid_list = ",".join(str(u) for u in C_UIDS + [b[0] for b in C_BACKUPS])
    rows = d1(f"SELECT uid, song, IFNULL(suspect_at,'') s, IFNULL(relogin_at,'') r "
              f"FROM accounts WHERE pool='hz' AND uid IN ({uid_list})")
    by = {int(r["uid"]): r for r in rows}
    final, bi, dropped = [], 0, []
    songs_seen = set()
    for uid in C_UIDS:
        r = by.get(uid)
        if r and r["song"] and not r["s"] and not r["r"] and int(r["song"]) not in songs_seen:
            final.append((uid, int(r["song"])))
            songs_seen.add(int(r["song"]))
        else:
            dropped.append(uid)
    for uid in dropped:
        while bi < len(C_BACKUPS):
            bu, _bs = C_BACKUPS[bi]
            bi += 1
            r = by.get(bu)
            if r and r["song"] and not r["s"] and not r["r"] and int(r["song"]) not in songs_seen:
                final.append((bu, int(r["song"])))
                songs_seen.add(int(r["song"]))
                log(f"  顶替: uid {uid} → 候补 {bu}（歌 {r['song']}）")
                break
        else:
            raise RuntimeError(f"候补耗尽，掉号 {dropped}")
    if len(final) != 15:
        raise RuntimeError(f"C 组名单 {len(final)} 个，应为 15")
    return final


def main():
    today = bj_today()
    log(f"# C 组链路日报 {today.isoformat()}（自动判定+自动执行）\n")
    st_path = STATE_PATH
    st = json.load(open(st_path, encoding="utf-8")) if os.path.exists(st_path) else {
        "ab": {"acted": None, "nights": AB_NIGHTS0, "results": {}}, "c": None}
    warn = False
    days = [(today - timedelta(days=1)).isoformat(), today.isoformat()]

    # ===== AB =====
    ab = st["ab"]
    if ab.get("acted"):
        log(f"\n## AB 阶段：终态「{ab['acted']}」，跳过")
    else:
        log("\n## AB 阶段（50 秒口径，55~60s vs 全池过半口径）")
        for d in days:
            m = measure(d, AB_EXP_UIDS, CTRL_UIDS)
            if m:
                ab["results"][d] = summarize(m)
                s = ab["results"][d]
                ratio = f"{s['exp_sum']/s['ctrl_sum']:.0%}" if s["ctrl_sum"] else "-"
                log(f"  夜 {d}: 实验合计Δ={s['exp_sum']} 对照合计Δ={s['ctrl_sum']} 比值={ratio}")
            else:
                log(f"  夜 {d}: 数据未就绪（09:30 快照未落/缺整日）")
        v = verdict(ab["results"], ab["nights"])
        log(f"  AB 判定: {v[0] if v else '待数据'}" + (f" —— {v[1]}" if v else ""))
        if v and v[0] == "50秒口径成立":
            gh_secret_set("POOL_PLAY_SECONDS", "55,60")
            gh_secret_set("AB_EXP_SONGS", "")
            ab["acted"] = "成立"
            log("\n### C 组启动")
            final = c_alive_check()
            songs = ",".join(str(s) for _, s in final)
            gh_secret_set("C_EXP_SONGS", songs)
            nights = [(today + timedelta(days=k)).isoformat() for k in (1, 2, 3)]
            st["c"] = {"status": "active", "uids": [u for u, _ in final],
                       "songs": [s for _, s in final], "nights": nights,
                       "results": {}, "launched": today.isoformat()}
            log(f"  C 组 15 歌已配 Secret，观测夜={nights}，判定预计 {nights[2]} 上午")
            mail(f"[C组链路] AB 判定成立·C 组已启动 {today}",
                 ["AB 50s 判定成立，全池已切 55~60s，AB 名单已清。",
                  f"C 组 15 首歌已配 C_EXP_SONGS，观测夜 {nights}。",
                  f"C 组判定预计 {nights[2]} 上午自动出并自动执行。", "本邮件为自动链路通知。"])
        elif v and v[0] == "50秒口径不成立":
            gh_secret_set("AB_EXP_SONGS", "")
            ab["acted"] = "不成立"
            st["c"] = {"status": "cancelled", "reason": "AB 50s 不成立，38s 无实验意义"}
            log("  **AB 不成立：已清 AB 名单回退现网口径；C 组作废，链路终止**")
            mail(f"[C组链路] AB 判定不成立·C 组作废 {today}",
                 ["AB 50s 判定不成立，已清 AB_EXP_SONGS，保留现网口径。",
                  "38s 下探无意义，C 组作废。链路终止。"])
        elif v and v[0] == "延长实验":
            extra = [(date.fromisoformat(ab["nights"][-1]) + timedelta(days=k)).isoformat() for k in (1, 2, 3)]
            ab["nights"] += extra
            log(f"  延长 3 夜：{extra}")
        elif v and v[0] == "数据无效":
            warn = True
            mail(f"[C组链路] AB 数据无效·冻结 {today}", [v[1], "今日不动 Secret。"])
        else:
            log("  AB 待数据。")

    # ===== C =====
    c = st.get("c")
    if c and c.get("status") == "active":
        log(f"\n## C 阶段（40~42s 下探，启动日 {c.get('launched')}）")
        for d in days:
            m = measure(d, c["uids"], CTRL_UIDS)
            if m:
                c["results"][d] = summarize(m)
                s = c["results"][d]
                ratio = f"{s['exp_sum']/s['ctrl_sum']:.0%}" if s["ctrl_sum"] else "-"
                log(f"  夜 {d}: C合计Δ={s['exp_sum']} 对照合计Δ={s['ctrl_sum']} 比值={ratio}")
            else:
                log(f"  夜 {d}: 数据未就绪")
        v = verdict(c["results"], c["nights"])
        log(f"  C 判定: {v[0] if v else '待数据'}" + (f" —— {v[1]}" if v else ""))
        if v and v[0] == "40秒口径成立":
            gh_secret_set("POOL_PLAY_SECONDS", "40,42")
            gh_secret_set("C_EXP_SONGS", "")
            c["status"] = "done"
            c["verdict"] = v
            log("  **C 成立：全池已切 40~42s，C 名单已清，链路完成**")
            mail(f"[C组链路] 40s 判定成立·全池已切 {today}",
                 ["C 组 3 夜判定成立，全池上报口径已切 40~42s（省约 4 倍运行时）。",
                  "C_EXP_SONGS 已清空。链路完成。"])
        elif v and v[0] == "40秒口径不成立":
            gh_secret_set("C_EXP_SONGS", "")
            c["status"] = "done"
            c["verdict"] = v
            log("  **C 不成立：已清 C 名单，保留现网口径，链路完成**")
            mail(f"[C组链路] 40s 判定不成立·已回退 {today}",
                 ["C 组判定不成立，已清 C_EXP_SONGS，保留现网口径。链路完成。"])
        elif v and v[0] == "延长实验":
            extra = [(date.fromisoformat(c["nights"][-1]) + timedelta(days=k)).isoformat() for k in (1, 2, 3)]
            c["nights"] += extra
            log(f"  延长 3 夜：{extra}")
        elif v and v[0] == "数据无效":
            warn = True
            mail(f"[C组链路] C 数据无效·冻结 {today}", [v[1], "今日不动 Secret。"])
        else:
            left = [d for d in c["nights"] if d not in c["results"]]
            log(f"  C 待数据，还差 {len(left)} 夜: {left}")
    elif c:
        log(f"\n## C 阶段：{c.get('status')}（{c.get('reason', '')}）")
    else:
        log("\n## C 阶段：未启动（等 AB 判定成立）")

    os.makedirs(os.path.dirname(st_path), exist_ok=True)
    # 2026-11-20 体检 P2：state.json 改原子写（临时文件 + os.replace）。
    # 旧写法直接 open(w) 截断 —— 写盘中途失败/进程被杀会留下半截 JSON，Secret 已改而
    # 状态未落盘，次日重复判定/重复发邮件。报告文件同理。
    _tmp_st = st_path + ".tmp"
    with open(_tmp_st, "w", encoding="utf-8") as _f:
        json.dump(st, _f, ensure_ascii=False, indent=1)
    os.replace(_tmp_st, st_path)
    _tmp_rp = REPORT_PATH + ".tmp"
    with open(_tmp_rp, "w", encoding="utf-8") as _f:
        _f.write("\n".join(_rep) + "\n")
    os.replace(_tmp_rp, REPORT_PATH)
    log("\n（状态已写入 c_chain/state.json，本 workflow 会提交回仓库；动作幂等）")
    if warn:
        raise SystemExit(2)   # 让 workflow 标黄提醒


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        print("## 链路异常:", e)
        print(traceback.format_exc()[-1500:])
        try:
            mail(f"[C组链路] 异常 {bj_today()}", [f"异常: {e}", "动作幂等，明晨自动重试。"])
        except Exception:
            pass
        raise SystemExit(1)

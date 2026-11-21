# -*- coding: utf-8 -*-
"""号体检 —— 一键排查单个账号的零增长/650进度问题。

用法:
    python acc_health.py <手机号或uid> [--refresh] [--no-live] [--pool hz|dz]

流程（对应 2026-11-11 人工排查 19927468421 的完整套路）:
  1. D1 本地镜像（/export，不吃读配额；当天已有镜像则复用，--refresh 强制重导）
  2. 按手机号/uid 找账号（hz/dz 都查）
  3. 近 14 天快照走势（650 进度 rate / 近30日播放 rpc30）
  4. 复算控制台 computeMarks 的标记口径（今日零增长/650未结算/净增≤0/有播放·650为0/连续N天未涨…）
  5. 实时复核创作者后台（区分"快照采早于结算"与"真停滞"；--no-live 跳过）
  6. 目标歌归属验证（公开接口查艺人 accountId 是否号主，排除填错歌）
  7. 台账记录（登记/续费历史）
  8. 输出明细 + 文字分析结论，并存报告到 tmp\\体检_<号>_<时间戳>.txt

2026-11-19 新增：换歌/冻结处置事件联动 —— 近 3 天 mail_queue 里的 songchange/songfix*
  ①标注到【2】快照走势对应日期行尾 ②【8】结论新增「换歌观察期」分支（优先于结算延迟口径）
  ③【3】「连续N天未涨」标记在冷却期内附提示（口径对齐 worker.js mail_scan v3）。

2026-11-20 改造：
  ①镜像导出失败自动重试 1 次，并把子进程真实报错带出来（以前网页端只显示「镜像导出失败」或英文原始异常）
  ②新增【8】笔记发布章节：网易任务「30 天内发布图文笔记天数 ≥4」（封顶 4/4），展示近 14 天走势
  ③【7】邮件口径更新：11-18 已废除「已通知重登」，relogin_at 不再写入，过期号立即删号+直邮

依赖: requests、pycryptodome（系统 Python 3.13.9 已带）。
注意: 实时复核每次只发 1 条只读 eapi 查询（登录校验+工作台），无写操作。
"""
import argparse
import glob
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta

PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # 项目根
CR   = os.path.dirname(os.path.abspath(__file__))                            # cron-relay
sys.path.insert(0, CR)

BJ = timezone(timedelta(hours=8))
MIRROR_DIR = os.path.join(PROJ, "本地备份")
OUT_DIR = os.path.join(PROJ, "tmp")


def bj(s):
    """UTC ISO → 北京 datetime；失败返回 None。"""
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(BJ)
    except (ValueError, TypeError):
        return None


def bj_str(s):
    d = bj(s)
    return d.strftime("%m-%d %H:%M") if d else "?"


def runs_recent(db, pool, uid, days=14):
    """近 N 天实跑名单（runs 表：relay 真跑完才写入，每天每号一条）。
    旧镜像没导 runs 表时返回 None（调用方静默跳过，不误报）。"""
    try:
        return list(db.execute(
            "SELECT day, slice, at FROM runs WHERE pool=? AND uid=? AND day>=? ORDER BY day",
            (pool, uid, (datetime.now(BJ) - timedelta(days=days)).strftime("%Y-%m-%d"))))
    except sqlite3.OperationalError:
        return None


def tf(v):
    """布尔值 → 中英双语（网页和文本报告共用）。"""
    return {True: "是(True)", False: "否(False)"}.get(v, str(v))


KIND_CN = {  # mail_queue 邮件类型 → 中英双语说明
    "reg": "reg(登记成功通知)",
    "songchange": "songchange(自动换歌)",
    "songfix": "songfix(共创冻结处置)",
    "songfix2": "songfix2(独唱冻结处置)",
    "songfix3": "songfix3(绑错歌/查无此歌处置)",
    "notify-dead": "notify-dead(删号通知)",
    "feenote": "feenote(收费口径说明)",
}


def load_runpy():
    """加载 cron-relay/run.py（有 __main__ 保护，import 安全）。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("runmod", os.path.join(CR, "run.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---------------------------------------------------------------- 第 1 步 镜像
def _mirror_ok(dbf):
    """校验镜像包含体检需要的全部表（防止部分导出文件混进来）。"""
    try:
        con = sqlite3.connect(dbf)
        tabs = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        con.close()
    except sqlite3.Error:
        return False
    return {"accounts", "snapshots", "ledger", "dead_log", "dead_notice", "mail_queue"} <= tabs


def ensure_mirror(refresh=False):
    os.makedirs(MIRROR_DIR, exist_ok=True)
    # 只认 d1_mirror_日期_时间.db 严格格式（跳过 d1_mirror_p0p1_xxx 这类部分导出文件）
    dbs = []
    for dbf in glob.glob(os.path.join(MIRROR_DIR, "d1_mirror_*.db")):
        if re.search(r"d1_mirror_(\d{8})_(\d{4})\.db$", dbf):
            dbs.append(dbf)
    dbs.sort()
    # 今天 08:00（北京，=UTC 日重置）之后导的才算新鲜
    floor = datetime.now(BJ).replace(hour=8, minute=0, second=0, microsecond=0)
    for dbf in reversed(dbs):
        m = re.search(r"d1_mirror_(\d{8})_(\d{4})\.db$", dbf)
        dt = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M").replace(tzinfo=BJ)
        if dt < floor:
            continue
        if not _mirror_ok(dbf):
            continue
        if not refresh:
            return dbf, f"复用镜像（{dt:%m-%d %H:%M} 导出，勾选「强制重导」可重导）"
    # 2026-11-20 改造：失败自动重试 1 次，并把子进程真实报错带出来（以前只给一句
    # 「镜像导出失败」，网页端看不到任何原因——实际多为瞬时网络/代理问题，重试即好）
    last_err = ""
    ok = False
    for attempt in (1, 2):
        print(f"  导出 D1 镜像（/export 通道，不吃读配额，第 {attempt}/2 次）…")
        try:
            r = subprocess.run(
                [sys.executable, os.path.join(PROJ, "tmp", "d1_mirror.py"),
                 "--table", "accounts", "--table", "snapshots", "--table", "ledger",
                 "--table", "dead_log", "--table", "dead_notice", "--table", "mail_queue",
                 "--table", "runs", "--table", "durs"],
                capture_output=True, text=True, encoding="locale", errors="replace",
                cwd=PROJ, timeout=300)
            if r.returncode == 0:
                ok = True
                break
            last_err = ((r.stderr or "") + (r.stdout or "")).strip()[-400:] or "子进程退出码非 0（无输出）"
        except subprocess.TimeoutExpired:
            last_err = "导出子进程 300 秒超时（多为网络/代理不通）"
        if attempt == 1:
            print(f"  第 1 次导出失败（{last_err[:200]}），10 秒后自动重试…")
            time.sleep(10)
    if not ok:
        print(last_err)
        raise SystemExit(f"镜像导出失败，原因：{last_err}"
                         f"（可手动跑 python tmp\\d1_mirror.py 复现看完整报错）")
    # 导完从新到旧找第一个格式正确且表齐全的，绝不再盲取 dbs[-1]
    dbs = []
    for dbf in glob.glob(os.path.join(MIRROR_DIR, "d1_mirror_*.db")):
        if re.search(r"d1_mirror_(\d{8})_(\d{4})\.db$", dbf):
            dbs.append(dbf)
    dbs.sort()
    for dbf in reversed(dbs):
        if _mirror_ok(dbf):
            return dbf, "新导镜像"
    raise SystemExit("  导出完成但找不到表齐全的镜像文件")


DEAD_REASON_CN = {
    "cookie_invalid": "CK 失效（cookie 无效判死）",
    "expired_pub": "公益号到期清理",
    "manual": "管理员手动删号",
}


def dead_history(db, key, say):
    """已删号的全部历史档案（2026-11-21 新增）。

    删号后 accounts 表不再有该号的行（号池列表查不到是设计），但历史表都在：
    dead_log 删号流水 / dead_notice 直邮记录 / ledger 购买台账 / mail_queue 邮件 /
    snapshots 快照走势。按手机号或 uid 全表回捞，找到任何一条返回 True。"""
    found = False

    # 删号流水
    deads = list(db.execute(
        "SELECT pool,uid,name,reason,at FROM dead_log WHERE name=? OR uid=? ORDER BY at DESC",
        (key, key)))
    if deads:
        found = True
        say("\n【D1】删号流水（dead_log，时间为北京时间）：")
        for r in deads:
            say(f"    ✂ {r['at']}  {DEAD_REASON_CN.get(r['reason'], r['reason'])}"
                f"（reason={r['reason']}）  pool={r['pool']}  uid={r['uid']}")

    # 直邮记录
    notices = list(db.execute(
        "SELECT pool,uid,email,removed_at,sent_at,state,skip_reason,kind FROM dead_notice "
        "WHERE name=? OR uid=? ORDER BY removed_at DESC LIMIT 10", (key, key)))
    if notices:
        found = True
        say("\n【D2】删号直邮记录（dead_notice）：")
        for r in notices:
            say(f"    ✉ {r['removed_at']} 删号 → 收件邮箱 {r['email']}  "
                f"状态={r['state']}  发出={r['sent_at'] or '—'}"
                + (f"（{r['skip_reason']}）" if r['skip_reason'] else ""))

    # 台账
    led = list(db.execute(
        "SELECT day,agent,plan,price,days,start,exp,remark FROM ledger "
        "WHERE name=? OR uid=? ORDER BY day DESC LIMIT 10", (key, key)))
    if led:
        found = True
        say("\n【D3】台账记录（ledger，购买/续费流水）：")
        for r in led:
            price = "待补价" if r["price"] is None else f"{r['price']:.0f}元"
            say(f"    {r['day']}  代理={r['agent'] or '-'}  套餐={r['plan'] or '-'}  {price}  {r['days']}天"
                f"  起始={r['start'] or '-'}  到期={r['exp'] or '-'}  {r['remark'] or ''}")

    # 邮件队列
    mails = list(db.execute(
        "SELECT kind,state,created_at,sent_at,skip_reason FROM mail_queue "
        "WHERE name=? OR uid=? ORDER BY created_at DESC LIMIT 20", (key, key)))
    if mails:
        found = True
        say("\n【D4】历史邮件（mail_queue）：")
        for r in mails:
            st = {"sent": "已发出", "claimed": "发送中", "pending": "排队中",
                  "dropped": "已放弃(连败3次)", "skipped": "已跳过"}.get(r["state"], r["state"])
            say(f"    {KIND_CN.get(r['kind'], r['kind'])}  {st}  入队={r['created_at']}  发出={r['sent_at'] or '—'}"
                + (f"（{r['skip_reason']}）" if r['skip_reason'] else ""))

    # 快照走势（删号前的最后数据；用户可能输手机号，快照要靠 dead_log 回捞出的 uid 来查）
    uids = sorted({str(r["uid"]) for r in deads + notices if r["uid"]})
    q = "SELECT day,rate,rpc30,at,pool,uid FROM snapshots WHERE name=?"
    args = [key]
    if uids:
        q += " OR uid IN (%s)" % ",".join("?" * len(uids))
        args += uids
    sn = list(db.execute(q + " ORDER BY day DESC LIMIT 14", args))
    if sn:
        found = True
        say("\n【D5】删号前快照走势（snapshots，最新在前，rate=650进度 rpc30=近30日播放）：")
        for r in sn:
            note = ""
            if r["rate"] is not None and r["rate"] >= 100:
                note = "  ←已做满100%"
            say(f"    {r['day']}  650进度(rate)={r['rate']}%  近30日播放(rpc30)={r['rpc30']}  "
                f"快照时刻={bj_str(r['at'])}{note}")
        # 实跑记录（删号前 relay 有没有真派到它）
        _pool = sn[0]["pool"] if sn else None
        _uid = sn[0]["uid"] if sn else None
        if _pool and _uid:
            rr = runs_recent(db, _pool, _uid)
            if rr is not None:
                if rr:
                    say(f"    实跑记录（近 14 天，runs 表）：{'、'.join(r['day'][5:] + '✓' for r in rr)}"
                        f"（共 {len(rr)} 天真跑过）")
                else:
                    say("    ⚠ 近 14 天没有任何实跑记录（runs 表零行）——删号前 relay 一直没派到这个号。")
    return found


# ---------------------------------------------------------------- 第 2 步 找号
def find_account(db, key):
    rows = list(db.execute(
        "SELECT * FROM accounts WHERE name=? OR uid=? ORDER BY pool", (key, key)))
    return rows


# ---------------------------------------------------------------- 第 4 步 标记复算
def cmp_ok(at1, at2, tol=3):
    h1, h2 = bj(at1), bj(at2)
    if not h1 or not h2:
        return False
    d = abs((h1 - h2).total_seconds()) / 3600
    return d <= tol or d >= 24 - tol


def streak_no_rise(hist):
    """从今天往前数连续未涨天数（rate<100 且较前一日无增长；缺快照的天跳过）。"""
    pts = [(d, v) for d, v in sorted(hist.items()) if v["rate"] is not None]
    n = 0
    for i in range(len(pts) - 1, 0, -1):
        cur, prev = pts[i], pts[i - 1]
        if cur[1]["rate"] < 100 and cur[1]["rate"] <= prev[1]["rate"]:
            n += 1
        else:
            break
    return n


def compute_marks(db, pool, uid, today_day, yest_day, hist):
    """单号版控制台标记复算（口径对齐 worker.js computeMarks，2026-11-11 核对过）。"""
    e = db.execute("SELECT song,added,pub FROM accounts WHERE pool=? AND uid=?", (pool, uid)).fetchone()
    a = db.execute("SELECT rate,rpc30,at FROM snapshots WHERE pool=? AND day=? AND uid=?",
                   (pool, today_day, uid)).fetchone()
    p = db.execute("SELECT rate,rpc30,at FROM snapshots WHERE pool=? AND day=? AND uid=?",
                   (pool, yest_day, uid)).fetchone()
    marks, rpcD = [], None
    added_day = str(e["added"])[:10] if e and e["added"] else ""
    # 无650任务（worker.js:8910 口径）：非公益 + 有歌 + 快照 rate 为 null + 非今天登记
    if (a is not None and a["rate"] is None and e and e["song"]
            and not e["pub"] and added_day and added_day < today_day):
        marks.append(("无650任务", "b-gray",
                      "后台没返回 650 任务：可能不是音乐人、没报名该任务或歌曲未过审，让号主去音乐人后台确认"))
    elif (a is not None and a["rate"] is None and e and e["song"] and not e["pub"]
          and added_day == today_day):
        marks.append(("今日入池·无快照", "b-gray", "今天才登记的新号，明天才进轮转，650 进度是空的属正常"))
    if a and a["rate"] is not None:
        if a["rate"] >= 100:
            marks.append(("已达100%", "b-green", "本周期 650 已做满，等下个 31 天周期自动归零重爬，不用管"))
        rpcD = (a["rpc30"] - p["rpc30"]) if (p and p["rpc30"] is not None and a["rpc30"] is not None) else None
        hasCycle = a["rate"] == 0 and (a["rpc30"] or 0) >= 650
        netLoss = (not hasCycle and p and a["rate"] <= p["rate"] and rpcD is not None and rpcD <= 0
                   and (a["rpc30"] or 0) >= 100 and cmp_ok(a["at"], p["at"]))
        if p and p["rate"] is not None and a["rate"] < 100:
            same = a["rate"] == p["rate"]
            if hasCycle:
                marks.append(("有播放·650为0", "b-orange",
                              f"播放量已有 {a['rpc30']} 次但 650 进度 0%。多半是快照早于结算；实时复核仍 0% 且连续 8 天以上才是任务不再统计播放"))
            elif netLoss:
                marks.append(("近30日净增≤0", "b-yellow",
                              f"近30日播放今天没涨或略降（差 {rpcD:+d}），650 也没涨：今天补的播放被 30 天前老播放到期退出抵掉，偶发正常"))
            elif same and rpcD is not None and rpcD > 0:
                marks.append(("650未结算", "b-yellow",
                              f"650 进度与昨天一样（{a['rate']}%），但播放量在涨（{rpcD:+d}）：播放已入账、网易分批结算还没滚到 650，停 1~2 天属正常"))
            elif same:
                marks.append(("今日零增长", "b-yellow",
                              "650 进度和昨天完全一样，播放量也没涨。先观察 2~3 天；连续 3 天以上且实时复核仍 0% 再人工查"))
        if a["rate"] < 100:
            st = streak_no_rise(hist)
            if st >= 2:
                marks.append((f"连续{st}天未涨", "b-yellow", "650 进度连续多天没涨，先看播放量在涨还是跌"))
    elif a is None:
        marks.append(("采集缺失", "b-gray", "今天这一轮没采到该号快照（接口超时或号没跑），偶尔一次不用管；连续几天要查"))
    return a, p, marks


# ---------------------------------------------------------------- 第 5 步 实时复核
def recent_song_actions(db, pool, uid, days=14):
    """近 N 天的冻结歌自动处置记录（songchange/songfix*），按时间倒序。

    days 默认 14（与【2】快照窗口对齐，用于走势标注）；冷却期判定请另取近 3 天子集。
    返回每条含 old_song/new_song（songchange 的 ref=旧歌id:新歌id[:B]）。"""
    cutoff = (datetime.now(BJ) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    tabs = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "mail_queue" not in tabs:
        return []
    out = []
    for r in db.execute(
            "SELECT kind,ref,state,created_at FROM mail_queue WHERE pool=? AND uid=? "
            "AND kind IN ('songchange','songfix','songfix2','songfix3') AND created_at>=? "
            "ORDER BY created_at DESC", (pool, uid, cutoff)):
        d = dict(r)
        ref = (d.get("ref") or "").split(":")
        d["old_song"] = ref[0] if ref else ""
        d["new_song"] = ref[1] if len(ref) > 1 else ""
        d["not_mine"] = len(ref) > 2 and "B" in ref[2]
        out.append(d)
    return out


def act_desc(act):
    """处置记录 → 一句人话（走势标注与结论共用）。"""
    kind = act.get("kind")
    t = str(act.get("created_at") or "")[:16]
    if kind == "songchange":
        s = f"{t} 自动换歌：旧歌{act.get('old_song')}→新歌{act.get('new_song')}"
        if act.get("not_mine"):
            s += "（旧歌非本人作品）"
        return s
    return {"songfix": f"{t} 共创冻结邮件已发(songfix)",
            "songfix2": f"{t} 独唱冻结邮件已发(songfix2)",
            "songfix3": f"{t} 绑错歌/查无此歌处置(songfix3)"}.get(kind, f"{t} {kind}")


def cooling_actions(actions, days=3):
    """冷却期子集：近 days 天内有过处置的记录（口径对齐 worker.js mail_scan v3）。"""
    cutoff = (datetime.now(BJ) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    return [x for x in (actions or [])
            if str(x.get("created_at") or "") >= cutoff]



def live_check(runmod, ck):
    c = runmod.Client(ck)
    ok = c.login_by_cookie(ck)
    if ok is not True:
        return {"alive": False, "text": "失效" if ok is False else "网络异常无法判定"}
    path = "/api/nmusician/workbench/special/right/vip/info"
    p = runmod.eapi_encrypt(path, "{}")
    r = c.s.post(runmod.BASE_URL + path.replace("/api/", "/eapi/", 1), data=p, timeout=30).json()
    d = r.get("data") or {}
    kids = ((d.get("furtherTask") or {}).get("children")) or []
    play = next((k for k in kids if k.get("missionCode") == "mission_code_recently_play_effect_count_v2"), {})
    note = next((k for k in kids if k.get("missionCode") == "mission_code_musician_notebook_publish"), {})
    return {
        "alive": True,
        "rate": play.get("progressRate"),
        "rpc30": d.get("recentPlayCount30"),
        "taskStatus": d.get("taskStatus"),
        "isMusician": d.get("isMusician"),
        "hasOpen": d.get("hasOpen"),
        "canOpen": d.get("canOpen"),
        "status": d.get("status"),
        "maintainDays": d.get("maintainDays"),
        "unlockVipRight": d.get("unlockVipRight"),
        "missionStatus": play.get("missionStatus"),
        "noteProgress": note.get("progressRate"),
        "furtherTaskStartTime": d.get("furtherTaskStartTime"),
        "furtherVipGetTime": d.get("furtherVipGetTime"),
    }


# ---------------------------------------------------------------- 第 6 步 歌曲归属
def song_owner(song_id):
    import requests
    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    try:
        r = requests.get(f"https://music.163.com/api/song/detail?id={song_id}&ids=[{song_id}]",
                         headers={"User-Agent": UA}, timeout=15).json()
        d = (r.get("songs") or [{}])[0]
        out = {"name": d.get("name"), "artists": []}
        alb = d.get("album") or {}
        pt = alb.get("publishTime")
        out["publishTime"] = datetime.fromtimestamp(pt / 1000).strftime("%Y-%m-%d") if pt else None
        for a in d.get("artists", []):
            art = {"id": a.get("id"), "name": a.get("name")}
            try:
                ra = requests.get(f"https://music.163.com/api/artist/{a['id']}",
                                  headers={"User-Agent": UA}, timeout=15).json()
                aa = ra.get("artist") or {}
                art["accountId"] = aa.get("accountId")
            except Exception:
                art["accountId"] = None
            out["artists"].append(art)
        return out
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------- 第 8 步 文字分析
def verdict(e, hist_days, a, p, marks, live, owner, rpcD, actions=None):
    """规则引擎：像人工排查一样给一段结论。"""
    name = e["name"]
    now_bj = datetime.now(BJ)
    lines = []

    added = bj(str(e["added"]).replace(" ", "T") + "+00:00") if e["added"] else None
    added_bj = None
    try:
        added_bj = datetime.strptime(str(e["added"])[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=BJ)
    except ValueError:
        pass
    days_in = (now_bj - added_bj).days if added_bj else None

    rate_t = a["rate"] if a else None
    rate_y = p["rate"] if p else None

    # ① 先说快照/复核对不上的情况（结算延迟）
    if live and live.get("alive") and live.get("rate") is not None and rate_t == 0 and live["rate"] > 0:
        lines.append(f"①快照里 650 是 0%，但刚刚实时查工作台已经是 {live['rate']}%：这一轮快照采在网易结算之前"
                     f"（结算窗口实测到 11:30~12:00），不是掉量也不是周期问题，不用管。")
        return " ".join(lines)

    # ①b 快照与实时都没有 650 任务 → 无650任务（对齐控制台「无650任务」口径）
    if rate_t is None:
        # 今天快照缺失但昨天有数据 → 这是采集缺失，不是「没任务」（11-21 实锤误判修复：
        # 15255190748 昨天已 100% 做满，今天快照缺被兜底文案判成「可能是非音乐人」——前后矛盾）
        if rate_y is not None:
            _extra = ("且昨天已 100% 做满，本周期任务已完成，等 31 天换期归零即可，"
                      if rate_y >= 100 else
                      f"最近一次进度 {rate_y:g}%，" if rate_y else "最近一次进度 0%（周期刚换期归零），")
            lines.append(f"②今天快照缺该号数据（【3】已标采集缺失——接口超时或当轮没跑），{_extra}"
                         f"今天没采到≠任务没了，明天快照恢复自动接上。偶尔缺失不用管，连续 2 天缺失再查。")
            return " ".join(lines)
        has_open = (live or {}).get("hasOpen")
        can_open = (live or {}).get("canOpen")
        is_mus = (live or {}).get("isMusician")
        if is_mus is False:
            lines.append("②实时复核显示该号【不是音乐人】（isMusician=False）：650 任务无从谈起。"
                         "如果登记歌确实能听，多半歌挂在别人名下或买家拿的是普通用户号——"
                         "找买家核实账号身份，要么换号要么退款。")
            return " ".join(lines)
        if has_open is False and can_open is False:
            # 实习期：maintainDays 在实习期恒 0（不是进度计数器，别用它算剩余天数），
            # 改用登记歌专辑发行时间旁证音乐人身份起点
            pub = (owner or {}).get("publishTime")
            if pub:
                try:
                    pd = datetime.strptime(pub, "%Y-%m-%d")
                    since = (datetime.now(BJ).replace(tzinfo=None) - pd).days
                except ValueError:
                    since = None
            else:
                since = None
            if since is not None and since >= 90:
                lines.append(f"②该号是音乐人但还在实习期未转正（status=0、canOpen=False）。"
                             f"登记歌发行于 {pub}（约 {since} 天前），身份早已超过官方 90 天实习期却仍未转正——"
                             f"说明转正不是纯时间驱动，可能卡在号主侧的认证/签约/操作上，"
                             f"让号主上音乐人后台查实习任务/认证状态并主动完成。")
            elif since is not None:
                left = 90 - since
                lines.append(f"②该号是音乐人但还在实习期未转正（status=0、canOpen=False）："
                             f"登记歌发行于 {pub}（约 {since} 天前），按 90 天实习期估算最早约 "
                             f"{(datetime.now(BJ) + timedelta(days=left)).strftime('%Y-%m-%d')} 前后才可能转正"
                             f"（以歌发行时间旁证，仅粗估）。转正后号主在后台开通特殊权益，650 才开始计；"
                             f"此前的 650 做不满属预期内，无需处理，也别急着换歌。")
            else:
                lines.append(f"②该号是音乐人但还在实习期未转正（status=0、canOpen=False），"
                             f"特殊权益当前开不了。按官方 90 天实习期，等转正后在音乐人后台开通特殊权益，"
                             f"650 进度才开始计；此前 650 做不满属预期内，无需处理。")
            return " ".join(lines)
        if has_open is False and can_open is True:
            lines.append("②快照和实时复核都没有 650 任务：该号音乐人身份在、已满足开通条件（canOpen=True），"
                         "只是没去开通——让号主去音乐人后台开通「特殊权益/进阶任务」，开通后进度从 0 开始爬。")
            return " ".join(lines)
        lines.append("②快照里网易没返回 650 任务进度（可能是非音乐人、没报名任务）："
                     "让号主去音乐人后台确认任务状态。注意近30日播放量照常在跑，只是不计入 650。")
        return " ".join(lines)

    # ② 新号爬坡期（实时复核有进度才算纯爬坡；实时也是 0% 就继续往深查）
    new_acc = days_in is not None and days_in <= 2
    live_has_progress = (live and live.get("alive") and (live.get("rate") or 0) > 0)
    if new_acc and (rate_t is None or (rate_t or 0) > 0 or live_has_progress):
        lines.append(f"②该号 {str(e['added'])[:10]} 才登记（入池 ≤2 天）：新号前两三天 650 进度低是正常爬坡，"
                     f"快照少/进度空都不用查，先看到第 3~4 天。")
        return " ".join(lines)
    prefix = ("②该号才登记不久（≤2 天），但快照和实时复核都是 0%："
              if new_acc and live and live.get("alive") else
              "②该号才登记不久（≤2 天），快照也是 0%：" if new_acc else "")

    # ③ 已做满
    if rate_t is not None and rate_t >= 100:
        lines.append(f"③本周期 650 已达 {rate_t}%：做满了，继续刷也不会有额外收益，等 31 天周期换期自动归零。")
        return " ".join(lines)

    # ④a 冻结处置邮件已发但歌一直没换（号主未响应）→ 别干等，人工催换歌
    acts = actions or []
    cool = cooling_actions(acts)
    if rate_t is not None and rate_t < 100 and acts and not cool:
        last = acts[0]
        if last.get("kind") != "songchange":
            lines.append(f"④a该号 {act_desc(last)}，但目标歌至今未换（号主未响应）：冻结歌播多久都不会涨，"
                         f"继续观察没有意义——需人工跟进催号主换本人原创独唱，或走无候选号的兜底处置。")
            return " ".join(lines)

    # ④b 换歌观察期（mail_scan 冷却期内刚处置过）
    if rate_t is not None and rate_t < 100 and cool:
        lines.append(f"④b该号近 3 天刚做过冻结歌处置（{act_desc(cool[0])}）：旧歌冻结期间的 650 读数不会回补，"
                     f"换歌后网易的有效认定有 1~2 天滞后，播放量在涨说明号本身正常。"
                     f"判断点=后 1~2 天快照：开始爬即结案；若播放量继续涨而 650 连续 2 天仍 0%，"
                     f"冷却期（3 天）过后系统会再次自动判定，期间不用人工重复换歌。")
        return " ".join(lines)

    # ④ 周期换期归零
    if rate_t == 0 and rate_y is not None and rate_y >= 10:
        lines.append(f"④昨天还有 {rate_y}%、今天 0%：这是 31 天任务周期换期归零（近期全池批量出现），"
                     f"不是播放失效，换期后从 0 重新爬即可，不用管。")
        return " ".join(lines)

    # ⑤ 结算延迟（快照口径）
    if rate_t == rate_y and rpcD is not None and rpcD > 0:
        lines.append(f"⑤650 进度与昨天持平（{rate_t}%）但播放量在涨（{rpcD:+d} 次）：播放已入账，"
                     f"网易分批结算还没滚到 650（入账窗口实测持续到 11:30~12:00）。停 1~2 天属正常节奏，"
                     f"连续 3 天以上播放涨而 650 不动才人工查。")
        return " ".join(lines)

    # ⑥ 真零增长 / 卡 0%
    if rate_t == rate_y and rpcD is not None and rpcD <= 0:
        st = 0
        pts = [(d, v) for d, v in sorted(hist_days.items()) if v["rate"] is not None]
        for i in range(len(pts) - 1, 0, -1):
            if pts[i][1]["rate"] < 100 and pts[i][1]["rate"] <= pts[i - 1][1]["rate"]:
                st += 1
            else:
                break
        back = ""
        o14 = [v for d, v in sorted(hist_days.items()) if v["rpc30"] is not None]
        if len(o14) >= 2 and o14[0]["rpc30"] and o14[-1]["rpc30"] > o14[0]["rpc30"]:
            avg = round((o14[-1]["rpc30"] - o14[0]["rpc30"]) / max(1, len(o14) - 1))
            if avg > 0:
                back = f"该号近 {len(o14)-1} 天平均每天净涨约 {avg} 次，今天净变化 {rpcD:+d} 次，" \
                       f"差额约 {max(0, avg - rpcD)} 次是 30 天前老播放到期退出抵掉的。"
        lines.append(f"{prefix or '⑥'}650 进度连续持平（{rate_t}%），播放量也没涨（{rpcD:+d} 次）。{back}")
        if rate_t == 0 and (a["rpc30"] or 0) >= 650:
            lines.append("播放量已过 650 次但进度 0%：多为快照早于结算；实时复核也 0% 且连续 8 天以上，"
                         "才是任务不再统计播放（需重新报名或换号）。")
        else:
            live_zero = (live and live.get("alive") and live.get("rate") == 0)
            live_pos = (live and live.get("alive") and (live.get("rate") or 0) > 0)
            if live_zero and st >= 2:
                lines.append(f"已连续 {st + 1} 天未涨且实时复核仍 0%（结算窗口后）：达到人工干预门槛——"
                             f"建议查播放有效性（是否被网易判无效），必要时换目标歌或让号主重新报名 650 任务。")
            elif live_pos and rpcD <= 0:
                lines.append(f"连续 {st + 1} 天进度没涨，但播放量在跌、实时复核仍有 {live['rate']}%："
                             f"这是 30 天滚动回吐（老播放到期退出）把进度涨幅吃平了，属自然衰减不用管；"
                             f"播放量连续 3 天以上在涨而进度完全不动才需要人工查。")
            elif st >= 4 and rpcD is not None and rpcD > 0:
                lines.append(f"连续 {st + 1} 天进度没涨且播放量在涨：播放被判无效的可能性大（实时复核 {live['rate']}%），"
                             f"超过 4 天了，建议人工查——换目标歌或让号主重新报名 650 任务。")
            else:
                lines.append(f"目前连续 {st + 1} 天未涨，还没到人工门槛：先观察 2~3 天再实时复核一次；"
                             f"期间 CK 活、笔记任务正常跑就先不动。")
        return " ".join(lines)

    # ⑦ 正常
    if rate_t is not None and rate_y is not None and rate_t > rate_y:
        _rd = rate_t - rate_y
        _rd_s = f"{int(_rd):+d}%" if float(_rd).is_integer() else f"{_rd:+g}%"
        lines.append(f"⑦650 进度正常爬坡（昨天 {rate_y:g}% → 今天 {rate_t:g}%，{_rd_s}），"
                     f"播放量变化 {rpcD:+d} 次，一切正常，不用管。")
        return " ".join(lines)

    lines.append("⑦数据不足以给出确定结论（快照缺失或字段异常），建议明天快照出来后再看一天。")
    return " ".join(lines)


# ---------------------------------------------------------------- 主流程
def health(key, refresh=False, no_live=False, only_pool=None, quiet=False):
    """跑一次完整体检。

    quiet=False（默认）：边跑边打印（命令行模式），报告行同时存 rep。
    quiet=True（网页服务模式）：不打印只采集，返回报告行列表（网页端自行排版）。
    返回 rep（文本行列表）。"""
    rep = []
    def _say(s=""):
        rep.append(s)
        if not quiet:
            print(s)
    say = _say

    say("=" * 74)
    say(f"号体检报告：{key}    生成时间：{datetime.now(BJ):%Y-%m-%d %H:%M} 北京")
    say("=" * 74)

    # 1 镜像
    dbf, how = ensure_mirror(refresh)
    say(f"\n【0】数据镜像：{os.path.basename(dbf)}  ← {how}")
    db = sqlite3.connect(dbf)
    db.row_factory = sqlite3.Row

    # 2 找号
    accs = find_account(db, key)
    if not accs:
        say(f"\n【账号】没找到手机号/uid 为 {key} 的在池账号（accounts 全表无匹配）。")
        if dead_history(db, key, say):
            say("\n【说明】该号已被删号：删号后 accounts 表不再有它的行，所以号池列表查不到——这是设计，"
                "不是数据丢了。上面【D1】~【D5】就是它的全部历史档案。")
            say("    按 11-20 口径（CK三类来源存活对比文档）：CK 失效删号是终态，反复重登有害要劝阻，"
                "不要引导号主复活；如果买家质疑，把直邮记录和快照走势给TA看即可。")
            say("    死因判读（毒源=服务端程序化轮询登录态接口，与出口 IP 无关）：")
            say("      · 2026-11-20 12:38 前登记的扫码号走「老二维码」链路（服务端轮询出码）→ 3~5 天批量清算属预期，"
                "走家宽出口也照死；")
            say("      · 11-20 12:38 起已全量切笔记本真浏览器 bridge 出码（真 Chrome，机理同手动长效 CK）→ "
                "这批号若 3~5 天内死则不正常，首批清算观察点 11-24~25。")
        else:
            say("  可能是：手机号记错 / 镜像数据滞后（可勾选「强制重导 D1 镜像」再试）/ 从未登记过。")
        return rep
    if only_pool:
        accs = [a for a in accs if a["pool"] == only_pool]
    targets = []
    for e in accs:
        say(f"\n【1】账号：池(pool)={e['pool']}  uid(网易用户ID)={e['uid']}  手机号={e['name']}  代理(agent)={e['agent']}")
        say(f"    登记时间(added)={e['added']}  套餐(plan)={e['plan']}  到期(exp)={e['exp']}  公益号(pub)={'是' if e['pub'] else '否'}"
            f"  退款(rb)={'是(rb=%d)' % e['rb'] if e['rb'] else '否'}  CK嫌疑标记={e['suspect_at'] or '无'}")
        say(f"    目标歌(song)={e['song']}  只收不听(no_listen)={e['no_listen']}  资料更新时间(updated_at)={bj_str(e['updated_at'])}（北京时间）")
        # 登记链路（11-20 12:38 锚点：前=老二维码服务端轮询（毒源），后=笔记本真浏览器 bridge）
        _eg = {"home_browser": "笔记本真浏览器出码(新链路·bridge)",
               "home_relay": "家宽转发·服务端轮询出码(老链路·毒源)"}.get(
            e["login_egress"] or "", f"未记录({e['login_egress'] or '-'})")
        _mt = {"link_qr": "链接扫码", "manual_import": "客服EXE+验证码"}.get(
            e["registration_method"] or "", e["registration_method"] or "未记录")
        _era = "⚠ 老链路时代登记，3~5 天清算窗口风险" if (e["login_egress"] or "") == "home_relay" else ""
        say(f"    登记方式(registration_method)={_mt}  登录链路(login_egress)={_eg}{_era}")
        targets.append(dict(e))

    for e in targets:
        pool, uid = e["pool"], e["uid"]
        owner = None
        today_day = datetime.now(BJ).strftime("%Y-%m-%d")
        yest_day = (datetime.now(BJ) - timedelta(days=1)).strftime("%Y-%m-%d")

        # 3 快照走势（近 14 天）＋ 近 3 天换歌/冻结处置联动（2026-11-19 新增）
        actions = recent_song_actions(db, pool, uid)
        act_by_day = {}
        for act in actions:
            d10 = str(act.get("created_at") or "")[:10]
            if d10:
                act_by_day.setdefault(d10, []).append(act)
        say(f"\n【2】近 14 天快照走势（pool={pool}）：")
        rows = list(db.execute(
            "SELECT day,rate,rpc30,at,missions FROM snapshots WHERE pool=? AND uid=? "
            "AND day>=? ORDER BY day", (pool, uid,
            (datetime.now(BJ) - timedelta(days=14)).strftime("%Y-%m-%d"))))
        hist = {}
        if rows:
            say(f"    {'日期':<12}{'650进度(rate)':>14}{'近30日播放(rpc30)':>18}   快照时刻(北京)")
            for r in rows:
                hist[r["day"]] = dict(r)
                note = ""
                for act in act_by_day.get(r["day"], []):
                    note += f"  ←{act_desc(act)}"
                say(f"    {r['day']:<12}{str(r['rate']):>8}%{str(r['rpc30']):>12}   {bj_str(r['at'])}{note}")
        else:
            say("    （14 天内无任何快照——新号或一直没跑）")
        # 实跑记录（runs 表：relay 真派到这个号、跑完了才写入，每天每号一条）
        rr = runs_recent(db, pool, uid)
        if rr is not None:
            if rr:
                say("    近 14 天实跑记录（runs 表，真跑了才有行）：")
                for r in rr:
                    say(f"      {r['day']}  ✓ 片(slice)={r['slice'] or '-'}  跑完入账时刻={bj_str(r['at'])}（北京）")
                missed = sorted({r["day"] for r in rows} - {r["day"] for r in rr})
                if missed:
                    say(f"      ⚠ 快照有但没实跑的日期：{'、'.join(missed)}（当天 relay 没派到这个号）")
            else:
                say("    ⚠ 近 14 天没有任何实跑记录（runs 表零行）——relay 一直没派到这个号，"
                    "播放量不可能涨，先查派片/灰度名单，别往网易侧怀疑。")
        a, p, marks = compute_marks(db, pool, uid, today_day, yest_day, hist)
        rpcD = (a["rpc30"] - p["rpc30"]) if (a and p and a["rpc30"] is not None and p["rpc30"] is not None) else None

        # 4 标记
        say(f"\n【3】控制台标记复算（今天 {today_day} vs 昨天 {yest_day}）：")
        if marks:
            for name, _, desc in marks:
                say(f"    ▸ [{name}] {desc}")
            if cooling_actions(actions) and any(n.startswith("连续") for n, _, _ in marks):
                say("    ℹ 该号近 3 天刚做过换歌/冻结处置（见【2】行尾标注）：按 mail_scan 冷却期口径，"
                    "换歌后 3 天内的「连续未涨」不计入冻结判定，此标记暂不必理会。")
        else:
            say("    ▸ 无异常标记（650 在涨或已做满）")

        # 5 实时复核
        live = None
        if not no_live and e["ck"]:
            say(f"\n【4】实时复核创作者后台（只读查询，1 次）：")
            try:
                runmod = load_runpy()
                live = live_check(runmod, e["ck"])
                if live.get("alive"):
                    say(f"    CK=活号；实时 650 进度={live.get('rate')}%  实时近30日播放={live.get('rpc30')}")
                    say(f"    任务总开关(taskStatus)={tf(live.get('taskStatus'))}  是音乐人(isMusician)={tf(live.get('isMusician'))}  "
                        f"特殊权益已开通(hasOpen)={tf(live.get('hasOpen'))}  可开通(canOpen)={tf(live.get('canOpen'))}")
                    say(f"    音乐人身份状态(status)={live.get('status')}  维持天数(maintainDays)={live.get('maintainDays')}  "
                        f"特殊权益生效(unlockVipRight)={tf(live.get('unlockVipRight'))}  650任务状态(missionStatus)={live.get('missionStatus')}")
                    np = live.get("noteProgress")
                    say(f"    笔记发布进度={np if np is not None else '未返回'}"
                        f"{'/4（30 天内发笔记天数，封顶 4；走势详见【8】）' if np is not None else ''}")
                    say("    （furtherTaskStartTime/furtherVipGetTime 字段网易数据不可信，仅留档不参与判定）")
                else:
                    say(f"    ⚠️ CK 状态：{live['text']}——如果判失效，先让买家换 CK 再谈其他")
            except Exception as ex:
                say(f"    实时复核失败：{ex}")
        else:
            say("\n【4】实时复核：跳过（--no-live 或无 CK）" if no_live
                else "\n【4】实时复核：跳过（该号在镜像里没有 CK）")

        # 6 歌曲归属
        if e["song"]:
            say(f"\n【5】目标歌归属验证：")
            owner = song_owner(e["song"])
            if owner.get("error"):
                say(f"    查询失败：{owner['error']}")
            else:
                say(f"    《{owner.get('name')}》(id={e['song']})")
                okflag = False
                for art in owner.get("artists", []):
                    hit = str(art.get("accountId")) == str(uid)
                    okflag = okflag or hit
                    say(f"    艺人「{art.get('name')}」(id={art.get('id')})  accountId(网易账号ID)={art.get('accountId')}"
                        f"  {'✅ 就是号主本人' if hit else ''}")
                if not okflag:
                    say("    ⚠️ 没有任何艺人绑定到号主 uid——如果这是号主小号名下的歌，播放可能全无效，重点怀疑！")

        # 7 台账
        say(f"\n【6】台账记录（ledger，购买/续费流水）：")
        has_ledger = "ledger" in {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        led = list(db.execute(
            "SELECT day,agent,plan,price,days,start,exp,rb,remark,src FROM ledger "
            "WHERE pool=? AND (uid=? OR name=?) ORDER BY day DESC LIMIT 10", (pool, uid, e["name"]))) if has_ledger else []
        if led:
            say(f"    {'日期':<12}{'代理':<6}{'套餐':<8}{'价格':>8}{'天数':>5}  起始       到期       备注")
            for r in led:
                price = "待补价" if r["price"] is None else f"{r['price']:.0f}元"
                say(f"    {r['day']:<12}{r['agent'] or '-':<6}{r['plan'] or '-':<8}{price:>8}{str(r['days']):>5}  "
                    f"{r['start'] or '-'}  {r['exp'] or '-'}  {r['remark'] or ''}")
        else:
            say("    无台账" + ("（可能是免费/公益号或漏登记——漏账可用 tmp\\ledger_backfill_1110.py 补）"
                              if has_ledger else "（镜像里没导 ledger，跑一次不带 --table 的 d1_mirror.py 或删掉旧镜像后重试）"))

        # 7 邮件提醒记录（2026-11-20 更新口径：11-18 已废除「已通知重登」，relogin_at 不再写入）
        say(f"\n【7】邮件提醒记录（邮件队列 mail_queue / 删号通知 dead_notice / 删号流水 dead_log）：")
        say("    当前邮件口径：判死/过期号 → 立即删号 + 直邮（notify-dead），没有「先通知重登、留缓冲期」这回事；"
            "管理员手动删号不发邮件（11-19 起）。")
        if e['relogin_at']:
            say(f"    relogin_at={e['relogin_at']}：11-18 废除重登机制前的历史遗留记录，该字段现已不再写入，仅留档。")
        tabs_now = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        mails = list(db.execute(
            "SELECT kind,ref,state,created_at,claimed_at,sent_at,skip_reason FROM mail_queue "
            "WHERE pool=? AND uid=? ORDER BY created_at DESC LIMIT 20", (pool, uid))) if "mail_queue" in tabs_now else []
        notices = list(db.execute(
            "SELECT kind,state,removed_at,sent_at,skip_reason FROM dead_notice "
            "WHERE pool=? AND (uid=? OR name=?) ORDER BY removed_at DESC LIMIT 10", (pool, uid, e["name"]))) if "dead_notice" in tabs_now else []
        deads = list(db.execute(
            "SELECT reason,at FROM dead_log WHERE pool=? AND (uid=? OR name=?) ORDER BY at DESC LIMIT 5",
            (pool, uid, e["name"]))) if "dead_log" in tabs_now else []
        state_cn = {"sent": "已发出", "claimed": "发送中", "pending": "排队中",
                    "dropped": "已放弃(连败3次)", "skipped": "已跳过",
                    "skip_returned": "已回池·不发", "skip_noemail": "无邮箱·不发"}
        if mails or notices or deads:
            if deads:
                for r in deads:
                    say(f"    ✂ 删号流水：{r['reason']}  {r['at']}")
            for r in notices:
                st = state_cn.get(r["state"], r["state"])
                say(f"    ✉ 删号通知[{r['kind'] or 'dead'}]：{st}  入队 {r['removed_at']}  发出 {r['sent_at'] or '—'}"
                    + (f"（{r['skip_reason']}）" if r["skip_reason"] else ""))
            if mails:
                say(f"    {'类型':<26}{'状态':<10}{'入队时间':<21}{'发出时间':<21}备注")
                for r in mails:
                    st = state_cn.get(r["state"], r["state"])
                    kind = KIND_CN.get(r["kind"], r["kind"])
                    say(f"    {kind:<26}{st:<10}{r['created_at'] or '-':<21}{r['sent_at'] or '-':<21}{r['skip_reason'] or ''}")
        else:
            say("    无任何邮件记录：这个号从未进过任何邮件队列，也从未发过重登邮件。")
            say("    注意：重登邮件只由采集判死链路触发（run.py 判死→直邮→写 relogin_at）；")
            say("    号还没被采集判死（比如只显示「采集缺失」）时，不会有任何邮件。")
            if "mail_queue" not in tabs_now:
                say("    （镜像缺 mail_queue/dead_notice 表，本次显示不完整——删旧镜像后重跑会自动重导）")

        # 8 笔记发布（2026-11-20 新增：网易同组小任务「30 天内发布图文笔记天数 ≥4」，与播放无关）
        NOTE_KEY = "mission_code_musician_notebook_publish"
        note_rows = []
        for r in rows:
            try:
                mis = json.loads(r["missions"]) if r["missions"] else {}
            except (TypeError, ValueError):
                mis = {}
            v = mis.get(NOTE_KEY)
            if v is not None:
                try:
                    note_rows.append((r["day"], int(v)))
                except (TypeError, ValueError):
                    pass
        live_np = (live or {}).get("noteProgress") if (live and live.get("alive")) else None
        say(f"\n【8】笔记发布情况（网易任务 mission_code_musician_notebook_publish："
            f"30 天内发布图文笔记的天数 ≥4，进度封顶 4/4）：")
        if live_np is not None:
            say(f"    实时复核：当前笔记进度 {live_np}/4"
                + ("（已满，本轮周期内不再发，属正常）" if live_np >= 4 else ""))
        if note_rows:
            say(f"    {'日期':<12}{'笔记进度':>8}   说明")
            prev = None
            for day, v in note_rows:
                if prev is None:
                    note = ""
                elif v == prev + 1:
                    note = "当天发过笔记（+1 天）"
                elif v > prev:
                    note = f"补涨 +{v - prev}（中间有快照没采到）"
                elif v < prev:
                    note = "进度回落（30 天窗口滚动，老的天数过期退出）"
                else:
                    note = ""
                prev = v
                say(f"    {day:<12}{f'{v}/4':>8}   {note}")
            last_v = note_rows[-1][1]
            if last_v >= 4:
                say("    ✅ 已发满 4/4：本轮任务完成。notes.py 有进度门控（11-11 起），满了自动停发，不用管。")
            else:
                say("    ℹ 发布节奏（notes.py 现口径，2026-11 核对代码）：每晚北京 22:23 随 relay 触发，"
                    "全部号每天都尝试发一篇；发布前先读任务进度——满 4/4 自动跳过（进度门控），没满就发；"
                    "发完 40~60 秒自动删动态（进度实时结算，删了不影响计数）。所以进度从 0 连涨到 4/4 是正常节奏，"
                    "涨满后不动=门控停发。只有「进度没满却连续 2 周不涨」才需要查"
                    "（多半是 CK 失效或被平台 250 风控——被风控的号会收到「安全验证分享异常」提醒邮件，见【7】）。")
        else:
            say("    近 14 天快照里没有笔记进度数据：可能是新号、当天快照网易没返回该子任务，或 missions 没上报。")
            if live_np is None and live and live.get("alive"):
                say("    实时复核也没拿到笔记进度：该号可能不是音乐人或没进进阶任务，见【4】的 isMusician/hasOpen。")

        # 9 结论
        say(f"\n【9】结论分析：")
        say("    " + verdict(e, hist, a, p, marks, live, owner, rpcD, actions))
        say()

    # 存档
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"体检_{key}_{datetime.now(BJ):%Y%m%d_%H%M}.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(rep))
    if not quiet:
        print(f"\n报告已存：{out}")
    return rep


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="号体检：单账号零增长/650 进度一键排查")
    ap.add_argument("key", nargs="?", default="", help="手机号或 uid")
    ap.add_argument("--refresh", action="store_true", help="强制重导 D1 镜像")
    ap.add_argument("--no-live", action="store_true", help="跳过实时复核（不查网易接口）")
    ap.add_argument("--pool", default="", help="只查指定池 hz|dz（默认两个都查）")
    a = ap.parse_args()
    if not a.key:
        # 双击 bat 无参数时在这里交互输入（bat 保持纯 ASCII，中文提示放 python 端避免编码闪退）
        try:
            a.key = input("请输入手机号或 uid: ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)
        if not a.key:
            print("未输入任何内容，退出。")
            sys.exit(0)
    health(a.key, refresh=a.refresh, no_live=a.no_live, only_pool=a.pool or None)

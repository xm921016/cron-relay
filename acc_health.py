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


def load_runpy():
    """加载 cron-relay/run.py（有 __main__ 保护，import 安全）。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("runmod", os.path.join(CR, "run.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ---------------------------------------------------------------- 第 1 步 镜像
def ensure_mirror(refresh=False):
    os.makedirs(MIRROR_DIR, exist_ok=True)
    today = datetime.now(BJ).strftime("%Y%m%d")
    dbs = sorted(glob.glob(os.path.join(MIRROR_DIR, "d1_mirror_*.db")))
    # 今天 08:00（北京，=UTC 日重置）之后导的才算新鲜
    floor = datetime.now(BJ).replace(hour=8, minute=0, second=0, microsecond=0)
    for dbf in reversed(dbs):
        m = re.search(r"d1_mirror_(\d{8})_(\d{4})\.db$", dbf)
        if not m:
            continue
        dt = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M").replace(tzinfo=BJ)
        if dt < floor:
            continue
        # 校验必要表都在（有的镜像只导了部分表）
        try:
            con = sqlite3.connect(dbf)
            tabs = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            con.close()
        except sqlite3.Error:
            continue
        if not {"accounts", "snapshots", "ledger"} <= tabs:
            continue
        if not refresh:
            return dbf, f"复用镜像（{dt:%m-%d %H:%M} 导出，--refresh 可重导）"
    print("  导出 D1 镜像（/export 通道，不吃读配额）…")
    r = subprocess.run(
        [sys.executable, os.path.join(PROJ, "tmp", "d1_mirror.py"),
         "--table", "accounts", "--table", "snapshots", "--table", "ledger"],
        capture_output=True, text=True, cwd=PROJ, timeout=300)
    if r.returncode != 0:
        print(r.stdout[-500:] if r.stdout else "", r.stderr[-500:] if r.stderr else "")
        raise SystemExit("  镜像导出失败")
    dbs = sorted(glob.glob(os.path.join(MIRROR_DIR, "d1_mirror_*.db")))
    return dbs[-1], "新导镜像"


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
def verdict(e, hist_days, a, p, marks, live, owner, rpcD):
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

    # ④ 归零跳变 → 周期换期
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
        lines.append(f"⑦650 进度正常爬坡（昨天 {rate_y}% → 今天 {rate_t}%，{rate_t - rate_y:+d}%），"
                     f"播放量变化 {rpcD:+d} 次，一切正常，不用管。")
        return " ".join(lines)

    lines.append("⑦数据不足以给出确定结论（快照缺失或字段异常），建议明天快照出来后再看一天。")
    return " ".join(lines)


# ---------------------------------------------------------------- 主流程
def health(key, refresh=False, no_live=False, only_pool=None):
    rep = []
    say = lambda s="": (print(s), rep.append(s))

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
        say(f"\n【账号】没找到手机号/uid 为 {key} 的账号（accounts 全表无匹配）。")
        say("  可能是：手机号记错 / 号已删（删号后 accounts 无行，只剩 dead_log） / 在另一个池。")
        return
    if only_pool:
        accs = [a for a in accs if a["pool"] == only_pool]
    targets = []
    for e in accs:
        say(f"\n【1】账号：pool={e['pool']}  uid={e['uid']}  手机号={e['name']}  agent={e['agent']}")
        say(f"    登记时间={e['added']}  套餐={e['plan']}  到期={e['exp']}  公益号={'是' if e['pub'] else '否'}"
            f"  退款={'是(rb=%d)' % e['rb'] if e['rb'] else '否'}  CK嫌疑标记={e['suspect_at'] or '无'}")
        say(f"    目标歌={e['song']}  no_listen={e['no_listen']}  updated_at={bj_str(e['updated_at'])}（北京时间）")
        targets.append(dict(e))

    for e in targets:
        pool, uid = e["pool"], e["uid"]
        owner = None
        today_day = datetime.now(BJ).strftime("%Y-%m-%d")
        yest_day = (datetime.now(BJ) - timedelta(days=1)).strftime("%Y-%m-%d")

        # 3 快照走势（近 14 天）
        say(f"\n【2】近 14 天快照走势（pool={pool}）：")
        rows = list(db.execute(
            "SELECT day,rate,rpc30,at,missions FROM snapshots WHERE pool=? AND uid=? "
            "AND day>=? ORDER BY day", (pool, uid,
            (datetime.now(BJ) - timedelta(days=14)).strftime("%Y-%m-%d"))))
        hist = {}
        if rows:
            say(f"    {'日期':<12}{'650进度':>8}{'近30日播放':>12}   快照时刻(北京)")
            for r in rows:
                hist[r["day"]] = dict(r)
                say(f"    {r['day']:<12}{str(r['rate']):>8}%{str(r['rpc30']):>12}   {bj_str(r['at'])}")
        else:
            say("    （14 天内无任何快照——新号或一直没跑）")
        a, p, marks = compute_marks(db, pool, uid, today_day, yest_day, hist)
        rpcD = (a["rpc30"] - p["rpc30"]) if (a and p and a["rpc30"] is not None and p["rpc30"] is not None) else None

        # 4 标记
        say(f"\n【3】控制台标记复算（今天 {today_day} vs 昨天 {yest_day}）：")
        if marks:
            for name, _, desc in marks:
                say(f"    ▸ [{name}] {desc}")
        else:
            say("    ▸ 无异常标记（650 在涨或已做满）")        # 5 实时复核
        live = None
        if not no_live and e["ck"]:
            say(f"\n【4】实时复核创作者后台（只读查询，1 次）：")
            try:
                runmod = load_runpy()
                live = live_check(runmod, e["ck"])
                if live.get("alive"):
                    say(f"    CK=活号；实时 650 进度={live.get('rate')}%  实时近30日播放={live.get('rpc30')}")
                    say(f"    taskStatus={live.get('taskStatus')}  isMusician={live.get('isMusician')}  "
                        f"hasOpen={live.get('hasOpen')}  canOpen={live.get('canOpen')}")
                    say(f"    音乐人 status={live.get('status')}  维持天数={live.get('maintainDays')}  "
                        f"特殊权益={live.get('unlockVipRight')}  650任务missionStatus={live.get('missionStatus')}")
                    say(f"    笔记任务进度={live.get('noteProgress')}（在跑的佐证）")
                    say("    （furtherTaskStartTime/furtherVipGetTime 字段网易数据不可信，仅留档不参与判定）")
                else:
                    say(f"    ⚠️ CK 状态：{live['text']}——如果判失效，先让买家换 CK 再谈其他")
            except Exception as ex:
                say(f"    实时复核失败：{ex}")
        else:
            say("\n【4】实时复核：跳过（--no-live 或无 CK）")

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
                    say(f"    艺人「{art.get('name')}」(id={art.get('id')}) accountId={art.get('accountId')}"
                        f"  {'✅ 就是号主本人' if hit else ''}")
                if not okflag:
                    say("    ⚠️ 没有任何艺人绑定到号主 uid——如果这是号主小号名下的歌，播放可能全无效，重点怀疑！")

        # 7 台账
        say(f"\n【6】台账记录（ledger）：")
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

        # 8 结论
        say(f"\n【7】结论分析：")
        say("    " + verdict(e, hist, a, p, marks, live, owner, rpcD))
        say()

    # 存档
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, f"体检_{key}_{datetime.now(BJ):%Y%m%d_%H%M}.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(rep))
    print(f"\n报告已存：{out}")


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

#!/usr/bin/env python3
"""家宽扫码出口每日看门狗（egress-watch workflow 配套，2026-11-13 新增）

背景：2026-11-12 深夜上线「家宽隧道出口」（CF Tunnel -> 用户本机 relay.js -> 网易），
worker 侧灰度开关 KV EGRESS_PCT=100，所有买家扫码请求走家宽；隧道故障自动回退 CF 直连。
本脚本每天北京上午跑一次，用数据回答「家宽出口活着吗、登记质量有没有变差」：

  1) 隧道健康：workflow 第一步已实测出码（TUNNEL 环境变量传入）
  2) 登记质量：D1 rate_limit 近 7 天 rqc 会话 / 深度轮询 / 成功提交，算「死会话率」
  3) KV EGRESS_PCT 当前灰度值（读不到不致命）
  4) 每天都发日报邮件；隧道死 或 死会话率突增 时主题带【异常】

数据口径（rate_limit 键族，键尾是北京日期）：
  rqc:<token>:<date>   登记页轮询计数（每个登记页会话一条）
  rtok:<token>:<date>  页面拿到登录凭证（803）
  rsub:<token>:<date>  提交登记成功
  死会话 = 轮询>=3 次（买家真的在操作页面）但既无 rtok 也无 rsub —— 与 11-12 晚
  「扫码确认了却报还没扫码」个案（3M6X7WEU）同口径。

额度注意：3 条 LIKE 前缀查询（rqc:/rtok:/rsub: 前缀走主键索引范围扫描），每天一次，量极小。

环境变量：
  CF_TOKEN / CF_ACCOUNT_ID   Cloudflare API（D1 读 + KV 读）
  D1_UUID                    默认 netpool 54f742fc-5f56-4723-a7a0-a832953d38c7
  KV_NS                      KV 命名空间 id（读 EGRESS_PCT）
  TUNNEL                     OK=隧道健康（第一步写入）；否则视为死
  EMAIL_FROM / EMAIL_AUTH_CODE / ALERT_TO   QQ SMTP 三件套
"""
import datetime
import json
import os
import smtplib
import urllib.request
from email.mime.text import MIMEText

ACC = (os.environ.get("CF_ACCOUNT_ID") or "").strip()
TOK = (os.environ.get("CF_TOKEN") or "").strip()
D1_UUID = (os.environ.get("D1_UUID") or "54f742fc-5f56-4723-a7a0-a832953d38c7").strip()
KV_NS = (os.environ.get("KV_NS") or "").strip()
TUNNEL = (os.environ.get("TUNNEL") or "").strip().upper()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/604.1"
BJ = datetime.timezone(datetime.timedelta(hours=8))
DAYS = 7


def api(url, body=None, method="GET"):
    r = urllib.request.Request(
        url, data=json.dumps(body).encode() if body is not None else None, method=method,
        headers={"Authorization": "Bearer " + TOK, "Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(r, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def d1(sql):
    d = api(f"https://api.cloudflare.com/client/v4/accounts/{ACC}/d1/database/{D1_UUID}/query",
            {"sql": sql}, "POST")
    if not d.get("success"):
        raise RuntimeError(f"D1 查询失败: {d.get('errors')}")
    rows = (d.get("result") or [{}])[0].get("rows") or []
    return rows


def kv_get(key):
    if not KV_NS:
        return "?"
    try:
        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/accounts/{ACC}/storage/kv/namespaces/{KV_NS}/values/{key}",
            headers={"Authorization": "Bearer " + TOK, "User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", "replace").strip() or "(空=全直连)"
    except Exception as e:
        return f"读取失败({e.__class__.__name__})"


def main():
    now = datetime.datetime.now(BJ)
    days = [(now - datetime.timedelta(days=i)).date().isoformat() for i in range(DAYS)]
    month_pref = now.strftime("%Y-%m")

    # 3 条键族查询（前缀可走主键索引；月窗口一次拉够，键尾日期在 Python 侧聚合）
    fam = {}
    for name, prefix in (("rqc", "rqc"), ("rtok", "rtok"), ("rsub", "rsub")):
        rows = d1(f"SELECT k, n FROM rate_limit WHERE k LIKE '{prefix}:%{month_pref}%' LIMIT 100000")
        m = {}
        for r in rows:
            k = r["k"] or ""
            # 键尾日期在最后一段
            date = k.rsplit(":", 1)[-1]
            tok = k[len(prefix) + 1:].rsplit(":", 1)[0]
            m.setdefault(date, {}).setdefault(tok, 0)
            m[date][tok] = max(m[date][tok], int(r.get("n") or 0))
        fam[name] = m

    lines = []
    alert = []
    if TUNNEL == "OK":
        lines.append("隧道健康: OK（出码测试 200）")
    else:
        lines.append("隧道健康: **异常**（出码测试失败，买家已自动走 CF 直连兜底，登记不受影响，但家宽出口没在工作）")
        alert.append("隧道出码失败")

    pct = kv_get("EGRESS_PCT")
    lines.append(f"灰度 EGRESS_PCT: {pct}")

    hdr = "日期 | 会话 | 深度轮询 | 拿到凭证 | 提交成功 | 死会话率"
    lines.append(hdr)
    lines.append("---")
    for d in days:
        rqc = fam["rqc"].get(d, {})
        rtok = set(fam["rtok"].get(d, {}))
        rsub = set(fam["rsub"].get(d, {}))
        sessions = len(rqc)
        engaged = sum(1 for n in rqc.values() if n >= 3)
        ok = len(rtok | rsub)
        dead = max(0, engaged - ok)
        rate = f"{dead / engaged * 100:.0f}%" if engaged else "-"
        lines.append(f"{d} | {sessions} | {engaged} | {len(rtok)} | {len(rsub)} | {rate}")

    # 最近一天死会话率突增判警（与前一日比 +25 个百分点或绝对值>40%）
    d0, d1d = days[0], days[1]
    def dead_rate(d):
        rqc = fam["rqc"].get(d, {})
        ok = set(fam["rtok"].get(d, {})) | set(fam["rsub"].get(d, {}))
        eng = sum(1 for n in rqc.values() if n >= 3)
        return (max(0, eng - len(ok)) / eng * 100) if eng else 0.0
    r0, r1 = dead_rate(d0), dead_rate(d1d)
    if r0 > 40 and r0 - r1 > 25:
        alert.append(f"昨日死会话率 {r0:.0f}% 明显高于前日 {r1:.0f}%")

    body = "\n".join(lines) + "\n\n口径：死会话=轮询>=3次但无凭证无提交（买家在操作但页面没拿到登录凭证，-462 类风控主特征）。\n回退开关：删 KV EGRESS_PCT 即全走 CF 直连。\n"
    subject = ("【异常】" if alert else "") + f"家宽出口日报 {now.date().isoformat()} 隧道{'OK' if TUNNEL=='OK' else '异常'} 死会话率{r0:.0f}%"
    if alert:
        body = "告警: " + "; ".join(alert) + "\n\n" + body

    frm = os.environ.get("EMAIL_FROM") or ""
    code = os.environ.get("EMAIL_AUTH_CODE") or ""
    to = os.environ.get("ALERT_TO") or frm
    if not (frm and code and to):
        print("未配置邮件凭据，跳过发信；日报内容:\n" + body)
        return
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = frm
    msg["To"] = to
    with smtplib.SMTP_SSL("smtp.qq.com", 465, timeout=30) as s:
        s.login(frm, code)
        s.sendmail(frm, [x.strip() for x in to.split(",") if x.strip()], msg.as_string())
    print("日报已发送:", subject)
    print(body)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""号体检网页版 —— 双击 号体检.bat 自动打开浏览器，黑窗口退役。

架构：
    号体检.bat  →  pythonw 本文件（无控制台窗口）  →  127.0.0.1:8765
    页面输入手机号/uid → POST /api/run → acc_health.health(quiet=True) 采集报告行
    → 本文件把报告行排版成 HTML 返回（数据口径 100% 复用 acc_health，不改任何判定逻辑）

要点：
  - 重复双击 bat 不会起第二个服务（先 ping 探活，活着就直接开浏览器页）。
  - 服务常驻后台，页面右上角「关闭体检服务」可退出；重启电脑自然消失。
  - pythonw 无 stdout，启动时把输出重定向到 tmp/acc_health_web.log 便于排障。
  - 端口冲突可设环境变量 ACC_HEALTH_PORT；ACC_HEALTH_NOBROWSER=1 用于无人值守测试。
"""
import html
import json
import os
import re
import sys
import threading
import time
import traceback
import urllib.request
import webbrowser
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CR   = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(CR)
sys.path.insert(0, CR)

BJ   = timezone(timedelta(hours=8))
PORT = int(os.environ.get("ACC_HEALTH_PORT") or 8765)
URL  = f"http://127.0.0.1:{PORT}/"

# pythonw 下 stdout/stderr 为 None，任何 print 都会炸 → 统一重定向到日志
os.makedirs(os.path.join(PROJ, "tmp"), exist_ok=True)
_logf = open(os.path.join(PROJ, "tmp", "acc_health_web.log"), "a", encoding="utf-8")
sys.stdout = _logf
sys.stderr = _logf
try:
    sys.stdout.reconfigure(line_buffering=True)   # pythonw 下不刷缓冲，排障时日志永远是空的
except Exception:
    pass

import acc_health  # noqa: E402  （run.py 有 __main__ 保护，import 安全）
import vip_gift_pool  # noqa: E402  （VIP 赠送池：探测/轮换/发卡，只读+token/create）

RUN_LOCK = threading.Lock()
VIP_LOCK = threading.Lock()          # VIP 探测/发卡互斥（同一时刻只跑一个 VIP 动作）
VIP_JOB = {"running": False, "kind": "", "done": 0, "total": 0,
           "cur": "", "log": [], "err": "", "finished_at": ""}


def _vip_log(s):
    VIP_JOB["log"].append("%s %s" % (datetime.now(BJ).strftime("%H:%M:%S"), s))
    VIP_JOB["log"] = VIP_JOB["log"][-200:]


def _vip_probe_worker(full):
    try:
        def cb(done, total, uid, r):
            VIP_JOB["done"], VIP_JOB["total"] = done, total
            VIP_JOB["cur"] = uid
            if done % 20 == 0 or done == total:
                _vip_log("探测 %d/%d 最新 uid=%s vip=%s left=%s" % (
                    done, total, uid, r.get("vip_level"), r.get("send_left")))
        vip_gift_pool.probe(full=full, progress_cb=cb, stop_flag=VIP_JOB)
        _vip_log("探测完成 %d/%d" % (VIP_JOB["done"], VIP_JOB["total"]))
    except Exception as e:
        VIP_JOB["err"] = f"{type(e).__name__}: {e}"
        _vip_log("探测异常：" + VIP_JOB["err"])
    finally:
        VIP_JOB["running"] = False
        VIP_JOB["finished_at"] = datetime.now(BJ).strftime("%H:%M:%S")


def _vip_take_worker(n):
    try:
        def cb(i, n_, rec):
            VIP_JOB["done"], VIP_JOB["total"] = i, n_
            if rec.get("error"):
                _vip_log("第 %d 张失败：%s" % (i, rec["error"]))
            else:
                _vip_log("第 %d 张成功：donor=%s(%s) 链接已生成" % (
                    i, rec.get("donor_name"), rec.get("donor_uid")))
        results = vip_gift_pool.take(n, progress_cb=cb)
        VIP_JOB["results"] = results
        _vip_log("发卡流程结束（成功 %d / 失败 %d）" % (
            sum(1 for r in results if not r.get("error")),
            sum(1 for r in results if r.get("error"))))
    except Exception as e:
        VIP_JOB["err"] = f"{type(e).__name__}: {e}"
        _vip_log("发卡异常：" + VIP_JOB["err"])
    finally:
        VIP_JOB["running"] = False
        VIP_JOB["finished_at"] = datetime.now(BJ).strftime("%H:%M:%S")

# ---------------------------------------------------------------- 文本行 → HTML
# 章节号支持纯数字（0~9）和 D 系列已删号历史章节（D1~D5，2026-11-21）
SEC_RE = re.compile(r"^\s*【(\d+|D\d+)】\s*(.*)$", re.IGNORECASE)
ROW2_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(.+?)%\s+(\S+)\s+(\d{2}-\d{2}\s+\d{2}:\d{2})\s*(.*)$")

MARK_CLS = {
    "已达100%": "b-green", "无650任务": "b-gray", "今日入池·无快照": "b-gray",
    "采集缺失": "b-gray", "有播放·650为0": "b-orange",
}


def esc(s):
    return html.escape(str(s), quote=False)


def rate_badge(v):
    """650 进度 → 彩色徽章（0%=红、>=100%=绿、其余黄、None=灰）。"""
    if v in (None, "None", ""):
        return '<span class="badge b-gray">无</span>'
    try:
        f = float(v)
    except (TypeError, ValueError):
        return f'<span class="badge b-gray">{esc(v)}</span>'
    cls = "b-green" if f >= 100 else ("b-red" if f == 0 else "b-yellow")
    return f'<span class="badge {cls}">{f:g}%</span>'


def kv_chips(line):
    """一行 key=value 对（≥2 空格分隔）→ chips；返回 (chips, 剩余文本)。
    键长上限 26：适配「中文说明(english_field)」双语键名（2026-11-20）。"""
    chips, rest = [], []
    for t in re.split(r"\s{2,}", line.strip()):
        m = re.match(r"^([^=\s]{1,26})=(.+)$", t)
        if m:
            chips.append((m.group(1), m.group(2)))
        elif t:
            rest.append(t)
    return chips, " ".join(rest)


def render_line(ln, cls=""):
    """兜底：普通文本行 → chip 化或段落。"""
    if not ln.strip():
        return ""
    chips, rest = kv_chips(ln)
    if chips:
        out = "".join(f'<span class="chip"><b>{esc(k)}</b>{esc(v)}</span>' for k, v in chips)
        if rest:
            out += f'<span class="chip">{esc(rest)}</span>'
        return f'<div class="ln {cls}">{out}</div>'
    t = esc(ln.strip())
    if "✅" in t:
        t = f'<span class="ok">{t}</span>'
    elif "⚠️" in t:
        t = f'<span class="warn">{t}</span>'
    return f'<div class="ln {cls}">{t}</div>'


def render_marks(lines):
    out = []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("▸ ["):
            m = re.match(r"^▸\s*\[(.+?)\]\s*(.*)$", s)
            if m:
                cls = MARK_CLS.get(m.group(1), "b-yellow")
                out.append(f'<div class="mark"><span class="badge {cls}">{esc(m.group(1))}</span>'
                           f'<span class="mark-desc">{esc(m.group(2))}</span></div>')
                continue
        out.append(render_line(s, "ln-note"))
    return "\n".join(out)


def render_snap(lines):
    """【2】快照走势 → 表格（事件标注并入备注列）。"""
    rows, other = [], []
    for ln in lines:
        s = ln.strip()
        if not s or ("日期" in s and "650进度" in s):
            continue
        m = ROW2_RE.match(s)
        if m:
            note = m.group(5).strip().lstrip("←").strip()
            rows.append((m.group(1), m.group(2).strip(), m.group(3), m.group(4), note))
        else:
            other.append(s)
    out = ['<table><thead><tr><th>日期</th><th>650进度(rate)</th><th>近30日播放(rpc30)</th>'
           '<th>快照时刻(北京)</th><th>事件备注</th></tr></thead><tbody>']
    for day, rate, rpc, at, note in rows:
        note_html = f'<span class="evt">← {esc(note)}</span>' if note else ""
        out.append(f"<tr><td>{esc(day)}</td><td>{rate_badge(rate)}</td><td>{esc(rpc)}</td>"
                   f"<td>{esc(at)}</td><td>{note_html}</td></tr>")
    out.append("</tbody></table>")
    out += [render_line(s) for s in other]
    return "\n".join(out)


def render_tbl(lines, must):
    """通用表：某行含 must 关键词 → 用**该行实际文本**当表头（不再写死列名），
    其后 ≥2 空格分隔的行 → 数据行；遇到非表行即收表，保持原文行序。"""
    out, headers, rows = [], None, []

    def flush():
        nonlocal headers, rows
        if headers and rows:
            out.append("<table><thead><tr>" +
                       "".join(f"<th>{esc(h)}</th>" for h in headers) +
                       "</tr></thead><tbody>")
            for r in rows:
                out.append("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>")
            out.append("</tbody></table>")
        headers, rows = None, []

    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if headers is None:
            if must in s and re.search(r"\s{2,}", s):
                headers = [c for c in re.split(r"\s{2,}", s) if c]
            else:
                out.append(render_line(s, "ln-note" if s.startswith(("✂", "✉", "ℹ")) else ""))
        else:
            cells = [c for c in re.split(r"\s{2,}", s) if c]
            if len(cells) >= 2:
                rows.append(cells)
            else:
                flush()
                out.append(render_line(s, "ln-note" if s.startswith(("✂", "✉", "ℹ")) else ""))
    flush()
    return "\n".join(out)


def render_section(sec):
    n, lines = sec["num"], sec["lines"]
    if n == 2:
        return render_snap(lines)
    if n == 3:
        return render_marks(lines)
    if n == 6:
        return render_tbl(lines, "日期")
    if n == 7:
        return render_tbl(lines, "类型")
    if n == 8:
        return render_tbl(lines, "日期")
    if n == 9:
        body = " ".join(x.strip() for x in lines if x.strip())
        return f'<div class="conclusion-text">{esc(body)}</div>'
    return "\n".join(render_line(x) for x in lines if x.strip())


def render_html(rep, key):
    header, secs = None, []
    cur = None
    for ln in rep:
        s = ln.rstrip()
        if s.strip() and set(s.strip()) == {"="}:
            continue
        m = SEC_RE.match(s)
        if m:
            title = m.group(2).strip()
            label, _, rest = title.partition("：")
            num_raw = m.group(1)
            cur = {"num": int(num_raw) if num_raw.isdigit() else num_raw.upper(),
                   "label": label.strip() or title,
                   "lines": ([rest.strip()] if rest.strip() else [])}
            secs.append(cur)
            continue
        if cur is None:
            if s.strip() and header is None:
                header = s.strip()
            continue
        cur["lines"].append(s)

    mtitle = re.match(r"号体检报告：(\S+)\s+生成时间：(.+)", header or "")
    key_show = esc(mtitle.group(1)) if mtitle else esc(key)
    time_show = esc(mtitle.group(2)) if mtitle else ""

    body = []
    for sec in secs:
        body.append(f'<div class="card"><h2><span class="secno">{sec["num"]}</span>'
                    f'{esc(sec["label"])}</h2>{render_section(sec)}</div>')

    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>号体检报告 - """ + key_show + """</title>
<style>
body{background:#f3f4f6;color:#1f2937;font-family:"Microsoft YaHei",system-ui,sans-serif;
     font-size:14px;line-height:1.6;margin:0}
.wrap{max-width:980px;margin:0 auto;padding:24px 16px 60px}
.head{background:linear-gradient(135deg,#2563eb,#4f46e5);color:#fff;border-radius:12px;
      padding:20px 24px;margin-bottom:16px}
.head h1{margin:0 0 4px;font-size:20px}
.head .t{opacity:.85;font-size:13px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px 20px;
      margin-bottom:14px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.card h2{margin:0 0 12px;font-size:15px;display:flex;align-items:center;gap:8px;
         border-bottom:1px solid #f1f5f9;padding-bottom:8px}
.secno{background:#2563eb;color:#fff;border-radius:6px;font-size:12px;
       min-width:20px;text-align:center;padding:1px 5px}
.ln{margin:4px 0}
.ln-note{color:#64748b;font-size:13px}
.chip{display:inline-block;background:#f8fafc;border:1px solid #e5e7eb;border-radius:6px;
      padding:2px 8px;margin:2px 6px 2px 0;font-size:13px;word-break:break-all}
.chip b{color:#94a3b8;font-weight:500;margin-right:4px}
table{width:100%;border-collapse:collapse;font-size:13px;margin:4px 0}
th{background:#f8fafc;text-align:left;padding:6px 10px;color:#64748b;font-weight:500;
   border-bottom:1px solid #e5e7eb;white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid #f3f4f6;vertical-align:top}
.badge{display:inline-block;border-radius:999px;padding:1px 10px;font-size:12px;white-space:nowrap}
.b-green{background:#ecfdf5;color:#059669}
.b-yellow{background:#fffbeb;color:#d97706}
.b-orange{background:#fff7ed;color:#ea580c}
.b-red{background:#fef2f2;color:#dc2626}
.b-gray{background:#f1f5f9;color:#64748b}
.mark{display:flex;gap:8px;margin:6px 0;align-items:flex-start}
.mark-desc{flex:1}
.ok{color:#059669}.warn{color:#dc2626}
.evt{color:#2563eb;font-size:12px}
.card h2 + .conclusion-text, .conclusion-text{font-size:14px}
</style></head><body><div class="wrap">
<div class="head"><h1>🩺 号体检报告：""" + key_show + """</h1>
<div class="t">生成时间：""" + time_show + """ ｜ 口径与命令行版完全一致（acc_health.py 同一套逻辑）</div></div>
""" + "\n".join(body) + """
</div></body></html>"""


# ---------------------------------------------------------------- 页面
PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>号体检</title>
<style>
body{background:#f3f4f6;color:#1f2937;font-family:"Microsoft YaHei",system-ui,sans-serif;
     font-size:14px;line-height:1.6;margin:0}
.wrap{max-width:980px;margin:0 auto;padding:32px 16px 60px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:24px 28px;
      margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
h1{font-size:20px;margin:0 0 16px}
label{font-size:13px;color:#475569}
input[type=text]{width:320px;max-width:100%;padding:8px 12px;border:1px solid #cbd5e1;
                 border-radius:8px;font-size:15px}
button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:9px 22px;
       font-size:15px;cursor:pointer}
button:disabled{background:#93c5fd;cursor:not-allowed}
button.ghost{background:#fff;color:#64748b;border:1px solid #cbd5e1;font-size:13px}
.opts{margin:14px 0;display:flex;gap:22px;flex-wrap:wrap;align-items:center}
#status{margin-top:12px;font-size:13px;color:#64748b}
#status.err{color:#dc2626}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #cbd5e1;
      border-top-color:#2563eb;border-radius:50%;animation:r 0.8s linear infinite;
      vertical-align:-2px;margin-right:6px}
@keyframes r{to{transform:rotate(360deg)}}
</style></head><body><div class="wrap">
<div class="card">
  <h1 id="sec-health">🩺 号体检</h1>
  <div>输入手机号或 uid，一键排查单账号的零增长 / 650 进度 / 笔记发布 / 删号邮件等问题。</div>
  <div style="margin-top:14px">
    <label>手机号或 uid：</label>
    <input type="text" id="key" placeholder="如 18888888888">
    <button id="go" onclick="run()">开始体检</button>
  </div>
  <div class="opts">
    <label title="体检前先实时查一次网易创作者后台（只读），区分「快照采早了」和「真停滞」，约多等 10~30 秒">
      <input type="checkbox" id="live" checked> 实时复核创作者后台（只读 1 次，约多等 10~30 秒）</label>
    <label title="不勾：复用今天 08:00 后已导出的本地镜像（秒出）；勾选：重新从线上导一份最新数据再体检，约多等 20~60 秒，失败会自动重试一次">
      <input type="checkbox" id="refresh"> 强制重导 D1 镜像</label>
    <label>池：
      <select id="pool"><option value="">自动（hz+dz 都查）</option>
      <option value="hz">hz</option><option value="dz">dz</option></select></label>
  </div>
  <div id="status"></div>
</div>
  <div id="result"></div>
<div style="text-align:center;color:#94a3b8;font-size:12px;margin-top:18px">
  号体检服务常驻本机后台：关掉网页不影响，双击 号体检&amp;VIP赠送.bat 随时再开；重启电脑自动消失。<br>
  VIP 赠送池已拆分为独立页：<a href="/vip" style="color:#2563eb">点这里打开 VIP 赠送池</a>
</div>
<script>
function run(){
  const k=document.getElementById('key').value.trim();
  if(!k){alert('请输入手机号或 uid');return}
  const b=document.getElementById('go');b.disabled=true;
  const st=document.getElementById('status');st.className='';
  const extra=document.getElementById('refresh').checked?'，含强制重导镜像，失败会自动重试':'';
  st.innerHTML='<span class="spin"></span>正在体检 '+k+' …'+extra+'（实时复核约需 10~30 秒，请勿关闭页面）';
  document.getElementById('result').innerHTML='';
  fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({key:k,no_live:!document.getElementById('live').checked,
      refresh:document.getElementById('refresh').checked,
      pool:document.getElementById('pool').value})})
  .then(r=>r.json()).then(d=>{
    if(d.ok){st.textContent='✅ 完成，文本版已存档到 tmp\\\\体检_'+k+'_'+d.ts+'.txt';
      document.getElementById('result').innerHTML=d.html;
      document.getElementById('result').scrollIntoView({behavior:'smooth'});}
    else{st.className='err';st.textContent='❌ '+(d.error||'未知错误');}
  }).catch(e=>{st.className='err';st.textContent='❌ 请求失败：'+e})
    .finally(()=>{b.disabled=false});
}
document.getElementById('key').addEventListener('keydown',e=>{if(e.key==='Enter')run()});
</script></body></html>"""

# 2026-11-25：VIP 赠送池拆为独立页（/vip），与号体检彻底分开（用户要求两个界面完全不一样）。
PAGE_VIP = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VIP 赠送池</title>
<style>
body{background:#f3f4f6;color:#1f2937;font-family:"Microsoft YaHei",system-ui,sans-serif;
     font-size:14px;line-height:1.6;margin:0}
.wrap{max-width:980px;margin:0 auto;padding:32px 16px 60px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:24px 28px;
      margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
h1{font-size:20px;margin:0 0 16px}
label{font-size:13px;color:#475569}
input[type=text]{width:320px;max-width:100%;padding:8px 12px;border:1px solid #cbd5e1;
                 border-radius:8px;font-size:15px}
button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:9px 22px;
       font-size:15px;cursor:pointer}
button:disabled{background:#93c5fd;cursor:not-allowed}
button.ghost{background:#fff;color:#64748b;border:1px solid #cbd5e1;font-size:13px}
.opts{margin:14px 0;display:flex;gap:22px;flex-wrap:wrap;align-items:center}
#status{margin-top:12px;font-size:13px;color:#64748b}
#status.err{color:#dc2626}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #cbd5e1;
      border-top-color:#2563eb;border-radius:50%;animation:r 0.8s linear infinite;
      vertical-align:-2px;margin-right:6px}
@keyframes r{to{transform:rotate(360deg)}}
</style></head><body><div class="wrap">
<div class="card">
  <h1 id="sec-vip">🎁 VIP 赠送池 <span style="font-size:12px;color:#64748b;font-weight:400">黑胶 V2+ 且本月从未赠送的号，排队依次生成赠送链接</span></h1>
  <div id="vipstats" style="display:flex;gap:10px;flex-wrap:wrap;margin:10px 0"></div>
  <div class="opts">
    <button class="ghost" onclick="vipProbe(false)">增量探测（只探新增号，秒级）</button>
    <button class="ghost" onclick="vipProbe(true)">全量探测（2000+ 号约 100 分钟，跨月自动全量）</button>
    <span>生成链接：</span>
    <input type="number" id="vipn" value="1" min="1" max="20" style="width:60px;padding:6px 8px;border:1px solid #cbd5e1;border-radius:8px">
    <button onclick="vipTake()">🎁 生成赠送链接</button>
  </div>
  <div id="vipjob" style="margin-top:8px;font-size:13px;color:#64748b"></div>
  <div id="vipresults" style="margin-top:8px"></div>
  <div style="margin-top:10px">
    <div style="font-size:13px;color:#475569;margin-bottom:6px">提取队列前 30（轮换序：本月没用过的优先 → 最近用过的靠后 → 额度厚的优先）</div>
    <table id="vipqueue"></table>
  </div>
  <div style="margin-top:10px">
    <div style="font-size:13px;color:#475569;margin-bottom:6px">最近生成的赠送卡（<b style="color:#dc2626">当月月底作废</b>，11 月生成的卡 11-30 23:59 过期；点击链接直接复制）</div>
    <table id="viptokens"></table>
  </div>
  <div style="margin-top:8px;font-size:12px;color:#94a3b8">
    口径：额度/赠送状态均为<b>月度</b>（官方每月重置，跨月自动全量重探）；每张卡生成后先按 7 天预留记账，重探时以官方剩余为准自动对账；
    只调 page/info 和 token/create，<b>不会替任何人领会员</b>（accept 动作永远由领卡人自己完成）。
  </div>
</div>
<div style="text-align:center;color:#94a3b8;font-size:12px">
  赠送服务与号体检共用一个本机后台：关掉网页不影响，双击 号体检&amp;VIP赠送.bat 随时再开；重启电脑自动消失。
</div>
<script>
// ---------------- VIP 赠送池（独立页 /vip 专用；号体检脚本已内联在首页，两个页面互不依赖） ----------------
function esc(s){const d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML}
function chip(label,val,cls){return '<span class="badge '+(cls||'b-gray')+'" style="font-size:13px;padding:4px 12px">'+esc(label)+' <b>'+esc(val)+'</b></span>'}
function vipRender(d){
  const s=d.stats||{};
  document.getElementById('vipstats').innerHTML=
    chip('月份',s.month||'-','b-gray')+
    chip('已探测',s.probed+' / '+s.known,'b-gray')+
    chip('V2+ 黑胶号',s.v2,'b-green')+
    chip('本月从未赠送',s.never_gifted,'b-green')+
    chip('本月可送总额度',(s.avail_days||0)+' 天','b-green')+
    chip('可提取队列',s.queue,'b-yellow')+
    chip('池更新',s.updated_at||'-','b-gray');
  const j=d.job||{};
  const jb=document.getElementById('vipjob');
  if(j.running){jb.innerHTML='<span class="spin"></span>'+esc(j.kind==='take'?'发卡中':'探测中')+' '+j.done+'/'+j.total+' '+esc(j.cur||'');}
  else{jb.innerHTML=j.err?'<span style="color:#dc2626">❌ '+esc(j.err)+'</span>':(j.finished_at?('上次完成 '+esc(j.finished_at)+'（'+esc(j.kind)+'）'):'');}
  if((j.log||[]).length)jb.innerHTML+='<div style="max-height:110px;overflow:auto;font-size:12px;color:#94a3b8;margin-top:4px">'+j.log.slice(-8).map(esc).join('<br>')+'</div>';
  // 发卡结果
  const rs=d.results||[];
  document.getElementById('vipresults').innerHTML=rs.length?('<table><thead><tr><th>时间</th><th>赠送号</th><th>等级</th><th>领取链接（点一下全选复制）</th></tr></thead><tbody>'+
    rs.map(r=>r.error?('<tr><td colspan="4" style="color:#dc2626">'+esc(r.error)+'</td></tr>'):
      ('<tr><td>'+esc(r.created_at)+'</td><td>'+esc(r.donor_name)+'<br><span style="color:#94a3b8;font-size:12px">uid '+esc(r.donor_uid)+'</span></td>'+
       '<td>V'+esc(r.vip_level)+'</td><td><input readonly style="width:420px;border:0;background:#f8fafc;font-size:12px;padding:4px" value="'+esc(r.short_url||r.link)+'" onclick="this.select()"></td></tr>')).join('')+'</tbody></table>'):'';
  // 队列
  const q=d.queue||[];
  document.getElementById('vipqueue').innerHTML=q.length?('<thead><tr><th>#</th><th>uid</th><th>手机号</th><th>池</th><th>等级</th><th>剩余/预留</th><th>最近使用</th></tr></thead><tbody>'+
    q.map((r,i)=>('<tr><td>'+(i+1)+'</td><td>'+esc(r.uid)+'</td><td>'+esc(r.name)+'</td><td>'+esc(r.pool)+'</td><td>V'+esc(r.vip)+'</td><td>'+esc(r.left)+' / '+esc(r.resv)+'</td><td>'+esc(r.last)+'</td></tr>')).join('')+'</tbody>')
    :'<tbody><tr><td style="color:#94a3b8">（空——先跑一次探测）</td></tr></tbody>';
  // 卡历史
  const t=d.tokens||[];
  document.getElementById('viptokens').innerHTML=t.length?('<thead><tr><th>时间</th><th>赠送号</th><th>状态</th><th>链接</th></tr></thead><tbody>'+
    t.map(r=>('<tr><td>'+esc(r.created_at)+'</td><td>'+esc(r.donor_name)+'</td><td>'+esc(r.status||'')+'</td>'+
      '<td><input readonly style="width:380px;border:0;background:#f8fafc;font-size:12px;padding:4px" value="'+esc(r.short_url||r.link)+'" onclick="this.select()"></td></tr>')).join('')+'</tbody>')
    :'<tbody><tr><td style="color:#94a3b8">（还没有生成过）</td></tr></tbody>';
}
function vipPoll(){
  fetch('/api/vip_status').then(r=>r.json()).then(d=>{vipRender(d);
    if((d.job||{}).running)setTimeout(vipPoll,2000);}).catch(()=>{});
}
function vipProbe(full){
  fetch('/api/vip_probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({full:full})})
    .then(r=>r.json()).then(d=>{if(d.ok){vipPoll()}else alert(d.error||'失败')});
}
function vipTake(){
  const n=document.getElementById('vipn').value||1;
  fetch('/api/vip_take',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({n:+n})})
    .then(r=>r.json()).then(d=>{if(d.ok){vipPoll()}else alert(d.error||'失败')});
}
vipPoll();
setInterval(()=>{fetch('/api/vip_status').then(r=>r.json()).then(d=>{
  const j=d.job||{}; if(j.running&&!document.getElementById('vipjob').querySelector('.spin'))vipPoll();
  const s=document.getElementById('vipstats'); if(s&&!s.childElementCount)vipRender(d);
}).catch(()=>{})},5000);
</script></body></html>"""


# ---------------------------------------------------------------- HTTP 服务
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默，全走日志文件
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path in ("/vip", "/vip.html"):
            self._send(200, PAGE_VIP, "text/html; charset=utf-8")
        elif self.path == "/ping":
            self._send(200, '{"ok":true}')
        elif self.path == "/api/vip_status":
            st = vip_gift_pool.stats()
            q = [{"uid": uid, "name": a.get("name"), "pool": a.get("pool"),
                  "vip": a.get("vip_level"), "left": a.get("send_left"),
                  "resv": a.get("reserved"), "last": a.get("last_used") or "本月未用"}
                 for _f, _lu, _nl, uid, a in vip_gift_pool.eligible()[:30]]
            toks = vip_gift_pool.load_tokens()[:20]
            exp = ""
            if toks:
                exp = datetime.fromtimestamp(toks[0]["expire_ms"] / 1000, BJ).strftime("%Y-%m-%d %H:%M")
            self._send(200, json.dumps({"ok": True, "stats": st, "queue": q,
                                        "tokens": toks, "expire_show": exp,
                                        "job": {k: VIP_JOB[k] for k in
                                                ("running", "kind", "done", "total", "cur", "log", "err", "finished_at")},
                                        "results": VIP_JOB.get("results", [])[:10]},
                                       ensure_ascii=False))
        elif self.path == "/shutdown":
            self._send(200, '{"ok":true}')
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        elif self.path.startswith("/api/vip_sell"):
            self._vip_sell_handle(dict(p.split("=", 1) for p in self.path.split("?", 1)[-1].split("&") if "=" in p))
        else:
            self._send(404, '{"error":"not found"}')

    def _vip_sell_handle(self, params):
        """同步发卡接口（闲鱼自动发货 API 关键词用）：GET/POST ?pass=&n=1 → 当场返回链接。"""
        pw = (params.get("pass") or "").strip()
        if pw != (os.environ.get("ACC_SELL_PASS") or "vipcard2026"):
            self._send(403, json.dumps({"ok": False, "error": "口令错误"}, ensure_ascii=False))
            return
        try:
            cnt = max(1, min(3, int(params.get("n") or 1)))
        except (TypeError, ValueError):
            cnt = 1
        # 月底闸门：默认 0=不停发（用户 2026-11-24 拍板每天都发）；要启用设 ACC_SELL_MINDAYS=N
        mindays = int(os.environ.get("ACC_SELL_MINDAYS") or 0)
        ms_left = vip_gift_pool.month_end_ms() - int(time.time() * 1000)
        days_left = int(ms_left // 86400000) + (1 if ms_left % 86400000 else 0)
        if days_left < mindays:
            self._send(200, json.dumps({"ok": False, "error": "本月赠送卡将于 %d 天后过期，暂停发货（每月 1 日补货）" % days_left}, ensure_ascii=False))
            return
        if not VIP_LOCK.acquire(blocking=False):
            self._send(409, json.dumps({"ok": False, "error": "发卡任务正在跑，请稍后再试"}, ensure_ascii=False))
            return
        try:
            rs = vip_gift_pool.take(cnt)
        except Exception as e:
            self._send(500, json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))
            return
        finally:
            VIP_LOCK.release()
        cards, errs = [], []
        for r in rs:
            if r.get("error"):
                errs.append(r["error"])
            else:
                cards.append({
                    "short_url": r.get("short_url") or "",
                    "link": r["link"],
                    "donor_name": r.get("donor_name"),
                    "vip_level": r.get("vip_level"),
                    "expire": datetime.fromtimestamp(r["expire_ms"] / 1000, BJ).strftime("%Y-%m-%d %H:%M:%S"),
                })
        if cards:
            c = cards[0]
            reply = ("【网易云音乐黑胶VIP】领取链接：%s\n"
                     "⚠ 请在 %s 前用手机网易云打开领取，逾期作废；领取后会员立即到账 7 天。" %
                     (c["short_url"] or c["link"], c["expire"][:16]))
            self._send(200, json.dumps({"ok": True, "cards": cards, "errors": errs, "reply_text": reply}, ensure_ascii=False))
        else:
            self._send(502, json.dumps({"ok": False, "error": "；".join(errs) or "池内无可用额度号，请先跑探测"}, ensure_ascii=False))

    def do_POST(self):
        if self.path == "/api/vip_probe":
            try:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            except Exception:
                req = {}
            full = bool(req.get("full"))
            if not VIP_LOCK.acquire(blocking=False):
                self._send(409, json.dumps({"ok": False, "error": "VIP 任务正在跑，请等它完成"}, ensure_ascii=False))
                return
            VIP_JOB.update({"running": True, "kind": "full" if full else "incr",
                            "done": 0, "total": 0, "cur": "", "log": [], "err": "",
                            "finished_at": "", "results": []})
            _vip_log("开始%s探测" % ("全量（约100分钟）" if full else "增量（只探新增号）"))
            threading.Thread(target=_vip_probe_worker, args=(full,), daemon=True).start()
            self._send(200, '{"ok":true}')
        elif self.path == "/api/vip_take":
            try:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            except Exception:
                req = {}
            try:
                cnt = max(1, min(20, int(req.get("n") or 1)))
            except (TypeError, ValueError):
                cnt = 1
            if not VIP_LOCK.acquire(blocking=False):
                self._send(409, json.dumps({"ok": False, "error": "VIP 任务正在跑，请等它完成"}, ensure_ascii=False))
                return
            VIP_JOB.update({"running": True, "kind": "take", "done": 0, "total": cnt,
                            "cur": "", "log": [], "err": "", "finished_at": "", "results": []})
            _vip_log("开始生成 %d 张赠送链接（轮换取号→复核额度→token/create）" % cnt)
            threading.Thread(target=_vip_take_worker, args=(cnt,), daemon=True).start()
            self._send(200, '{"ok":true}')
        elif self.path.startswith("/api/vip_sell"):
            params = dict(p.split("=", 1) for p in self.path.split("?", 1)[-1].split("&") if "=" in p)
            try:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                for k in ("pass", "n"):
                    if body.get(k) is not None and str(body[k]).strip():
                        params[k] = str(body[k]).strip()
            except Exception:
                pass
            self._vip_sell_handle(params)
        elif self.path != "/api/run":
            self._send(404, '{"error":"not found"}')
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n).decode("utf-8"))
            key = str(req.get("key") or "").strip()
            if not key:
                self._send(400, json.dumps({"ok": False, "error": "手机号/uid 不能为空"}, ensure_ascii=False))
                return
            if not RUN_LOCK.acquire(blocking=False):
                self._send(409, json.dumps({"ok": False, "error": "已有一个体检在跑，请等它完成"}, ensure_ascii=False))
                return
            try:
                rep = acc_health.health(key, refresh=bool(req.get("refresh")),
                                        no_live=bool(req.get("no_live")),
                                        only_pool=(req.get("pool") or "").strip() or None,
                                        quiet=True)
                page = render_html(rep, key)
                ts = datetime.now(BJ).strftime("%Y%m%d_%H%M")
                self._send(200, json.dumps({"ok": True, "html": page, "ts": ts}, ensure_ascii=False))
            except SystemExit as e:
                self._send(500, json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
            except Exception as e:
                traceback.print_exc(file=_logf)
                _logf.flush()
                self._send(500, json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))
            finally:
                RUN_LOCK.release()
        except Exception as e:
            self._send(500, json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))


def _open_browser():
    """pythonw 下最可靠的开浏览器方式：ShellExecute（不吃代理、不吃浏览器探测）。"""
    try:
        os.startfile(URL)  # noqa: S606
    except Exception:
        try:
            webbrowser.open(URL)
        except Exception:
            pass


def _server_alive():
    """HTTP 探活（不能只测 TCP connect）。
    2026-11-20 实锤：本机透明代理会拦截一切 loopback 连接，端口没人听时 connect 也能
    「成功」——裸 socket 探活永远误判已有实例，新服务起不来（用户双击 bat 没反应的真凶）。
    改用 http.client 直连（不走环境变量代理），拿到我们自己的 /ping 响应才算活着。"""
    import http.client
    try:
        c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=2)
        c.request("GET", "/ping")
        body = c.getresponse().read()
        c.close()
        return b'"ok":true' in body
    except Exception:
        return False


def main():
    # 已有实例在跑 → 直接开浏览器走人，不起第二个服务
    if _server_alive():
        print(f"[web] 已有实例 {URL}，直接打开浏览器")
        if os.environ.get("ACC_HEALTH_NOBROWSER") != "1":
            _open_browser()
        return
    try:
        srv = ThreadingHTTPServer((os.environ.get("ACC_HEALTH_BIND") or "127.0.0.1", PORT), Handler)
    except OSError:
        # 端口被占但探活没过（极端竞态/半死实例）：照样把浏览器打开，别让用户点了没反应
        print(f"[web] {PORT} 端口被占但探活失败，兜底打开浏览器")
        _open_browser()
        return
    srv.daemon_threads = True
    print(f"[web] 号体检网页版已启动：{URL}  (pid={os.getpid()})")
    if os.environ.get("ACC_HEALTH_NOBROWSER") != "1":
        threading.Timer(0.5, _open_browser).start()
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
        print(f"[web] 服务已退出 {datetime.now(BJ):%m-%d %H:%M}")


if __name__ == "__main__":
    main()

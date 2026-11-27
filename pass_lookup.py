# -*- coding: utf-8 -*-
"""读「口令总表」取机器口令的唯一入口（随仓库分发版，2026-11-27）。

为什么放进仓库：本文件**不含任何口令**，只是一段查表逻辑。以前它只存在于本机
工作区的 tmp/ 下（不入库），换台机器跑号体检时 `from pass_lookup import lookup`
直接 ImportError → 【7】里那行 250 提醒永远显示「查询失败」。

口令表本身仍然**绝不入库**（.gitignore 的 `*口令*` 拦着）。查找顺序：

  1. 环境变量 PASS_TABLE            —— 直接指定口令表路径（最省事）
  2. 仓库目录 / 工作区根下的 控制台口令备份_*.txt（取最新一份）
  3. 环境变量 ASSIGN_PASS 等单键值   —— 表不存在或表里没这个键时兜底
     （acc_health.py 里反过来：环境变量优先，方便临时覆盖）

用法:
    python pass_lookup.py ASSIGN_PASS            # 取一个键
    python pass_lookup.py ASSIGN_PASS PEER_KEY   # 取多个键

⚠ 2026-11-24 实锤坑：口令总表里 ASSIGN_PASS 有两种排版——
   表格行「ASSIGN_PASS    JOIO...（两群同值）」（无等号、多空格分隔）
   Secret 行「ASSIGN_PASS = JOIO...」。
   严格正则 ASSIGN_PASS[=:：] 只匹配到后者、前者直接落空 → 取到空口令
   → 线上一律回 403「口令错误」，全是假警报。
   所以这里只认「行首键名 + 容错分隔」，取行内 ASCII 词元（≥8 位），
   中文注释（两群同值/别删…）天然被滤掉。
"""
import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)

# 会去这些目录里找 控制台口令备份_*.txt（按顺序，第一个有文件的为准）
SEARCH_DIRS = [
    HERE,                                   # cron-relay/
    PROJ,                                   # 工作区根
    os.path.join(PROJ, "cron-relay"),       # 工作区根/cron-relay
    os.getcwd(),
]


def table_candidates():
    """返回候选口令表路径列表（新的在前）。"""
    out = []
    envp = (os.environ.get("PASS_TABLE") or "").strip()
    if envp:
        out.extend(sorted(glob.glob(envp), reverse=True))
        if os.path.isfile(envp):
            out.insert(0, envp)
    for d in SEARCH_DIRS:
        try:
            hits = glob.glob(os.path.join(d, "控制台口令备份_*.txt"))
        except Exception:
            hits = []
        out.extend(sorted(hits, reverse=True))   # 取最新一份
    seen, uniq = set(), []
    for p in out:
        p = os.path.abspath(p)
        if p not in seen and os.path.isfile(p):
            seen.add(p)
            uniq.append(p)
    return uniq


def load_table():
    """返回 (路径, 全文)。找不到表时抛 SystemExit（调用方一般会兜住）。"""
    files = table_candidates()
    if not files:
        raise SystemExit("找不到 口令总表（可用环境变量 PASS_TABLE 指定，或 直接设 ASSIGN_PASS）")
    path = files[0]
    with io.open(path, encoding="utf-8", errors="ignore") as f:
        return path, f.read()


def _from_env(key):
    """没有口令表时的兜底：环境变量直接给值（只支持同名键）。"""
    v = (os.environ.get(key) or "").strip()
    return [v] if v else []


def lookup(key):
    """取一个键的所有候选值（去重保序）。表不存在/没命中 → 返回 []。"""
    try:
        _, text = load_table()
    except SystemExit:
        return _from_env(key)
    vals = []
    for ln in text.splitlines():
        # 只认「行首键名」，避免误抓 ④⑤/续行里的口令字样
        m = re.match(r"^\s*" + re.escape(key) + r"\s*(?:[=:：]\s*)?(\S.*)$", ln)
        if not m:
            continue
        vals.extend(re.findall(r"[A-Za-z0-9_\-]{8,}", m.group(1)))
    if not vals:
        return _from_env(key)
    seen = set()
    out = []
    for v in vals:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python pass_lookup.py <KEY> [KEY2 ...]  例: python pass_lookup.py ASSIGN_PASS")
        sys.exit(1)
    cands = table_candidates()
    print("来源:", cands[0] if cands else "(无口令表，仅环境变量兜底)")
    for k in sys.argv[1:]:
        vals = lookup(k)
        print(k + ": " + (" / ".join(vals) if vals else "(未找到)"))

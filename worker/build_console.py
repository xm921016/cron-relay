# -*- coding: utf-8 -*-
"""build_console.py —— 把 console.html 注入 worker.js 的 CONSOLE_HTML 模板位。
2026-11-15 方案④起，CONSOLE_HTML 源文件外置为 worker/console.html：
  平时改 console.html（IDE 高亮、无模板字符串约束），部署前跑本脚本拼回 worker.js。
安全护栏：
  1) console.html 含反引号或 ${ 直接拒绝注入（模板字符串铁律）；
  2) 注入后用最近的 worker.js.bak_* 备份做「模板块外逐字节一致」校验 ——
     头尾任何一行被意外改动都会立刻报错停止（防并行会话覆写/误改）。
用法：在本目录（cron-relay/worker）下执行  python build_console.py
"""
import io, os, glob, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'worker.js')
HTML = os.path.join(HERE, 'console.html')
MARK = 'const CONSOLE_HTML = `'

def read(p):
    return io.open(p, 'r', encoding='utf-8', newline='').read()

src = read(SRC)
html = read(HTML)

# 护栏 1：模板字符串铁律
if '`' in html:
    raise SystemExit('!! console.html 含反引号，会提前终止模板字符串 —— 先去掉再构建')
if '${' in html:
    raise SystemExit('!! console.html 含 ${ ，CONSOLE_HTML 模板禁用 —— 先去掉再构建')

i = src.find(MARK)
if i < 0:
    raise SystemExit('!! worker.js 里找不到 CONSOLE_HTML 起始标记')
j = src.find('`;', i + len(MARK))
if j < 0:
    raise SystemExit('!! worker.js 里找不到 CONSOLE_HTML 结束标记（`;）')
if src.find(MARK, i + 10) >= 0:
    raise SystemExit('!! 出现第二个 CONSOLE_HTML 标记，文件结构异常，停止')

out = src[:i + len(MARK)] + html + src[j:]

# 护栏 2：与最近备份比对模板块外内容
baks = sorted(glob.glob(os.path.join(HERE, 'worker.js.bak_*')))
checked = False
if baks:
    bak = read(baks[-1])
    bi = bak.find(MARK)
    bj = bak.find('`;', bi + len(MARK)) if bi >= 0 else -1
    if bi >= 0 and bj >= 0:
        if src[:i] == bak[:bi] and src[j:] == bak[bj:]:
            print('[OK] 模板块外与备份 %s 逐字节一致' % os.path.basename(baks[-1]))
            checked = True
        else:
            raise SystemExit('!! 模板块外的代码与最近备份不一致 —— 有并行改动或误改，停止注入。'
                             '先人工 diff 确认后再处理。')
if not checked:
    print('[WARN] 没有可用的 worker.js.bak_* 备份可比对，跳过块外校验（不推荐）')

io.open(SRC, 'w', encoding='utf-8', newline='').write(out)
old_len = j - i - len(MARK) - 2
print('[OK] 注入完成：CONSOLE_HTML %d -> %d 字符，worker.js 共 %d 字符'
      % (old_len, len(html), len(out)))

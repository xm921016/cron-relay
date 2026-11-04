#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D1 加密备份 → 蓝奏云「D1备份」文件夹（每日一份，滚动保留 N 份）。

===============================================================================
这个脚本为什么长这样：2026-11-04 逐条实测出来的蓝奏云接口真相，别重复踩坑
===============================================================================
1) 上传端点必须是 pc.woozooo.com/html5up.php，字段 task=1 + vie=2 + ve=2。
   老域名 up.woozooo.com 一律返回 {"zt":0,"info":0,"text":0} 静默失败 —— 很容易
   误判成「文件名不允许」或「cookie 失效」，实际只是打错了域名。

2) html5up.php 完全不认 folder_id。query 传、body 传、referer 带、先列目录让它
   写 session —— 全都试过，文件一律落根目录。所以只能：先上传 → 再用
   task=20 + file_id(单值) + folder_id 把它移进目标文件夹。

3) 列文件：task=5 + folder_id + pg + vei。
   vei 是**页面级一次性签名**，每次都要现抓
   mydisk.php?item=files&action=index&folder_id=<id> 里的 'vei':'...'，
   缓存/复用必定失败（返回 zt:2 + 空 text，看起来像「文件夹是空的」）。
   另注：task=47 只列子文件夹，不列文件；task=18 已被封（HTTP 405）。

4) 删除：task=6 + file_id(单值)。

5) ⚠⚠ 移动和删除如果把 file_id 写成 file_id[]（数组形式），接口照样回
   「变更成功」/「已删除」，但**什么都没发生**。必须传单值，且事后回读列表校验。
   这是本脚本里所有「回读确认」的来源。

6) 取回（下载）走的是 developer*.lanrar.com 另一个域名，前置阿里云 ESA WAF：
   acw_sc__v2 JS 挑战能过（用 node 执行混淆脚本），但过了之后还有一层
   「系统发现您的网络异常，需要验证后下载文件」的人机验证，脚本无法通过。
   ⇒ 本脚本只负责「存」。取回由人工在网页点（文件夹密码见文档）。

环境变量：
    LANZOU_COOKIE   必填。整串 cookie（ylogin=...; phpdisk_info=...; uag=...）
    LANZOU_FOLDER   目标文件夹 id，默认 14198686（「D1备份」）
    LANZOU_UID      默认 1537461
    BACKUP_DIR      本地待上传目录，默认 backup_daily
    LANZOU_KEEP     保留份数，默认 30
    LANZOU_DRY=1    预演，不实际写入
"""

import io
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = "https://pc.woozooo.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

COOKIE = (os.environ.get("LANZOU_COOKIE") or "").strip().strip("'").strip('"')
FOLDER = (os.environ.get("LANZOU_FOLDER") or "14198686").strip()
UID = (os.environ.get("LANZOU_UID") or "1537461").strip()
BACKUP_DIR = (os.environ.get("BACKUP_DIR") or "backup_daily").strip()
KEEP = int(os.environ.get("LANZOU_KEEP") or "30")
DRY = os.environ.get("LANZOU_DRY") == "1"


# --------------------------------------------------------------------------- #
# HTTP 基础设施
# --------------------------------------------------------------------------- #
def _read(r, tries=20):
    buf = bytearray()
    for _ in range(tries):
        chunk = r.read(65536)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def http(url, data=None, raw=None, ctype=None, retries=3):
    """GET / POST(表单) / POST(multipart 原始体)。断流自动重试。"""
    last = None
    for i in range(retries):
        headers = {"User-Agent": UA, "Cookie": COOKIE}
        if raw is not None:
            headers["Content-Type"] = ctype
            body = raw
        elif data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["X-Requested-With"] = "XMLHttpRequest"
            headers["Referer"] = HOST + "/mydisk.php"
            body = urllib.parse.urlencode(data, doseq=True).encode()
        else:
            body = None
        try:
            req = urllib.request.Request(url, data=body, headers=headers)
            with urllib.request.urlopen(req, timeout=180) as r:
                return _read(r).decode("utf-8", "replace")
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            last = "%s: %s" % (type(e).__name__, e)
            if i < retries - 1:
                print("  ! 第 %d 次请求失败（%s），重试" % (i + 1, last))
                time.sleep(3 * (i + 1))
    raise RuntimeError("请求失败 %s：%s" % (url, last))


def api(data):
    """doupload.php —— 蓝奏云的「后台」接口，全部 task 都走这里。"""
    txt = http(HOST + "/doupload.php?uid=" + UID, data=data)
    try:
        return json.loads(txt)
    except ValueError:
        raise RuntimeError("非 JSON 响应（多半是 cookie 失效被踢回登录页）：" + txt[:200])


# --------------------------------------------------------------------------- #
# 核心动作（每个都带回读校验）
# --------------------------------------------------------------------------- #
def check_login():
    """cookie 过期是这套备份最可能的无声故障，必须先探活再干活。"""
    if not COOKIE:
        raise SystemExit("FAIL: 没配 LANZOU_COOKIE")
    html = http(HOST + "/mydisk.php?item=files&action=index")
    if "ylogin" not in COOKIE:
        raise SystemExit("FAIL: LANZOU_COOKIE 里没有 ylogin，不是有效登录态")
    # 掉登录会跳登录页；正常页面上会有上传器与文件夹变量
    if "html5uploader" not in html and "folder_id" not in html:
        raise SystemExit("FAIL: cookie 已失效（页面不含上传器），请重新抓 cookie 更新 Secret")
    return True


def _vei(folder):
    """页面级一次性签名，每次列目录都要现抓。"""
    html = http("%s/mydisk.php?item=files&action=index&folder_id=%s" % (HOST, folder))
    m = re.search(r"'vei'\s*:\s*'([^']+)'", html)
    if not m:
        raise RuntimeError("抓不到 vei（页面结构变了？）")
    return m.group(1)


def list_files(folder=None):
    """返回 [{id, name, size}]。空文件夹是 zt:2 + text:[]（不是错误）。"""
    folder = folder or FOLDER
    d = api({"task": "5", "folder_id": folder, "pg": "1", "vei": _vei(folder)})
    if d.get("zt") not in (1, 2):
        raise RuntimeError("列目录失败：%s" % json.dumps(d, ensure_ascii=False)[:200])
    out = []
    for it in d.get("text") or []:
        if isinstance(it, dict) and it.get("id"):
            out.append({"id": str(it["id"]),
                        "name": it.get("name_all") or it.get("name") or "",
                        "size": it.get("size") or "",
                        "f_id": it.get("f_id") or ""})
    return out


def upload(name, blob):
    """上传到根目录（html5up.php 不认 folder_id，这是唯一可行路径）。"""
    b = "----WebKitFormBoundary" + "".join(
        random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
    o = io.BytesIO()
    for k, v in (("task", "1"), ("vie", "2"), ("ve", "2")):
        o.write(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                 % (b, k, v)).encode())
    o.write(("--%s\r\nContent-Disposition: form-data; name=\"upload_file\"; "
             "filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n"
             % (b, name)).encode())
    o.write(blob)
    o.write(("\r\n--%s--\r\n" % b).encode())

    txt = http(HOST + "/html5up.php", raw=o.getvalue(),
               ctype="multipart/form-data; boundary=" + b)
    try:
        d = json.loads(txt)
    except ValueError:
        raise RuntimeError("上传返回非 JSON：" + txt[:200])
    if d.get("zt") != 1:
        raise RuntimeError("上传失败：%s" % json.dumps(d, ensure_ascii=False)[:200])
    it = (d.get("text") or [{}])[0]
    return str(it.get("id") or ""), it.get("f_id") or ""


def move(file_id, folder=None):
    """task=20 + file_id 单值。用 file_id[] 会静默失败（回「变更成功」但没动）。"""
    folder = folder or FOLDER
    d = api({"task": "20", "file_id": file_id, "folder_id": folder})
    if d.get("zt") != 1:
        raise RuntimeError("移动失败：%s" % json.dumps(d, ensure_ascii=False)[:200])


def delete(file_id):
    """task=6 + file_id 单值。同样不能用 file_id[]。"""
    d = api({"task": "6", "file_id": file_id})
    if d.get("zt") != 1:
        raise RuntimeError("删除失败：%s" % json.dumps(d, ensure_ascii=False)[:200])


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main():
    print("[lanzou] 目标文件夹 id=%s，保留 %d 份，%s"
          % (FOLDER, KEEP, "预演模式" if DRY else "实际写入"))

    check_login()
    local = []
    if os.path.isdir(BACKUP_DIR):
        for fn in sorted(os.listdir(BACKUP_DIR)):
            if fn.endswith(".enc"):
                local.append(fn)
    if not local:
        print("[lanzou] %s 里没有 .enc，跳过" % BACKUP_DIR)
        return 0
    print("[lanzou] 本地待上传 %d 份：%s" % (len(local), ", ".join(local)))

    existing = list_files(FOLDER)
    print("[lanzou] 云端现有 %d 份" % len(existing))

    # ---- 上传（同名先删，保证每天只有一份、可重跑） ----
    for fn in local:
        path = os.path.join(BACKUP_DIR, fn)
        blob = open(path, "rb").read()
        same = [f for f in existing if f["name"] == fn]
        if same:
            if DRY:
                print("[lanzou] 预演：%s 已存在（id=%s），会先删再传" % (fn, same[0]["id"]))
                continue
            for f in same:
                delete(f["id"])
                print("[lanzou] 已删旧同名 %s (id=%s)" % (fn, f["id"]))
            existing = [f for f in existing if f["name"] != fn]
        if DRY:
            print("[lanzou] 预演：会上传 %s (%d B)" % (fn, len(blob)))
            continue

        fid, f_id = upload(fn, blob)
        if not fid:
            raise RuntimeError("上传 %s 没拿到文件 id" % fn)
        print("[lanzou] 已上传 %s → id=%s f_id=%s (%d B)" % (fn, fid, f_id, len(blob)))
        move(fid)
        # 回读校验：移动是静默失败重灾区，必须确认它真在目标文件夹里
        now = list_files(FOLDER)
        got = [f for f in now if f["id"] == fid]
        if not got:
            raise RuntimeError("移动后回读不到 %s（id=%s），可能留在了根目录" % (fn, fid))
        print("[lanzou] 已移入「D1备份」并回读确认：%s  %s  f_id=%s"
              % (fn, got[0]["size"], got[0].get("f_id") or f_id))
        existing = now

    # ---- 滚动保留 ----
    now = list_files(FOLDER)
    named = [f for f in now if re.match(r"^d1-\d{4}-\d{2}-\d{2}", f["name"])]
    named.sort(key=lambda x: x["name"], reverse=True)     # 文件名带日期，倒序即新旧
    other = [f for f in now if f not in named]
    if other:
        print("[lanzou] 文件夹里还有 %d 个非本体系文件，不动它们：%s"
              % (len(other), ", ".join(f["name"] for f in other[:5])))
    drop = named[KEEP:]
    print("[lanzou] 滚动：共 %d 份，保留 %d 份，待删 %d 份"
          % (len(named), min(len(named), KEEP), len(drop)))
    for f in drop:
        if DRY:
            print("[lanzou] 预演：会删 %s (id=%s)" % (f["name"], f["id"]))
            continue
        delete(f["id"])
        print("[lanzou] 已删过期 %s (id=%s)" % (f["name"], f["id"]))

    final = list_files(FOLDER)
    print("[lanzou] 完成。云端共 %d 份：" % len(final))
    for f in sorted(final, key=lambda x: x["name"], reverse=True):
        print("    %-34s %-8s id=%-12s f_id=%s"
              % (f["name"], f["size"], f["id"], f.get("f_id") or "-"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as e:
        print("FAIL: %s: %s" % (type(e).__name__, e))
        raise SystemExit(1)

# -*- coding: utf-8 -*-
"""从私库 vault 取回某一天的 D1 备份（2026-11-04 新增）。

为什么需要
----------
每日备份现在只存在于 5 个账号的 private vault 仓（hub 仓的 backup/ 目录已废弃）。
d1-restore.yml 原来只认本地 backup/$FILE，取消每周备份后那个目录永远是空的 ——
恢复通道会变成摆设。这个脚本让恢复流程直接从「还活着的那个账号」把文件取回来。

用法
----
  python d1_vault_pull.py d1-2026-11-04.json.gz.enc             # 下载到当前目录
  python d1_vault_pull.py d1-2026-11-04.json.gz.enc --out backup
  python d1_vault_pull.py --list                                # 看每个账号有哪些份

行为
----
· 按 VAULT_TOKENS 顺序逐个尝试，第一个成功即停止（不重复下载）。
· 下载后打印大小与 sha256，便于与另一账号的同一份比对是否一致。
· 全部失败则非零退出，让 workflow 变红。
"""
import base64
import hashlib
import http.client
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
UA = "d1-vault-pull/1.0"
REPO = (os.environ.get("VAULT_REPO") or "vault").strip()
BRANCH = (os.environ.get("VAULT_BRANCH") or "main").strip()
SUBDIR = "backup"


def _read_all(r):
    """分块读完响应体：单次 read() 在网络抖动时会抛 IncompleteRead。"""
    buf = bytearray()
    while True:
        chunk = r.read(65536)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def gh(tok, url, accept="application/vnd.github+json"):
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + tok, "User-Agent": UA, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            body = _read_all(r)
            return r.status, (json.loads(body.decode() or "{}") if body else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:200]}
    except http.client.IncompleteRead as e:
        return 0, {"error": f"IncompleteRead {e}"}


def tree_index(tok, owner):
    """只取 git tree 的元数据（path → size/sha），响应几百字节，不会断流。

    不能用 contents API 拿元数据：即使 Accept 只要 json，GitHub 仍会把整个文件
    base64 塞进 content 字段（460KB 文件 → 620KB 响应），实测必断。
    """
    s, d = gh(tok, f"{API}/repos/{owner}/{REPO}/git/trees/{BRANCH}?recursive=1")
    if s != 200 or not isinstance(d, dict):
        return {}
    return {x["path"]: x for x in d.get("tree", []) if x.get("type") == "blob"}


def gh_raw(tok, url, expect_size=None, tries=3):
    """流式下载原始字节（raw media type，比 JSON+base64 少 33% 体积）。"""
    last = None
    for i in range(tries):
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + tok, "User-Agent": UA,
            "Accept": "application/vnd.github.raw"})
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                blob = _read_all(r)
            if expect_size is not None and len(blob) != expect_size:
                last = f"大小不符：拿到 {len(blob)}B，声明 {expect_size}B"
                print(f"  ! 第 {i+1} 次：{last}，重试")
                continue
            return blob
        except (urllib.error.HTTPError, http.client.IncompleteRead, OSError) as e:
            last = f"{type(e).__name__}: {e}"
            print(f"  ! 第 {i+1} 次下载失败（{last}），重试")
    raise RuntimeError(f"下载失败：{last}")


def git_blob_sha1(blob):
    """Git 的 blob sha1，可与 tree 里的 sha 直接比对。"""
    return hashlib.sha1(b"blob %d\0" % len(blob) + blob).hexdigest()


def targets():
    raw = os.environ.get("VAULT_TOKENS") or ""
    out = []
    for line in raw.replace("\r", "").split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = line.split()
        if len(p) >= 2:
            out.append((p[0], p[1]))
    if not out:
        raise SystemExit("缺 VAULT_TOKENS（每行 `<owner> <token>`）")
    return out


def do_list(ts):
    for owner, tok in ts:
        s, d = gh(tok, f"{API}/repos/{owner}/{REPO}/contents/{SUBDIR}?ref={BRANCH}")
        names = sorted(x["name"] for x in d) if s == 200 and isinstance(d, list) else []
        print(f"{owner}/{REPO}: {len(names)} 份"
              + (f"（{names[0]} … {names[-1]}）" if names else f"  [{s}]"))
    return 0


def main():
    args = [a for a in sys.argv[1:]]
    if not args:
        raise SystemExit(__doc__)
    if args[0] == "--list":
        return do_list(targets())
    name = args[0]
    out_dir = "."
    if "--out" in args:
        out_dir = args[args.index("--out") + 1]
    os.makedirs(out_dir, exist_ok=True)
    dest = os.path.join(out_dir, name)

    for owner, tok in targets():
        idx = tree_index(tok, owner)
        ent = idx.get(f"{SUBDIR}/{name}")
        if not ent:
            print(f"  {owner}: 没有 {name}")
            continue
        url = f"{API}/repos/{owner}/{REPO}/contents/{SUBDIR}/{name}?ref={BRANCH}"
        try:
            blob = gh_raw(tok, url, expect_size=ent.get("size"))
        except Exception as e:
            print(f"  {owner}: {e}")
            continue
        if git_blob_sha1(blob) != ent["sha"]:
            print(f"  {owner}: sha1 校验失败，换下一个账号")
            continue
        open(dest, "wb").write(blob)
        print(f"[pull] 已从 {owner}/{REPO} 取回 {name}：{len(blob)/1024:.0f}KB "
              f"git-sha1 校验通过 {ent['sha'][:10]}")
        print(f"[pull] 落盘 → {dest}")
        return 0
    raise SystemExit(f"5 个账号都没取到 {name}")


if __name__ == "__main__":
    sys.exit(main())

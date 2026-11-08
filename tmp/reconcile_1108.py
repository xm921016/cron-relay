# -*- coding: utf-8 -*-
"""2026-11-08 额度事故的收尾脚本 —— 明早 08:00 之后跑一次即可。

背景：11-08 当天 D1 读额度被打满（239%）。当晚为了不停业，浏览器登记链路改走 KV，
      但超额状态下 `UPSERT`（ON CONFLICT 需要读）时好时坏 —— 所以当晚登记成功的号，
      可能只落在 KV 权威键（entry:u<uid>），D1 影子库里没有这一行。
      影子库缺行的后果：relay 的分配是从 D1 的 accounts / runs 读的，缺行 = 这个号明天不刷。

本脚本做三件事：
  1. 对比 KV 号池快照 `pool:hz` 与 D1 `accounts`，把 D1 缺的号补写回去（d1Upsert 同口径）。
  2. 清理测试残留（`ledger` 里 pool='zztest' 的那行，当晚 DELETE 被 7500 拒了）。
  3. 打印今天的额度用量，确认已归零。

用法（**必须在北京 08:00 / UTC 00:00 之后**）：
    python tmp\\reconcile_1108.py            # 只看差异，不动数据
    python tmp\\reconcile_1108.py --apply    # 真的补写 + 清理
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

ACC = 'c60450bfb7f2c2becfd744ba2508a4f2'
DB = '54f742fc-5f56-4723-a7a0-a832953d38c7'
NS = '12aac9fba6a04b8fb19ee88ffac7fc7a'
TOK = os.environ.get('CF_TOKEN') or os.environ.get('CF_API_TOKEN')
if not TOK:
    raise SystemExit('缺少凭据：请设置环境变量 CF_API_TOKEN（GitHub Actions 里走 secrets）')
POOL = 'hz'
D1_COLS = ('uid,name,ck,song,added,email,phone,grp,exp,agent,plan')


def api(url, data=None, method='GET'):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method,
                                headers={'Authorization': 'Bearer ' + TOK,
                                         'Content-Type': 'application/json',
                                         'User-Agent': 'Mozilla/5.0'})
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return json.load(op.open(req, timeout=120))


def sql(q):
    try:
        r = api('https://api.cloudflare.com/client/v4/accounts/%s/d1/database/%s/query' % (ACC, DB),
                {'sql': q}, 'POST')['result'][0]
        return r
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', 'ignore')
        if '7500' in body:
            print('\n!! D1 读额度还没重置（code 7500）。请在北京 08:00 / UTC 00:00 之后再跑本脚本。\n')
            raise SystemExit(2)
        raise


def kv_get(key):
    req = urllib.request.Request(
        'https://api.cloudflare.com/client/v4/accounts/%s/storage/kv/namespaces/%s/values/%s'
        % (ACC, NS, urllib.parse.quote(key, safe='')),
        headers={'Authorization': 'Bearer ' + TOK})
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        return op.open(req, timeout=60).read().decode('utf-8', 'ignore')
    except Exception as e:
        return 'ERR:' + str(e)


def main():
    apply = '--apply' in sys.argv

    # ---- 1. KV 权威池 vs D1 ----
    raw = kv_get('pool:' + POOL)
    if raw.startswith('ERR:'):
        print('读 KV 快照失败:', raw)
        return
    kv_pool = json.loads(raw)
    print('KV 号池快照 %d 条' % len(kv_pool))

    r = sql("SELECT uid,name FROM accounts WHERE pool='%s'" % POOL)
    if not r.get('results') and r.get('meta', {}).get('changes') is None:
        pass
    rows = r.get('results') or []
    print('D1 accounts %d 条' % len(rows))
    d1_uids = set(str(x.get('uid')) for x in rows if x.get('uid'))
    d1_names = set(str(x.get('name')) for x in rows if x.get('name'))

    missing = []
    for e in kv_pool:
        uid = e.get('uid')
        name = e.get('name')
        hit = (uid is not None and str(uid) in d1_uids) or (name and str(name) in d1_names)
        if not hit:
            missing.append(e)

    print('D1 缺失（只在 KV 里）: %d 条' % len(missing))
    for e in missing:
        print('   uid=%s name=%s song=%s added=%s' %
              (e.get('uid'), e.get('name'), e.get('song'), (e.get('added') or '')[:10]))

    if missing and apply:
        ok = 0
        for e in missing:
            vals = [POOL] + [e.get(k) for k in D1_COLS.split(',')]
            q = ('INSERT INTO accounts (pool,%s) VALUES (%s) ON CONFLICT(pool,uid) DO UPDATE SET '
                 'name=excluded.name, ck=excluded.ck, song=excluded.song, added=excluded.added, '
                 'email=excluded.email, phone=excluded.phone, grp=excluded.grp, exp=excluded.exp, '
                 'agent=excluded.agent, plan=excluded.plan'
                 % (D1_COLS, ','.join(['?'] * (len(D1_COLS.split(',')) + 1))))
            body = json.dumps({'sql': q, 'params': vals}).encode()
            req = urllib.request.Request(
                'https://api.cloudflare.com/client/v4/accounts/%s/d1/database/%s/query' % (ACC, DB),
                data=body, method='POST',
                headers={'Authorization': 'Bearer ' + TOK,
                         'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'})
            try:
                api_req = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                    req, timeout=90)
                j = json.load(api_req)
                if j.get('success'):
                    ok += 1
                else:
                    print('   补写失败', e.get('uid'), str(j)[:120])
            except Exception as ex:
                print('   补写异常', e.get('uid'), str(ex)[:120])
        print('补写完成 %d / %d' % (ok, len(missing)))

    # ---- 2. 清理测试残留 ----
    r = sql("SELECT COUNT(*) c FROM ledger WHERE pool='zztest'")
    n = (r.get('results') or [{}])[0].get('c', 0)
    print('测试残留 ledger(pool=zztest): %d 行' % n)
    if n and apply:
        print('   删除:', sql("DELETE FROM ledger WHERE pool='zztest'").get('meta', {}).get('changes'))
        print('   复查:', sql("SELECT COUNT(*) c FROM ledger WHERE pool='zztest'").get('results'))

    if not apply:
        print('\n（当前是 dry-run，加 --apply 才会真的补写/删除）')


if __name__ == '__main__':
    main()

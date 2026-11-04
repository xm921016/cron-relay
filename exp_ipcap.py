#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一次性实验（2026-11-04）：同一出口 IP 上的「同 IP 号数 → 计入率」曲线。

设计
----
一个 workflow job = 一台 GHA VM = 一个出口 IP。job 内用 N 个不同账号，
各串行播同一批 5 首歌（每首播 55%~70% 时长，与正式 run.py 完全同一口径）。
次日读这 25 首 + 5 首对照的 rpc30 涨幅，差分即为该臂同 IP 的有效剂量。

臂与片范围（各臂互不重叠，避免同一账号被两臂重复使用）
------------------------------------------------------
A6   N=6   片 0-1     (12 个候选里取 6)
B12  N=12  片 2-4     (18 个候选里取 12)
C24  N=24  片 5-9     (30 个候选里取 24)
D48  N=48  片 10-18   (54 个候选里取 48)

账号与 CK 全部经 /api/assign 现取（与正式 relay 同一条通路），
不落盘、不进仓库、不出现在 workflow 日志里。

环境变量
--------
WORKER_URL, ASSIGN_PASS        同 run.py
EXP_ARM, EXP_N                 本臂名称与号数
EXP_JOB_LO, EXP_JOB_HI         assign 片号范围（含两端）
EXP_NS                         总片数
EXP_SONGS                      "songid:dur:owneruid,..."（owner = 歌主，歌主不听自己的歌）
"""
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import run as R


def parse_songs(spec):
    out = []
    for part in (spec or '').split(','):
        part = part.strip()
        if not part:
            continue
        bits = part.split(':')
        sid = bits[0].strip()
        dur = int(bits[1]) if len(bits) > 1 and bits[1].strip() else 240
        owner = bits[2].strip() if len(bits) > 2 else ''
        out.append((sid, dur, owner))
    return out


def play_seconds(dur):
    """与 run.py:792-794 完全一致：0.55~0.70 比例，保底 min(35, 歌长-3)。"""
    t = int(dur * random.uniform(0.55, 0.70))
    return max(t, min(R.MIN_PLAY_SECONDS, dur - 3))


def collect_accounts(ns, job_lo, job_hi):
    seen, accs = set(), []
    by_slice = {}
    for j in range(job_lo, job_hi + 1):
        got = R.load_assign(ns, j)
        if not got:
            print('[assign] 片 %d 取号失败' % j, flush=True)
            continue
        by_slice[j] = len(got)
        for a in got:
            uid = str(a.get('uid') or '')
            if not uid or uid in seen:
                continue
            if a.get('pub'):
                continue          # 公益号：只帮别人听，不进实验
            if not a.get('ck'):
                continue
            seen.add(uid)
            accs.append(a)
    print('[assign] 片 %s 各片号数=%s  去重后候选 %d' % (
        '%d-%d' % (job_lo, job_hi), by_slice, len(accs)), flush=True)
    return accs


def run_arm(arm, accs, songs, n_target):
    owners = {o for _s, _d, o in songs if o}
    picked = [a for a in accs if str(a.get('uid')) not in owners][:n_target]
    # 号自己的歌不在目标歌里（防御性检查：万一歌主列表漏了）
    song_ids = {s for s, _d, _o in songs}
    picked = [a for a in picked if str(a.get('song') or '') not in song_ids][:n_target]
    print('[%s] 实际投入 %d 个号（目标 %d）' % (arm, len(picked), n_target), flush=True)
    if not picked:
        return 0, 0, []

    results = []
    lock_n = {'ok': 0, 'fail': 0}

    def one_account(a):
        uid = str(a.get('uid'))
        c = R.Client(a['ck'])
        ok_cnt = 0
        for sid, dur, _o in songs:
            t = play_seconds(dur)
            try:
                ok = c.scrobble(sid, t)
            except Exception as e:
                ok = False
                print('[%s] uid=%s song=%s 异常 %s' % (arm, uid[-4:], sid, str(e)[:80]), flush=True)
            if ok:
                ok_cnt += 1
            time.sleep(random.uniform(1.0, 3.0))
        return uid, ok_cnt

    t0 = time.time()
    workers = min(12, len(picked))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(one_account, a) for a in picked]
        for f in as_completed(futs):
            uid, ok_cnt = f.result()
            results.append((uid, ok_cnt))
            lock_n['ok'] += ok_cnt
            lock_n['fail'] += (len(songs) - ok_cnt)

    print('[%s] 完成 %.1f 分钟：成功 %d 次 / 失败 %d 次（%d 号 × %d 首）' % (
        arm, (time.time() - t0) / 60, lock_n['ok'], lock_n['fail'], len(picked), len(songs)),
        flush=True)
    return lock_n['ok'], lock_n['fail'], results


def main():
    arm = os.environ.get('EXP_ARM', '').strip()
    n_target = int(os.environ.get('EXP_N', '0'))
    job_lo = int(os.environ.get('EXP_JOB_LO', '0'))
    job_hi = int(os.environ.get('EXP_JOB_HI', '0'))
    ns = int(os.environ.get('EXP_NS', '97'))
    songs = parse_songs(os.environ.get('EXP_SONGS', ''))
    if not arm or n_target <= 0 or not songs:
        raise SystemExit('参数不全：EXP_ARM=%r EXP_N=%r songs=%d' % (arm, n_target, len(songs)))

    print('=== 实验臂 %s：%d 号（同一 IP）× %d 首，片 %d-%d / 共 %d 片 ===' % (
        arm, n_target, len(songs), job_lo, job_hi, ns), flush=True)
    print('目标歌：%s' % ' '.join(s for s, _d, _o in songs), flush=True)

    accs = collect_accounts(ns, job_lo, job_hi)
    if len(accs) < n_target:
        print('[warn] 候选只有 %d 个，少于目标 %d，按实际数执行' % (len(accs), n_target), flush=True)
    ok, fail, _res = run_arm(arm, accs, songs, n_target)
    print('=== 臂 %s 结束：成功 %d / 失败 %d ===' % (arm, ok, fail), flush=True)
    if ok == 0:
        sys.exit(1)


if __name__ == '__main__':
    main()

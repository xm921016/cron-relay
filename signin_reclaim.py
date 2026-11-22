# -*- coding: utf-8 -*-
"""白天补领班次（2026-11-22）：云贝任务领取(P4) + VIP 成长值领取(P6)。

背景：00:20 班次的签到/领取跑在凌晨，而「听歌30分钟」等每日任务（period=1）
白天才完成 —— 凌晨时任务未完成、P4/P6 领不到；任务当天 0 点重置，隔天无法
补领，白天完成的奖励就一直挂着（11-22 大号实测：听日推+300、VIP+3 挂到下午）。

本脚本只做领取（幂等：无可领取=no-op），不签到、不判死、不删号、
不碰 /api/assign（避免扰动播放分配）。

CK 来源：D1 accounts 表直查大号（与 2026-11-15 起「只保留大号签到」的口径一致），
复用 d1_backup.py 同款 CF_TOKEN / D1_UUID 访问通道（GitHub schedule 实测延迟
4~8h，见 run.yml 头注释，故 workflow 里放 4 个班次对冲，多跑无害）。

用法（GitHub Actions / 本机）：
  env: CF_TOKEN, CF_ACCOUNT_ID
  python3 signin_reclaim.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SIGNIN_NAME = "17316702006"


def main():
    from d1_backup import api  # 环境变量 CF_TOKEN/CF_ACCOUNT_ID 缺失时会在首次查询报错

    rows = api("SELECT name, ck FROM accounts WHERE pool='hz' AND name=? AND ck != ''",
               [SIGNIN_NAME], label="signin-reclaim 取大号CK")
    if not rows or not (rows[0].get("ck") or "").strip():
        print(f"D1 查无大号 {SIGNIN_NAME} 的 CK（可能已删号），跳过补领")
        return
    cfg = {
        "source": "Secrets",   # 只领取，绝不判死/删号（signin.py 对 Secrets 来源强制跳过上报）
        "accounts": [{"name": SIGNIN_NAME, "cookie": rows[0]["ck"].strip(), "roles": "signin"}],
    }
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "accounts_signin_reclaim.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False)

    os.environ["SIGNIN_CONFIG"] = cfg_path
    os.environ["SIGNIN_CLAIM_ONLY"] = "1"
    import signin
    signin.main()


if __name__ == "__main__":
    main()

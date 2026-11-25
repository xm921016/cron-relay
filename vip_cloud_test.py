# -*- coding: utf-8 -*-
"""海外 IP 发卡真数据验证（2026-11-25 用户要求）：
在 GitHub runner（海外 IP）上调网易 eapi token/create 现场生成一张 VIP 邀请卡。
范围与安全：
  - 只调 page/info（查资格）+ token/create（生成卡，不扣额度）+ shorturl（官方短链，best-effort）；
  - 绝不调 accept（不替任何人领会员）；不写任何本地记账（vip_gift_pool 状态零改动）；
  - CK 从环境变量读入，绝不打印/落日志；卡若无人领取月底自动作废，无副作用。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vip_gift_pool import _client, PAGEINFO_URL, TOKENCREATE_URL, SHORTURL_URL, make_link, RESERVE_DAYS


def main():
    ck = os.environ.get("VIP_TEST_CK", "").strip()
    if not ck:
        print("RESULT=MISSING_CK")
        return 1
    cli = _client(ck)
    # 1) 查资格（只读）
    try:
        page = cli.eapi_post(PAGEINFO_URL, {"checktoken": ""})
    except Exception as e:
        print("RESULT=PAGE_ERROR err=%s" % type(e).__name__)
        return 2
    d = page.get("data") if isinstance(page.get("data"), dict) else {}
    d = d or {}
    code = page.get("code")
    cansend = int(d.get("canSendVip") or 0)
    left = int(d.get("sendVipDayLeft") or 0)
    print("PAGE code=%s canSend=%s left=%s" % (code, cansend, left))
    if code != 200 or cansend != 1 or left < RESERVE_DAYS:
        print("RESULT=NOT_ELIGIBLE")
        return 3
    # 2) 发卡（token/create 只生成卡，不扣额度）
    try:
        resp = cli.eapi_post(TOKENCREATE_URL, {})
    except Exception as e:
        print("RESULT=CREATE_ERROR err=%s" % type(e).__name__)
        return 4
    data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
    tok = str((data or {}).get("token") or "").strip()
    if resp.get("code") != 200 or not tok:
        print("RESULT=CREATE_FAIL code=%s msg=%s" % (resp.get("code"), str(resp.get("message", ""))[:80]))
        return 5
    link = make_link(tok)
    short = ""
    try:
        sr = cli.eapi_post(SHORTURL_URL, {"url": link})
        sd = sr.get("data") if isinstance(sr.get("data"), dict) else {}
        short = str((sd or {}).get("shortUrl") or "")
    except Exception:
        short = ""
    print("RESULT=CREATE_OK")
    # 仓库是 public、Actions 日志公开：链接一律 base64 输出，避免明文卡链被爬走白嫖
    import base64
    print("LINK_B64=" + base64.b64encode(link.encode("utf-8")).decode("ascii"))
    print("SHORT_B64=" + base64.b64encode(short.encode("utf-8")).decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

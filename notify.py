# -*- coding: utf-8 -*-
"""
号主直邮模块（2026-10-17 新增）。

账号出问题时，给成员本人发一封说人话的邮件（不是给群主、也不是 GitHub 那种
开发者日志），只讲三件事：发生了什么、不影响什么、要做哪一步。
语气保持平和，不使用"风控/拦截/异常"等刺激性措辞。

通道：QQ 邮箱 SMTP，凭据从环境变量读取（GitHub Secrets 注入）：
  EMAIL_FROM      发件 QQ 邮箱地址
  EMAIL_AUTH_CODE 该邮箱的 SMTP 授权码（16 位）
未配置或发送失败都只记日志，绝不影响批量执行/日常主流程。

触发分工（避免同一个号一天收到多封重复提醒）：
  - 登录凭证失效 → run.py 在播放前验活时先发（它的判定最严、覆盖最广，包含「code 200
                   但已掉线、每日推荐 0 首」这类号）；signin.py 只对 run.py 本片没报过的
                   号补发。两者同 job 同目录，靠 dead_sent.json 去重 → 一个号一天最多一封。
  - 发动态需安全验证 → notes.py 负责（每 6 天最多轮到一次）
"""
import os
import smtplib
import time
import html as _html
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

DISPLAY_NAME = "网易音乐人650任务"
# 2026-10-23：落款统一（此前 verify 用「小助手」、relogin 用「目标任务」，同一个人收到两封
# 会出现两个身份）。全部改用品牌名，两群模板完全一致，只有 JOIN_PAGE 按群不同。
SIGN = "网易音乐人650任务"
SMTP_HOST = "smtp.qq.com"
SMTP_PORT = 465
# 成员接入登记页（邮件里给号主重新登录用）
JOIN_PAGE = "https://xx1031.xyz"


def _cred():
    return (
        (os.environ.get("EMAIL_FROM", "") or "").strip(),
        (os.environ.get("EMAIL_AUTH_CODE", "") or "").strip(),
    )


# 2026-11-06：多发信通道（轮发）。QQ 邮箱普通号每日发信上限 ~500 封，且高频连发会被断连，
# 单通道扛不住补发/高峰；第二个通道（EMAIL_FROM2/EMAIL_AUTH_CODE2）可选配置，未配置时行为不变。
# 轮发策略：每成功发一封就把指针移到下一个通道（流量对半摊）；某通道失败当场用下一个通道重试一次，
# 全失败才算失败（失败件照旧退回队列，下一班重试时会轮到另一个通道）。
# 2026-11-09：通道数不再写死到 4，改为按序扫描 EMAIL_FROM / EMAIL_FROM2..EMAIL_FROM20，
# 只认「地址+授权码都有」的项（中间有空号也不影响后面的），新增邮箱只要配 Secret 即可生效。
# 同批：起始通道按「当前半小时时段」错开（原来每班都从通道 1 起，一班只发 1~3 封时后面几个
# 通道永远轮不到，加了也白加）。进程内仍逐封轮转，跨班次则自然摊平；单通道时行为不变。
_MAX_CH = 20
_ACCTS = []
_ACCT_AT = [int(time.time() // 1800)]


def _acct(i):
    sfx = "" if i == 1 else str(i)
    return (
        (os.environ.get("EMAIL_FROM" + sfx, "") or "").strip(),
        (os.environ.get("EMAIL_AUTH_CODE" + sfx, "") or "").strip(),
    )


def _accts():
    if not _ACCTS:
        for i in range(1, _MAX_CH + 1):
            f, a = _acct(i)
            if f and a:
                _ACCTS.append((f, a))
    return _ACCTS


def mail_ready():
    return bool(_accts())


# 2026-11-06 排版改版：用户反馈纯文本邮件太紧凑，改发 multipart/alternative——
# 纯文本部分原样保留（老客户端降级用），HTML 部分只动排版不动措辞（正文一字不改）：
# 段落间留白 + 2 倍行距 + 品牌红顶栏 + 售后群高亮块 + 灰色落款 + 卡片式容器。
_BRAND_RED = "#DD001B"


def _html_wrap(body):
    """纯文本正文 → 卡片式 HTML。约定：
    · 空行（\\n\\n）分段；段内换行（\\n）转 <br>
    · 「售后群：」开头 → 浅红高亮块
    · 「——」开头 → 落款，小号灰字
    其余一律正常段落。"""
    blocks = []
    for para in body.split("\n\n"):
        esc = _html.escape(para).replace("\n", "<br>")
        st = para.strip()
        if st.startswith("——"):
            blocks.append('<p style="margin:28px 0 2px;font-size:13px;color:#9aa0a6;">' + esc + "</p>")
        elif st.startswith("售后群："):
            blocks.append('<div style="margin:4px 0 18px;padding:12px 16px;background:#fff5f5;'
                          'border-radius:8px;color:' + _BRAND_RED + ';font-weight:bold;">' + esc + "</div>")
        else:
            blocks.append('<p style="margin:0 0 18px;line-height:2;">' + esc + "</p>")
    inner = "".join(blocks)
    return (
        '<div style="background:#f4f6f8;padding:28px 16px;">'
        '<div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:12px;'
        'overflow:hidden;border:1px solid #eceff3;">'
        '<div style="height:4px;background:' + _BRAND_RED + ';"></div>'
        '<div style="padding:30px 34px 26px;font-family:-apple-system,BlinkMacSystemFont,'
        "'PingFang SC','Microsoft YaHei','Helvetica Neue',Arial,sans-serif;"
        'font-size:15px;color:#333333;">'
        + inner +
        "</div></div>"
        '<p style="max-width:560px;margin:12px auto 0;text-align:center;font-size:12px;color:#b6bcc4;">'
        "网易音乐人650任务 · 系统自动发送</p></div>"
    )


def send_user_email(to_email, subject, body):
    """给成员本人发一封纯文本邮件。任何异常只记日志，不抛出、不影响主流程。"""
    to_email = (to_email or "").strip()
    if not to_email or "@" not in to_email:
        return False
    accts = _accts()
    if not accts:
        print("[notify] 未配置 EMAIL_FROM/EMAIL_AUTH_CODE，跳过直邮")
        return False
    last_err = ""
    for i in range(len(accts)):
        f, a = accts[(_ACCT_AT[0] + i) % len(accts)]
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = formataddr((DISPLAY_NAME, f))
            msg["To"] = to_email
            msg.attach(MIMEText(body, "plain", "utf-8"))          # 降级：老客户端/纯文本视图
            msg.attach(MIMEText(_html_wrap(body), "html", "utf-8"))  # 主视图：排版版
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as server:
                server.login(f, a)
                server.sendmail(f, [to_email], msg.as_string())
            _ACCT_AT[0] = (_ACCT_AT[0] + i + 1) % len(accts)
            tag = "" if len(accts) == 1 else f"（via {f}）"
            print(f"[notify] 已直邮号主 {to_email}{tag}：{subject}")
            return True
        except Exception as e:
            last_err = str(e)
            print(f"[notify] 直邮失败 {to_email}（通道 {f}）：{e}")
    return False


def _who(nickname, name):
    who = (nickname or "").strip()
    if name:
        who = f"{who}（{name}）" if who else str(name)
    return who or "网易音乐人650任务成员"


def notify_verify(email, nickname, name):
    """发动态时平台要求完成一次安全验证。平和陈述，不吓人。

    2026-10-23 改版：把「安全验证」从标题里拿掉（容易被读成"我账号出事了"），
    开场先说"跟你说一声"、把范围锁死在"一条动态"，动作改成可选项而不是义务。

    2026-11-11 改版（实测驱动，两处原话都已不成立）：
      · 删掉「你自己发一条动态就恢复了」—— 已证伪。我们发的是「分享到动态」eapi 接口，
        风控标记挂在我们库里那条 CK 会话上；号主在手机上发笔记走的是另一条会话，
        碰不到这条标记。实测：号主 11-07 亲手发过动态，之后我们每天仍 code=250。
      · 删掉「6 天后系统会自动再试一次」—— 旧口径。NOTES_EVERY_DAYS=1 起是每天都试，
        所以旧文案会让人以为"等着就行"，实际是天天失败、天天发信。
      · 明确劝阻号主自己退出登录：他一退，我们那条 CK 会话大概率被踢，听歌任务直接中断，
        比现在更糟。必须先由售后准备好，再指导他重登，不能让他擅自操作。

    2026-11-12 改版（「换绑登录」ckswap 功能上线后的配套文案，用户定稿口径）：
      · 动作从「联系售后」具体化成两步：①联系客服拿「换绑登录」链接重新扫码登录
        （worker 新增 kind=ckswap：原地换 CK，免费、有效期/歌曲/邮箱不动、听歌不中断、
        不写台账）；②自己在 App 里发一条图文笔记，网易若弹验证顺手完成（完成验证有
        助于解除账号侧标记；不弹也无妨，没有副作用）。
      · 恢复承诺要留有余地：换绑解决的是「会话级」标记（最常见）；如果换绑后仍 250，
        属账号级风控，等几天会自然解除。文案写「一般第二天恢复」，不说死。
    """
    if not (email or "").strip():
        return False
    subject = "【网易音乐人650任务】一条动态暂时发不出去，麻烦联系客服换绑一下"
    body = (
        f"你好，{_who(nickname, name)}：\n\n"
        "跟你说一声：这个号在自动发动态时，被网易云单独要求做一次安全验证，这条动态暂时发不出去。\n"
        "其它都正常——听歌、签到、你的歌被别人播放，全都照旧。\n\n"
        "处理起来很简单，两步：\n"
        "第一步：联系客服拿一条「换绑登录」链接，打开后用原来登记的那个网易云账号扫码登录一次。\n"
        "这一步是把被标记的登录凭证换成一条全新的——免费，有效期、歌曲、邮箱都不变，听歌不受影响。\n"
        "第二步：换绑完成后，打开网易云音乐 App → 底部「笔记」→ 自己发一条图文动态（一句话、一张图都可以）。\n"
        "如果发的过程中网易弹了安全验证，顺手完成一下就行；没弹也无妨。\n\n"
        "提醒一句：请不要自己在 App 里退出登录 —— 扫码不需要先退出，直接扫就行；"
        "自己先退出的话听歌任务会中断，反而更麻烦。\n\n"
        "一般换完第二天自动发动态就恢复了；万一还提示验证，说明网易对这个号多看了几天，"
        "等几天会自己好，不用反复操作，不影响听歌和播放。\n\n"
        "——" + SIGN
    )
    return send_user_email(email, subject, body)


def notify_relogin(email, nickname, name):
    """登录凭证过期/掉线，需要重新登记一次。平和陈述，不吓人。

    2026-10-23 改版：
      · 触发面扩大 —— 以前只有日常程序（signin.py）会调用；现在听歌程序（run.py）在
        播放前验活时判定的失效号也会调用，两边靠 dead_sent.json 去重，一个号一天最多一封。
      · 措辞按需求改成「账号信息过期，重新登记」，并给出「找售后」这条兜底路径，
        避免不会操作的人卡在登记页上没人管。
      · 删掉「7 天后自动移除」——实际清理是「两次判死才删」，与 7 天无关，写进去会误导。
      · 正文里不再出现任何网址（用户要求）：号主不一定能分清哪个链接是真的，
        直接让他找售后最省事，也避免仿冒站搭便车。JOIN_PAGE 常量保留但已不写进邮件。
    """
    if not (email or "").strip():
        return False
    subject = "【网易音乐人650任务】账号信息过期了，麻烦重新登记一次"
    body = (
        f"你好，{_who(nickname, name)}：\n\n"
        "跟你说一声：这个号的登录信息过期了，直接联系售后帮你登记。\n\n"
        "重新登记完，下一次任务会自动恢复正常，不用再做别的。\n\n"
        "——" + SIGN
    )
    return send_user_email(email, subject, body)


# ---------------------------------------------------------------------------
# 2026-11-06 新增：登记成功通知 + 到期提醒（邮件队列 mail_queue → notify_mail.py 派发）。
# 群号在 worker 侧按 reg_cfg 现查后随队列下发（row["group"]）；这里拿到的 group 为空时
# 说明该客服没配群号（default_group 也没配），降级成「联系客服获取」，绝不写死群号。
# 文案为用户 2026-11-06 逐字确认版：登记温和、到期急迫（A 套：数字直给）。
# ---------------------------------------------------------------------------

def _group_line(group):
    g = (group or "").strip()
    return f"售后群：{g}" if g else "售后群：请联系你的客服获取"


def notify_reg_ok(email, nickname, name, group=""):
    """登记成功：报喜 + 温和地把售后群推出去（用户 2026-11-06 定稿文案，逐字使用）。"""
    if not (email or "").strip():
        return False
    subject = "【网易音乐人650任务】登记成功，麻烦加一下售后群"
    body = (
        f"你好，{_who(nickname, name)}：\n"
        "你的账号已经登记成功，明天起会开始听歌任务，你可按照以前习惯一切正常使用APP。\n"
        f"{_group_line(group)}\n"
        "以后账号要是需要重新登录、或者有什么变化，我们会在群里通知。\n"
        "比等邮件快得多，邮件偶尔会掉进垃圾箱，容易耽误事。\n"
        "（备注一下登记用的手机号）\n\n"
        "——" + SIGN
    )
    return send_user_email(email, subject, body)


def notify_songfix(email, nickname, name, group=""):
    """换歌提醒（共创版，2026-11-13 文案 v2：冻结口径改为「登记前已被冻结，拿来即冻结」）。

    触发：歌是共创作品（song_meta.n_artists>1），且任务进度连续多天 0 增长/冻结。
    走 mail_queue 队列（kind=songfix，ref=歌曲 id）。
    语气对齐既有文案：平和陈述、给可执行动作、不吓人。
    """
    if not (email or "").strip():
        return False
    subject = "【网易音乐人650任务】你登记的歌曲没有计入任务，请换一首歌"
    body = (
        f"你好，{_who(nickname, name)}：\n\n"
        "跟你说一个数据核查结果：你的账号这几天的播放任务进度一直没有增长。\n\n"
        "经核查，原因出在目前登记的这首歌上：这首歌在被登记使用之前，就已经因为之前的行为\n"
        "被平台冻结了——我们登记使用的时候它就是冻结状态，播放量一直不计入任务数据。\n"
        "这不是这段时间播放造成的，也不是你账号的问题（我们这边每天都在正常安排播放）。\n\n"
        "另外说明一下：这首歌是「多人共创」作品，按平台规则，共创歌曲的有效播放本来就不计入\n"
        "650 播放任务。\n\n"
        "处理办法：换成你自己上传的原创独唱歌曲（自己上传、自己演唱、不与他人合作发布），\n"
        "然后到售后群联系客服重新登记新歌。换好之后，第二天的进度就会正常增长。\n\n"
        "如果你已经换过歌了，请忽略这封邮件，或者到售后群跟客服说一声。\n\n"
        + _group_line(group) + "\n\n"
        "——" + SIGN
    )
    return send_user_email(email, subject, body)


def notify_songfix_solo(email, nickname, name, group=""):
    """独唱冻结版换歌提醒（kind=songfix2，2026-11-13 文案 v2：冻结口径同 notify_songfix）。

    与 notify_songfix 的区别：登记的歌**是**本人原创独唱（不是共创），
    但平台侧连续多天不把播放计入任务数据（我方派歌正常、平台侧数据冻结）。
    文案不能提「共创」，只陈述冻结事实 + 给换歌动作。
    走 mail_queue 队列（kind=songfix2，ref=歌曲 id）。
    """
    if not (email or "").strip():
        return False
    subject = "【网易音乐人650任务】你登记的歌曲连续多日没有计入任务进度，建议换一首歌"
    body = (
        f"你好，{_who(nickname, name)}：\n\n"
        "跟你说一个数据核查结果：你的账号这几天一直在正常安排播放，但任务进度连续多天没有增长。\n\n"
        "经核查，原因出在目前登记的这首歌上：这首歌在被登记使用之前，就已经因为之前的行为\n"
        "被平台冻结了——我们登记使用的时候它就是冻结状态，播放一直不被平台计入任务数据。\n"
        "这不是这段时间播放造成的，也不是你账号的问题（你的账号一切正常）。\n\n"
        "处理办法：重新上传/发布一首新的本人原创独唱歌曲（自己上传、自己演唱），\n"
        "然后到售后群联系客服把登记的歌换成新歌。换好之后，第二天的进度就会正常增长。\n\n"
        "如果你已经换过歌了，请忽略这封邮件，或者到售后群跟客服说一声。\n\n"
        + _group_line(group) + "\n\n"
        "——" + SIGN
    )
    return send_user_email(email, subject, body)


def notify_songfix_bad(email, nickname, name, group=""):
    """绑错歌/查无此歌版换歌提醒（2026-11-13 新增，kind=songfix3）：

    与 songfix（共创）/songfix2（本人独唱被冻结）的区别：登记的歌**根本不是他音乐人
    名下的作品**（独唱但唯一作者是别人，即「绑错歌」），或歌已下架/删除（「查无此歌」）。
    这是结构性问题，播放永远不计入他的 650，文案直接陈述「不是你的歌」，不提冻结。
    走 mail_queue 队列（kind=songfix3，ref=歌曲 id）。
    """
    if not (email or "").strip():
        return False
    subject = "【网易音乐人650任务】你登记的歌曲不是你自己名下的作品，请换一首歌"
    body = (
        f"你好，{_who(nickname, name)}：\n\n"
        "跟你说一个数据核查结果：你的账号这几天的播放任务进度一直没有增长。\n\n"
        "原因是目前登记的这首歌不是你自己音乐人名下的作品（是其他艺人的歌，"
        "或者该歌曲已下架/被删除）——平台只把音乐人本人作品的播放计入 650 任务，\n"
        "所以不管每天播放多少，进度都不会涨。这不是你账号的问题"
        "（我们这边每天都在正常安排播放）。\n\n"
        "处理办法：换一首你自己上传、自己演唱、以你本人音乐人身份发布的原创独唱歌曲，\n"
        "然后到售后群联系客服重新登记新歌。换好之后，第二天的进度就会正常增长。\n\n"
        "如果你已经换过歌了，请忽略这封邮件，或者到售后群跟客服说一声。\n\n"
        + _group_line(group) + "\n\n"
        "——" + SIGN
    )
    return send_user_email(email, subject, body)


def notify_songchange(email, nickname, name, group="", song_old="", song_new="", notmine=False):
    """主动换歌通知（2026-11-13 新增，kind=songchange）：

    我们把号主登记的歌直接换掉后，向号主说明为什么换歌。
    ref 编码为「旧歌id:新歌id」，歌名由 worker 在 mail_pending 时查 song_meta 附带
    （song_old/song_new），notify_mail 透传进来。
    notmine=True（ref 第三段为 B）时走「原歌不是你名下作品」文案——用于绑错歌/
    查无此歌的自动换歌；默认文案是「原歌登记前已被平台冻结」。
    走 mail_queue 队列（kind=songchange，ref=旧歌id:新歌id[:B]，唯一键天然去重）。
    """
    if not (email or "").strip():
        return False
    old = (song_old or "").strip() or "原歌曲"
    new = (song_new or "").strip() or "新歌曲"
    subject = "【网易音乐人650任务】你账号登记的歌曲已更换，说明一下原因"
    if notmine:
        reason = (
            f"原因：原来的《{old}》不是你自己音乐人名下的作品（是其他艺人的歌，"
            "或该歌曲已下架/被删除），平台不会把它的播放计入 650 任务数据，\n"
            "这就是之前连续多天任务进度没有增长的原因。为了不让你的账号白白空转，\n"
            f"我们把它换成了《{new}》。\n\n"
        )
    else:
        reason = (
            f"原因：原来的《{old}》在被登记使用之前，就已经因为之前的行为被平台冻结了——\n"
            "我们拿来使用时它就是冻结状态，播放量一直不计入任务数据，\n"
            "这就是之前连续多天任务进度没有增长的原因。为了不让你的账号白白空转，\n"
            f"我们把它换成了《{new}》。\n\n"
        )
    body = (
        f"你好，{_who(nickname, name)}：\n\n"
        f"跟你说明一下：你账号登记的歌曲，我们已经从《{old}》换成了《{new}》。\n\n"
        + reason +
        "换歌不影响你的账号状态和已有数据，只是登记的歌变了，换好后第二天的进度就会正常增长。\n\n"
        "如果你想换成自己上传的其他歌曲，到售后群联系客服说一声就行。\n\n"
        + _group_line(group) + "\n\n"
        "——" + SIGN
    )
    return send_user_email(email, subject, body)


# 到期提醒 A 套（数字直给型）：标题直接给天数，语气逐档加急；
# 用户 2026-11-06 要求：不说「在群里说一声」，统一「售后群联系客服」。
_EXPIRE_TPL = {
    30: ("你的账号还剩 30 天",
         "提醒一下，你的账号（{who}）在 {exp} 到期，还剩 30 天。\n\n"
         "到期后会自动停止听歌，播放进度原地停住，不会清空。\n"
         "要继续用的话，这段时间续上就行，续完不影响已有数据。\n\n"
         "续费或者有疑问，请到售后群联系客服。"),
    15: ("你的账号还剩 15 天",
         "你的账号（{who}）{exp} 到期，还剩 15 天，半个月过去了。\n\n"
         "到期后停止听歌，进度原地停住。现在续还来得及，不用等到最后几天。\n"
         "续费或者有疑问，请到售后群联系客服。"),
    7: ("只剩 7 天，你的账号快到期了",
        "你的账号（{who}）{exp} 到期，只剩 7 天了。\n\n"
        "一周之后就会停止听歌，进度原地停住。\n"
        "这几天是续费的正常时间，别拖到最后一天才想起来。\n\n"
        "续费请尽快到售后群联系客服。"),
    3: ("只剩 3 天，请尽快安排续费",
        "你的账号（{who}）{exp} 到期，只剩 3 天。\n\n"
        "三天后自动停止听歌。到时候再补，中间停的这几天是不会补回来的。\n\n"
        "请尽快到售后群联系客服办理续费。"),
    1: ("明天就到期，最后 1 天",
        "最后提醒：你的账号（{who}）{exp} 到期，就剩 1 天了。\n\n"
        "到期后立刻停止自动听歌，进度原地停住。\n"
        "现在续还来得及，再晚就是停了之后补。\n\n"
        "请今天之内到售后群联系客服，说一句「我要续」就行。\n"
        "或者直接回这封邮件，客服会联系你。"),
}


def notify_expire(email, nickname, name, group="", exp="", days=30):
    """到期提醒（剩余 ≤30/15/7/3/1 天各一封，同一档同一到期日只发一次，去重在队列侧做）。"""
    if not (email or "").strip():
        return False
    days = int(days) if days in _EXPIRE_TPL else (30 if int(days or 0) > 30 else min(
        (s for s in (30, 15, 7, 3, 1) if int(days or 0) <= s), default=1))
    subj_tail, mid = _EXPIRE_TPL[days]
    subject = f"【网易音乐人650任务】{subj_tail}"
    who = _who(nickname, name)
    body = (
        "你好，" + who + "：\n\n"
        + mid.format(who=who, exp=(exp or "").strip() or "近期") + "\n"
        + _group_line(group) + "\n\n"
        "——" + SIGN
    )
    return send_user_email(email, subject, body)


if __name__ == "__main__":
    # 本地/CI 自测：python notify.py 收件邮箱 [模板] [参数...]
    # 模板：缺省=发件通道测试；relogin=账号过期重新登记；regok=登记成功；expire=到期提醒
    import sys
    if len(sys.argv) >= 2:
        to = sys.argv[1]
        tpl = sys.argv[2] if len(sys.argv) >= 3 else ""
        if tpl == "relogin":
            aname = sys.argv[3] if len(sys.argv) >= 4 else "你的账号"
            ok = notify_relogin(to, "", aname)
        elif tpl == "regok":
            aname = sys.argv[3] if len(sys.argv) >= 4 else "你的账号"
            grp = sys.argv[4] if len(sys.argv) >= 5 else ""
            ok = notify_reg_ok(to, "", aname, grp)
        elif tpl == "expire":
            aname = sys.argv[3] if len(sys.argv) >= 4 else "你的账号"
            grp = sys.argv[4] if len(sys.argv) >= 5 else ""
            exp = sys.argv[5] if len(sys.argv) >= 6 else "2026-12-06"
            dys = int(sys.argv[6]) if len(sys.argv) >= 7 else 30
            ok = notify_expire(to, "", aname, grp, exp, dys)
        else:
            ok = send_user_email(
                to,
                "【网易音乐人650任务】发件通道测试",
                "如果你收到这封邮件，说明直邮通道工作正常。\n\n——" + SIGN,
            )
        sys.exit(0 if ok else 1)
    print("usage: python notify.py <to_email> [relogin|regok|expire <name> <group> [exp] [days]]")
    sys.exit(2)

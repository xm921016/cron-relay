/**
 * relay-watchdog —— relay 触发总管（CF Cron Trigger 版，2026-11-17）
 *
 * 2026-11-17 升级：GitHub schedule 已从 run.yml 移除，本 worker 升级为「触发总管」：
 *   （用户拍板：CF 主跑、GitHub 只兜底；开跑时间不必精准，0:10~0:30 间随机即可）
 *   · 主触发：cron '10 16 * * *'（北京 0:10）—— 随机延迟 0~13 分钟后无条件 dispatch run.yml
 *     （无 inputs，闸门不适用；day 锚点=当天北京日期，实际 0:10~0:23 间随机开跑，正落 0 点后播放窗口）。
 *     dispatch 失败才发告警邮件，成功不发（每晚正常路径静默）。
 *   · 兜底：cron '35 16 * * *' / '10 18 * * *'（北京 0:35 / 2:10）—— 漏班检查：
 *     判据 = run.yml 是否存在「创建于北京昨天 14:00 之后」的 run（任何状态任何事件）；
 *     没有 → 判定主触发失败，dispatch 补开 + alert-relay 告警邮件。
 *   · 第三层：cron-relay 仓 watchdog.yml（GitHub 0:40 / 2:10，同判据）。
 *   先到者补开、后到者跳过（判据相同、幂等），不会重复派发。
 *
 * 2026-11-24 定制群接线（用户拍板：dz 触发与 hz 同构，消 GitHub schedule 4~8h 延迟与偶发丢班）：
 *   主触发与兜底层升级为双群同班（hz + dz）：同一组 cron（北京 0:10 / 0:35 / 2:10），
 *   dz 仓 = xm921017/dingzhi，走 GH_TOKEN_DZ（xm921017 PAT；未绑定/失效时 dz 腿静默跳过，
 *   绝不影响 hz 主链路——与主 worker PEER_KEY 未配置即跳过同精神）。
 *   dingzhi 仓 run.yml 的 on.schedule 已同步删除（0 点闸门代码防御性保留，已无触发路径）；
 *   dz 仓 guard.yml（北京 07:30 查漏+补片）保留为第三层，与本 worker 的 0:35/2:10 判据幂等。
 *   补漏状态机（leakTick）/白天补漏轮（secondRound）/快照哨兵（snapGuard）仍是 hz 专属：
 *   dz 快照由主 worker cron 统一发令，cktest 只认 hz 池，故逐号查验不对 dz 开。
 *
 * 2026-11-18 大改（用户拍板：补漏不定固定时间，改事件驱动两轮制）：
 *   旧「北京 9:30 / 12:00 固定两班补漏轮」废弃，换成每 10 分钟一次的 tick 状态机
 *   （cron 每 10 分钟一班，活动窗口北京 00:20~20:00，窗外零请求）：
 *     ① 播放链路（主仓 + 全部节点仓 run.yml）全部收工 → 立即查 coverage（/api/coverage）：
 *        漏 0 个 → 直接收工，不跑任何补漏轮（没漏不浪费）；
 *     ② 漏了 → dispatch 补漏第 1 轮（run.py 断点续跑自动只补漏 + 全池重新验活）；
 *     ③ 第 1 轮收工后再查一次：补齐了 → 收工（第 2 轮不跑）；还有漏 → dispatch 第 2 轮；
 *     ④ 第 2 轮收工后还有漏 → 两轮都补不回 = 号本身有问题 → 立即逐号查验
 *        （/api/console/cktest，与控制台「验证CK」同口径；判 dead 后隔 4s 复验一次，
 *        两次都 dead 才算确认，与 run.py confirm_dead 同精神）；
 *        2026-11-18 晚升级（用户拍板「判死的号马上发邮件，不要等隔日」）：
 *        确认失效的号当场 /api/report_dead（ADMIN_PASS，confirm=true）立即删号并
 *        入队 dead_notice，随后 dispatch notify-dead.yml（wait_h=0）让 Actions
 *        当场把「账号信息过期」邮件发给号主（几分钟内），不再等今晚夜轮；
 *        全部结果仍发 alert-relay 告警邮件给群主。删号只对「两次复验一致」的死号，
 *        且单次 ≤ INSPECT_MAX(30) < report_dead 单次上限 40。
 *   状态机存 KV 绑定 WD（key = leak:<北京日期>，2 天过期）。
 *   每一轮 dispatch 都带停摆保护：dispatch 后 5h 仍未见对应 run → 告警一次。
 *   与快照的关系：补漏轮跑完会让 snapshot.yml 被 workflow_run 再次触发，但 snapshot
 *   有 already_collected_today 去重，当天不会重复采集；补漏轮若拖过 09:30 门闩，
 *   snapshot 会顺延采集时刻（等 relay 全部结束），数据仍是当天统一口径。
 *
 * 判据窗口说明：判据按北京日期取「昨天 14:00」。正常晚主触发 0:10~0:23 创建的 run
 *   在窗口内 → 兜底层跳过；主触发失败整晚无 run → 兜底层补开。
 * 白天的手动/补跑 run（如 backfill 08:13）在窗口外，不会误判「今晚已开班」。
 *
 * 端点：GET /watchdog?pass=<RUN_PASS>[&mode=primary|check|second|leak|leakreset]
 *   mode=check（默认）→ 跑兜底判据；mode=primary → 立即执行一次主触发 dispatch；
 *   mode=leak → 手动跑一次补漏状态机 tick（返回状态与决策）；mode=leakreset → 清掉今天的补漏状态。
 *   xx1031.xyz 域名有 WAF：调用必须带浏览器 UA（铁律 6）。
 */

const GH_API = 'https://api.github.com';
const PRIMARY_CRON = '10 16 * * *';     // 北京 0:10 主触发（随机延迟后 0:10~0:23 间开跑）
const FALLBACK_CRONS = ['35 16 * * *', '10 18 * * *'];  // 北京 0:35 / 2:10 兜底检查
const LEAK_TICK_CRON = '*/5 * * * *';   // 每 5 分钟 tick：补漏状态机（北京 00:20~20:00 活动窗口）+ 定时发令表 schedTick（2026-11-24 改 */5，与 deploy_watchdog.py CRONS 同步）
const OLD_SECOND_CRONS = ['30 1 * * *', '0 4 * * *'];   // 旧固定补漏班（已从 schedules 移除，路由保留兼容手动调用）
const PRIMARY_DELAY_MAX_MS = 13 * 60 * 1000;  // 随机延迟上限 13 分钟（cron 单次墙钟 15 分钟，留余量）
const UA_BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const INSPECT_MAX = 30;                 // 单次查验上限（两轮都漏的号一般是个位数）
const ROUND_STALL_MS = 5 * 3600 * 1000; // dispatch 后 5h 未见对应 run → 停摆告警
const ONGOING_STATES = ['queued', 'in_progress', 'waiting', 'pending'];

function ghHeaders(env, token) {
  return {
    'Authorization': 'Bearer ' + (token || env.GH_TOKEN),
    'Accept': 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'User-Agent': 'relay-watchdog-cf',
  };
}

// 北京「昨天」14:00（按北京日期算，= 北京日期-1 的 14:00）作为「今晚的班」判据窗口起点。
// ⚠️ 不能用 UTC 日期减一天硬算：0:35/2:10 检查时 UTC 日期=北京日期-1，但白天手动调
// /watchdog 时 UTC 日期=北京日期；且 UTC 当日 06:00 ≠ 北京昨日 14:00（差 24h 曾致兜底
// 把昨晚 run 误判成今晚已开班、漏班永远不补开，2026-11-17 已修）。统一按北京日期推。
function cutoffIso(now) {
  const bj = new Date(now.getTime() + 8 * 3600 * 1000);   // 北京墙钟
  const cut = new Date(Date.UTC(bj.getUTCFullYear(), bj.getUTCMonth(), bj.getUTCDate() - 1, 6, 0, 0));
  return cut.toISOString();
}

function bjDateStr(now) {
  const bj = new Date(now.getTime() + 8 * 3600 * 1000);
  return bj.toISOString().slice(0, 10);
}

function bjMinuteOfDay(now) {
  const bj = new Date(now.getTime() + 8 * 3600 * 1000);
  return bj.getUTCHours() * 60 + bj.getUTCMinutes();
}

function wdBase(env) {
  return (env.WORKER_URL || 'https://xx1031.xyz').replace(/\/+$/, '');
}

function nodeRepos(env) {
  // 2026-11-19 多节点分摊：013/014/011/010 各 ≤10 片/天、016 收剩余（正常以 NODE_REPOS 绑定为准）
  return (env.NODE_REPOS || 'xm921013/relay-node,xm921014/relay-node,xm921011/relay-node,xm921010/relay-node,xm921016/relay-node')
    .split(',').map(function (s) { return s.trim(); }).filter(Boolean);
}

// 双群清单（2026-11-24 定制群接线）：hz 走既有绑定；dz 走 GH_TOKEN_DZ（未配置即整腿跳过）。
function pools(env) {
  const list = [
    { key: 'hz', owner: env.GH_OWNER, repo: env.GH_REPO, token: env.GH_TOKEN },
    { key: 'dz', owner: env.DZ_OWNER || 'xm921017', repo: env.DZ_REPO || 'dingzhi', token: env.GH_TOKEN_DZ },
  ];
  return list.filter(function (p) { return p.owner && p.repo && p.token; });
}

async function gh(env, path, payload, token) {
  const r = await fetch(GH_API + path, {
    method: payload ? 'POST' : 'GET',
    headers: ghHeaders(env, token),
    body: payload ? JSON.stringify(payload) : undefined,
    // 2026-11-24：加 15s 超时——GitHub API 故障时不能让 tick 里排队等发令的班次卡死整个 schedTick
    signal: AbortSignal.timeout(15000),
  });
  const text = await r.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (e) { body = null; }
  return { status: r.status, body: body, text: text.slice(0, 400) };
}

// 调 worker HTTP API（铁律 6：xx1031.xyz 有 WAF，必须带浏览器 UA）。
async function wdApi(env, path, payload) {
  const r = await fetch(wdBase(env) + path, {
    method: payload ? 'POST' : 'GET',
    headers: {
      'User-Agent': UA_BROWSER,
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    body: payload ? JSON.stringify(payload) : undefined,
  });
  const text = await r.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (e) { body = null; }
  return { status: r.status, body: body, text: text.slice(0, 300) };
}

async function alertMail(env, subject, body) {
  const base = '/repos/' + env.GH_OWNER + '/' + env.GH_REPO;
  try {
    const d = await gh(env, base + '/actions/workflows/alert-relay.yml/dispatches',
      { ref: 'main', inputs: { subject: subject, body: body } });
    return 'HTTP ' + d.status;
  } catch (e) {
    return 'alert-failed: ' + String(e && e.message || e);
  }
}

/* ============================================================================
   定时发令表（2026-11-24，用户拍板「全部一次迁完」）：GitHub schedule 全面退役。
   背景：GitHub schedule 实测延迟 1~5h+（guard 计划 23:30Z 实际 02:20~02:49Z、
   relay 曾整班丢失、backfill 14:30 实际 17:30~20:00）；CF cron 按分钟准点触发。
   先例：播放主触发/快照/签到补领/买家池跑批均已 CF 发令，零漂移。
   机制：每 5 分钟 tick 每次醒来跑 schedTick()，命中表项且 KV sched:<name>:last ≠ 本分钟
   → POST /dispatches → 写 KV；失败经 alert-relay 发告警邮件。
   口径：
   · 时间全 UTC，分钟必须落 5 分格（tick 为每 5 分钟一班）；keepalive 17→15 是唯一的平移（差 2 分钟）。
   · 每条 yml 已删 on.schedule，只留 workflow_dispatch（手动应急入口不变）；
     backfill 的 workflow_run 主路径（relay 结束即触发）原样保留，cron 兜底改由本表接管。
   · watchdog.yml（hz 0:40/2:10）刻意保留 GitHub schedule —— 它是「连 CF 都失效」的
     跨体系最后保险，CF 化反而失去独立性。
   · 应急开关：KV sched:disable=1 → schedTick 全跳（单任务禁用=把该项从表里注释掉重部署）；
     手动补发：/watchdog?mode=schedforce&name=<表项名>&pass=<RUN_PASS>。
   · 额度（Workers Paid）：tick 288 次/天 + 全表 ~160 次 dispatch/天 + KV 写 ~160 次/天，
     占月配额 <0.5%，仪表盘 CPU（~3%）无可感变化。
   ============================================================================ */
const SCHED_DISABLE_KV = 'sched:disable';
const SCHED_KV_PFX = 'sched:';
const SCHED_TABLE = [
  // ---- hz：xm921016/cron-relay ----
  //（⚠ notify-mail 不进本表：主 worker MAIL_CRONS=['5 * * * *'] 已有每小时 :05 的邮件队列发令腿
  //   （带队列判空/上一班在跑即跳过逻辑），本表再接会双发令——2026-11-24 排查实锤后撤。）
  { name: 'hz-backfill',      cron: '30 6 * * *',   pool: 'hz', wf: 'backfill.yml' },
  { name: 'hz-guard',         cron: '30 23 * * *',  pool: 'hz', wf: 'guard.yml' },
  { name: 'hz-coverage',      cron: '0 12 * * *',   pool: 'hz', wf: 'coverage.yml' },
  { name: 'hz-resync-pool',   cron: '30 11 * * *',  pool: 'hz', wf: 'resync-pool.yml' },
  { name: 'hz-notify-dead',   cron: '0 3 * * *',    pool: 'hz', wf: 'notify-dead.yml' },
  { name: 'hz-c-chain',       cron: '30 2 * * *',   pool: 'hz', wf: 'c-chain.yml' },
  { name: 'hz-cpu-watch',     cron: '10 2 * * *',   pool: 'hz', wf: 'cpu-watch.yml' },
  { name: 'hz-egress-watch',  cron: '30 1 * * *',   pool: 'hz', wf: 'egress-watch.yml' },
  { name: 'hz-d1-daily',      cron: '40 11 * * *',  pool: 'hz', wf: 'd1-daily.yml' },
  { name: 'hz-d1-reconcile',  cron: '10 0 * * *',   pool: 'hz', wf: 'd1-reconcile-kv-shadow.yml' },
  { name: 'hz-gray-check',    cron: '40 23 * * *',  pool: 'hz', wf: 'gray-check.yml' },
  { name: 'hz-bridge-watch',  cron: '*/15 * * * *', pool: 'hz', wf: 'bridge-watch.yml' },
  { name: 'hz-keepalive',     cron: '15 3 * * 1',   pool: 'hz', wf: 'keepalive.yml' },
  { name: 'hz-weekly-report', cron: '20 1 * * 1',   pool: 'hz', wf: 'weekly-report.yml' },
  // ---- dz：xm921017/dingzhi ----
  { name: 'dz-backfill',      cron: '30 6 * * *',   pool: 'dz', wf: 'backfill.yml' },
  { name: 'dz-guard',         cron: '30 23 * * *',  pool: 'dz', wf: 'guard.yml' },
  { name: 'dz-coverage',      cron: '0 12 * * *',   pool: 'dz', wf: 'coverage.yml' },
  { name: 'dz-resync-pool',   cron: '30 11 * * *',  pool: 'dz', wf: 'resync-pool.yml' },
  { name: 'dz-mail-remind',   cron: '0 2 * * *',    pool: 'dz', wf: 'mail-remind.yml' },
  { name: 'dz-keepalive',     cron: '15 3 * * 1',   pool: 'dz', wf: 'keepalive.yml' },
];

// 迷你 cron 匹配（只支持本表用到的形态：*  /步进  逗号列表，单字段；月/日均不特化）
function schedFieldMatch(field, val) {
  if (field === '*') return true;
  if (field.indexOf('*/') === 0) return (val % parseInt(field.slice(2), 10)) === 0;
  const ps = field.split(',');
  for (let i = 0; i < ps.length; i++) {
    if (parseInt(ps[i], 10) === val) return true;
  }
  return false;
}

function schedCronMatch(cron, d) {
  const f = cron.trim().split(/\s+/);
  if (f.length !== 5) return false;
  return schedFieldMatch(f[0], d.getUTCMinutes())
    && schedFieldMatch(f[1], d.getUTCHours())
    && schedFieldMatch(f[2], d.getUTCDate())
    && schedFieldMatch(f[3], d.getUTCMonth() + 1)
    && schedFieldMatch(f[4], d.getUTCDay());
}

async function schedDispatchOne(env, t, now) {
  const p = pools(env).find(function (x) { return x.key === t.pool; });
  if (!p) return { ok: false, status: 'no_token', msg: t.pool + ' 缺 PAT 绑定' };
  let st = 0;
  try {
    const d = await gh(env, '/repos/' + p.owner + '/' + p.repo
      + '/actions/workflows/' + t.wf + '/dispatches', { ref: 'main' }, p.token);
    st = d.status;
  } catch (e) {
    st = -1;
  }
  if (st === 204) return { ok: true, status: 204 };
  const msg = '任务：' + t.name + '（' + t.pool + ' ' + t.wf + '，表内 cron ' + t.cron + '）\n'
    + '时间：' + now.toISOString() + '\nGitHub /dispatches 返回 HTTP ' + st + '，本班未发。\n'
    + '手动应急：Actions 页 workflow_dispatch 本工作流；或 /watchdog?mode=schedforce&name=' + t.name + '&pass=<RUN_PASS>。';
  try { await alertMail(env, '[sched] ' + t.name + ' 发令失败 HTTP ' + st, msg); } catch (e) {}
  return { ok: false, status: st, msg: msg };
}

// 每 5 分钟 tick 调一次；matcher 只挂在此分支，避免与 primary/fallback 同分钟双跑。
// ⚠ 2026-11-24 实锤：匹配必须用 event.scheduledTime（计划触发的整分时刻），不能用执行时刻
//   new Date() —— tick 延迟几秒执行（如 09:45:59 排到 09:46:00+ 跑）分钟就错位，全班静默漏发。
async function schedTick(env, nowMs) {
  let disabled = '';
  try { disabled = (await env.WD.get(SCHED_DISABLE_KV)) || ''; } catch (e) {}
  if (disabled === '1') return { action: 'sched_disabled' };
  const now = new Date(nowMs || Date.now());
  const cur = now.toISOString().slice(0, 16);   // 分钟粒度 UTC 串，字典序即时间序
  // 心跳：进函数先写（区分「tick 没触发」vs「dispatch 挂起堵住尾部写」），7 天过期防堆积
  try { await env.WD.put('sched:tick:last', now.toISOString(), { expirationTtl: 604800 }); } catch (e) {}
  const out = [];
  for (let i = 0; i < SCHED_TABLE.length; i++) {
    const t = SCHED_TABLE[i];
    if (!schedCronMatch(t.cron, now)) continue;
    const key = SCHED_KV_PFX + t.name + ':last';
    let last = '';
    try { last = (await env.WD.get(key)) || ''; } catch (e) {}
    if (last === cur) { out.push(t.name + ':dup'); continue; }
    const r = await schedDispatchOne(env, t, now);
    if (r.ok) {
      try { await env.WD.put(key, cur); } catch (e) {}
      out.push(t.name + ':dispatched');
    } else {
      out.push(t.name + ':FAIL(' + r.status + ')');
    }
  }
  return { action: 'sched', fired: out.length, detail: out };
}

// 手动按表项名补发（无视 cron 匹配，发完写 KV 防止正点 tick 再补一发）
async function schedForce(env, name) {
  const t = SCHED_TABLE.find(function (x) { return x.name === name; });
  if (!t) return { action: 'schedforce', error: 'unknown name: ' + name, known: SCHED_TABLE.map(function (x) { return x.name; }) };
  const now = new Date();
  const r = await schedDispatchOne(env, t, now);
  if (r.ok) {
    try { await env.WD.put(SCHED_KV_PFX + t.name + ':last', now.toISOString().slice(0, 16)); } catch (e) {}
  }
  return { action: 'schedforce', name: t.name, ok: r.ok, status: r.status };
}

async function getState(env, key) {
  try { return await env.WD.get(key, { type: 'json' }); } catch (e) { return null; }
}

async function putState(env, key, val) {
  try { await env.WD.put(key, JSON.stringify(val), { expirationTtl: 172800 }); } catch (e) { /* 状态写失败只影响本轮判断，下轮重试 */ }
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

// 主触发：随机延迟 0~13 分钟后无条件 dispatch（每晚 cron 一班，实际 0:10~0:23 间随机开跑）。
// 墙钟限制：Cron Trigger 单次 invocation 上限 15 分钟，13 分钟延迟 + fetch 留了余量。
// 手动调用（immediate=true，?mode=primary 一键补开）跳过随机延迟立即 dispatch。
// 失败才告警，成功静默。2026-11-24 起双群同班（hz + dz 各自 dispatch，互不影响）。
async function primary(env, immediate) {
  const now = new Date();
  if (!immediate) {
    const delayMs = Math.floor(Math.random() * PRIMARY_DELAY_MAX_MS);
    await new Promise(r => setTimeout(r, delayMs));
  }
  const out = { at: now.toISOString(), results: [] };
  const ps = pools(env);
  for (let i = 0; i < ps.length; i++) {
    const p = ps[i];
    const base = '/repos/' + p.owner + '/' + p.repo;
    let d;
    try {
      d = await gh(env, base + '/actions/workflows/run.yml/dispatches', { ref: 'main' }, p.token);
    } catch (e) {
      const msg = String(e && e.message || e);
      console.error('primary dispatch error [' + p.key + ']:', msg);
      const alert = await alertMail(env, '[' + p.key + '] relay CF 主触发失败，请人工介入',
        '时间：' + now.toISOString() + '\n主触发 dispatch run.yml 异常：' + msg + '\n兜底层将在 0:35 / 2:10 再次尝试补开。');
      out.results.push({ pool: p.key, action: 'error', stage: 'dispatch', message: msg, alert: alert });
      continue;
    }
    if (d.status !== 204) {
      const alert = await alertMail(env, '[' + p.key + '] relay CF 主触发失败，请人工介入',
        '时间：' + now.toISOString() + '\n主触发 dispatch run.yml 返回 HTTP ' + d.status + '：' + d.text + '\n兜底层将在 0:35 / 2:10 再次尝试补开。');
      out.results.push({ pool: p.key, action: 'error', stage: 'dispatch', status: d.status, message: d.text, alert: alert });
      continue;
    }
    out.results.push({ pool: p.key, action: 'dispatch' });
  }
  const errs = out.results.filter(x => x.action === 'error').length;
  out.action = errs && errs === out.results.length ? 'error' : (errs ? 'partial_error' : 'dispatch');
  return out;
}

// 兜底：漏班检查 → 补开 + 告警。2026-11-24 起双群同判据（hz + dz 各查各的 run.yml）。
async function fallback(env) {
  const now = new Date();
  const cut = cutoffIso(now);
  const out = { mode: 'fallback', cutoff: cut, results: [] };
  const ps = pools(env);
  for (let i = 0; i < ps.length; i++) {
    const p = ps[i];
    const base = '/repos/' + p.owner + '/' + p.repo;
    let r;
    try {
      r = await gh(env, base + '/actions/workflows/run.yml/runs?per_page=30', null, p.token);
    } catch (e) {
      out.results.push({ pool: p.key, action: 'error', stage: 'list', message: String(e && e.message || e) });
      continue;
    }
    if (r.status !== 200) {
      out.results.push({ pool: p.key, action: 'error', stage: 'list', status: r.status, message: r.text });
      continue;
    }
    const runs = ((r.body && r.body.workflow_runs) || [])
      .filter(x => x && x.created_at >= cut);
    if (runs.length) {
      out.results.push({ pool: p.key, action: 'skip', reason: 'tonight_already_scheduled',
        runs: runs.slice(0, 5).map(x => '#' + x.run_number + ' ' + x.event + ' ' + x.status + ' ' + x.created_at) });
      continue;
    }

    let d;
    try {
      d = await gh(env, base + '/actions/workflows/run.yml/dispatches', { ref: 'main' }, p.token);
    } catch (e) {
      out.results.push({ pool: p.key, action: 'error', stage: 'dispatch', message: String(e && e.message || e) });
      continue;
    }
    if (d.status !== 204) {
      out.results.push({ pool: p.key, action: 'error', stage: 'dispatch', status: d.status, message: d.text });
      continue;
    }

    const alert = await alertMail(env, '[' + p.key + '] relay 主触发失败，watchdog 已自动补开',
      '时间：' + now.toISOString() + '\n'
      + p.owner + '/' + p.repo + ' 的 run.yml 在窗口（' + cut + ' 之后创建）没有任何 run，判定主触发失败。\n'
      + 'watchdog 已自动 dispatch run.yml 补开今晚轮次，开跑时间晚于 0:30 属正常。\n'
      + '若 2:10 的二次检查再次补开，说明首轮补开也异常，请人工介入。');
    out.results.push({ pool: p.key, action: 'dispatch', alert: alert });
  }
  const errs = out.results.filter(x => x.action === 'error').length;
  const disp = out.results.filter(x => x.action === 'dispatch').length;
  out.action = errs && !disp ? 'error' : (errs ? 'partial_error' : (disp ? 'dispatch' : 'skip'));
  return out;
}

/* ---- 2026-11-18 事件驱动两轮补漏状态机 ---- */

// 查一个仓 run.yml 的 run 列表（可按 sinceIso 过滤）与在跑状态。
// 2026-11-19：卡死识别 —— queued/waiting 超 90 分钟的 run 视为「永远跑不起来」
// （实例：xm921015 被 GitHub 封禁后 dispatch 仍返回 204，run 永远停在 queued，
//  旧逻辑把它当 ongoing，tick 从此永远 skip，补漏/告警全部静默失效）。
const STUCK_QUEUED_MS = 90 * 60 * 1000;
async function repoRunYml(env, repo, sinceIso) {
  const d = await gh(env, '/repos/' + repo + '/actions/workflows/run.yml/runs?per_page=30');
  if (d.status !== 200) return { err: d.status + ' ' + d.text };
  const all = ((d.body && d.body.workflow_runs) || []).filter(x => !!x);
  const runs = sinceIso ? all.filter(x => x.created_at >= sinceIso) : all;
  const nowMs = Date.now();
  const ongoing = runs.filter(function (x) {
    if (ONGOING_STATES.indexOf(x.status) < 0) return false;
    if (x.status === 'in_progress') return true;   // 真在跑不算卡死
    const age = nowMs - new Date(x.created_at).getTime();
    return age < STUCK_QUEUED_MS;                   // queued/waiting 超 90 分钟 = 卡死，不再当忙
  });
  return { runs: runs, ongoing: ongoing, hasOngoing: ongoing.length > 0 };
}

// 播放链路全景：主仓 + 全部节点仓。
// ongoing=任一仓 run.yml 还有在跑/排队轮次；masterRunsAt=主仓 cutoff 后各 run 的创建时间。
// 任一仓查询失败按「忙」处理：宁可跳过本轮 tick，也不在状态不明时 dispatch（防双播源头）。
// 例外（2026-11-19）：403（账号被 GitHub 封禁）= 节点永久下线，按节点下线处理不当忙；
// queued/waiting 超 90 分钟的 run 视为卡死（永远起不来），也不再当忙 —— 见 repoRunYml。
async function chainStatus(env, now) {
  const cut = cutoffIso(now);
  const master = env.GH_OWNER + '/' + env.GH_REPO;
  const repos = [master].concat(nodeRepos(env));
  const out = { cut: cut, repos: {}, ongoing: false, masterRunsAt: [] };
  for (let i = 0; i < repos.length; i++) {
    const repo = repos[i];
    const r = await repoRunYml(env, repo, cut);
    if (r.err) {
      out.repos[repo] = { err: r.err };
      // 2026-11-19：403 = 账号被 GitHub 封禁（suspended），该仓永远不可能有 run 在跑，
      // dispatch 也不可能成功 —— 按「节点下线」处理，不再当「忙」卡死整个状态机
      //（旧逻辑任何查询失败都 ongoing=true，xm921015 被封后 tick 从此永远 skip）。
      if (/^403 /.test(r.err)) {
        out.repos[repo].nodeDown = true;
        // 封号告警：每节点每天最多一封（KV 去重 20h），不静默
        try {
          const dk = 'nodedown:' + repo;
          const seen = await env.WD.get(dk);
          if (!seen) {
            await env.WD.put(dk, new Date().toISOString(), { expirationTtl: 20 * 3600 });
            out.repos[repo].alerted = await alertMail(env,
              '[hz] 播放节点 ' + repo + ' 疑似被 GitHub 封禁（runs API 403）',
              '时间：' + now.toISOString() + '\n节点 ' + repo + ' 查询返回 403（account suspended 症状）。\n'
              + '影响：该节点今晚分不到片（master plan 健康检查会自动跳过并把份额落给 016），\n'
              + '但如果被封的是 016（master 同账号），主仓/派发链路整体失效，需要按\n'
              + '「016 被封应急切换 Runbook」换新账号重建 master 仓 + 重绑 CF secrets。');
          }
        } catch (e) { /* 告警失败不影响状态机 */ }
        continue;
      }
      // 其余错误（网络/5xx/限流）保持「宁当忙不双播」的安全语义
      out.ongoing = true;
      continue;
    }
    out.repos[repo] = {
      n: r.runs.length,
      ongoing: r.ongoing.slice(0, 3).map(x => '#' + x.run_number + ' ' + x.status + ' ' + x.created_at),
    };
    if (r.hasOngoing) out.ongoing = true;
    if (repo === master) out.masterRunsAt = r.runs.map(x => x.created_at).sort();
  }
  return out;
}

// coverage（/api/coverage）：漏跑名单与控制台同一口径（expected 取 plan 快照、
// 已通知重登的号不算漏）。
async function coverage(env, now) {
  const day = bjDateStr(now);
  const d = await wdApi(env, '/api/coverage?pass=' + encodeURIComponent(env.ASSIGN_PASS || '') + '&pool=hz&day=' + day);
  if (d.status !== 200 || !d.body || !d.body.ok) return { ok: false, detail: d.status + ' ' + d.text };
  return d.body;
}

async function dispatchRelay(env) {
  return gh(env, '/repos/' + env.GH_OWNER + '/' + env.GH_REPO + '/actions/workflows/run.yml/dispatches', { ref: 'main' });
}

// 与控制台「验证CK」同口径的实时验证（/api/console/cktest，只读）。
// 404 = 该号已不在池（多半是补漏轮验活时已判死删除）→ 单独归类，不算「没查出来」。
async function cktestOnce(env, uid) {
  const d = await wdApi(env, '/api/console/cktest', {
    user: env.CK_USER || 'xx1031', pass: env.CK_PASS || '', uid: uid,
  });
  if (d.status === 404) return { verdict: 'not_in_pool', message: '该账号已不在池（可能已被判死删除）' };
  if (d.status !== 200 || !d.body) return { verdict: 'err', message: d.status + ' ' + d.text };
  return d.body;
}

// 两轮补漏后仍漏的号逐号查验：dead 隔 4s 复验一次，两次都 dead 才算确认
//（与 run.py confirm_dead「至少两次明确失效」同精神，绝不凭单次失败下结论）。
// verdict 口径（/api/console/cktest 实际返回）：dead / alive / mismatch / unknown / err；
// 复验不过的降级为 dead_once_unconfirmed。注意 cktest 从不返回 'dead_confirmed' ——
// 上游过滤必须用 'dead'（2026-11-18 实修：曾误过滤导致死号全部落进「未确认」桶）。
async function inspectUids(env, uids) {
  const list = (uids || []).slice(0, INSPECT_MAX);
  const results = [];
  for (let i = 0; i < list.length; i++) {
    const uid = list[i];
    let a = null;
    try { a = await cktestOnce(env, uid); } catch (e) { a = { verdict: 'err', message: String(e && e.message || e) }; }
    let verdict = a.verdict || (a.ok ? 'ok' : 'err');
    let msg = String(a.message || a.msg || '').slice(0, 80);
    if (verdict === 'dead') {
      await sleep(4000);
      let b = null;
      try { b = await cktestOnce(env, uid); } catch (e) { b = null; }
      if (!b || (b.verdict || '') !== 'dead') verdict = 'dead_once_unconfirmed';
    }
    results.push({ uid: uid, verdict: verdict, message: msg });
    await sleep(1500);
  }
  return { results: results, truncated: Math.max(0, (uids || []).length - list.length) };
}

// 补漏状态机 tick（2026-11-24 起随 schedTick 每 5 分钟一班，活动窗口北京 00:20~20:00）。
async function leakTick(env) {
  const now = new Date();
  const bjMin = bjMinuteOfDay(now);
  // 活动窗口北京 00:20~20:00：起点避开主触发的随机延迟（00:10~0:23 开跑），
  // 终点留给白天两轮补漏 + 查验收尾，22 点后到次日主触发前保持静默。
  if (bjMin < 20 || bjMin > 20 * 60) {
    return { action: 'skip', reason: 'outside_window', bjMinute: bjMin };
  }
  const key = 'leak:' + bjDateStr(now);
  const st = await getState(env, key);

  const chain = await chainStatus(env, now);
  if (chain.ongoing) {
    return { action: 'skip', reason: 'round_in_progress', chain: chain };
  }
  if (!chain.masterRunsAt.length) {
    return { action: 'skip', reason: 'night_not_started', chain: chain };
  }
  if (st && st.stage === 'done') {
    return { action: 'skip', reason: 'leak_flow_done_today', state: st };
  }

  // dispatch 已发但 GitHub 还没创建出对应 run（极少见）→ 再等；超 5h 视为停摆，告警一次
  if (st && st.dispatchedAt) {
    const seen = chain.masterRunsAt.some(t => t >= st.dispatchedAt);
    if (!seen) {
      if ((now - new Date(st.dispatchedAt)) > ROUND_STALL_MS && !st.stallAlerted) {
        const alert = await alertMail(env, '[hz] 补漏第 ' + st.stage + ' 轮疑似停摆，请人工介入',
          '时间：' + now.toISOString() + '\n补漏第 ' + st.stage + ' 轮于 ' + st.dispatchedAt + ' dispatch，超过 5 小时 GitHub 上仍未见对应 run。\n请到 Actions 页核对主仓 run.yml 是否有异常。');
        st.stallAlerted = true;
        await putState(env, key, st);
        return { action: 'stall_alert', stage: st.stage, alert: alert };
      }
      return { action: 'skip', reason: 'waiting_for_dispatched_run', since: st.dispatchedAt };
    }
  }

  const cov = await coverage(env, now);
  if (!cov.ok) {
    return { action: 'skip', reason: 'coverage_failed', detail: cov.detail };
  }

  // ① 夜轮收工后第一次评估：漏 0 直接收工，不跑任何补漏轮（用户拍板：没漏不浪费）
  if (!st) {
    if (cov.missing_n === 0) {
      await putState(env, key, { stage: 'done', at: now.toISOString(), note: 'night_no_leak' });
      return { action: 'done', note: '夜轮收工且无漏，不需要补漏轮', missing: 0 };
    }
    const d = await dispatchRelay(env);
    if (d.status !== 204) {
      const alert = await alertMail(env, '[hz] 补漏第1轮 dispatch 失败，请人工介入',
        '时间：' + now.toISOString() + '\n夜轮收工后仍漏 ' + cov.missing_n + ' 个号，dispatch run.yml 返回 HTTP ' + d.status + '：' + d.text);
      return { action: 'error', stage: 'dispatch', round: 1, status: d.status, alert: alert };
    }
    await putState(env, key, { stage: 1, dispatchedAt: now.toISOString(), missingAtDispatch: cov.missing_n });
    return { action: 'dispatch', round: 1, missing: cov.missing_n, at: now.toISOString() };
  }

  // ② 第 1 轮收工后再查：补齐 → 收工（第 2 轮不跑）；还有漏 → 第 2 轮
  if (st.stage === 1) {
    if (cov.missing_n === 0) {
      await putState(env, key, { stage: 'done', at: now.toISOString(), note: 'round1_filled', round1At: st.dispatchedAt });
      return { action: 'done', note: '第1轮已补齐，不跑第2轮' };
    }
    const d = await dispatchRelay(env);
    if (d.status !== 204) {
      const alert = await alertMail(env, '[hz] 补漏第2轮 dispatch 失败，请人工介入',
        '时间：' + now.toISOString() + '\n第1轮后仍漏 ' + cov.missing_n + ' 个号，dispatch run.yml 返回 HTTP ' + d.status + '：' + d.text);
      return { action: 'error', stage: 'dispatch', round: 2, status: d.status, alert: alert };
    }
    await putState(env, key, { stage: 2, dispatchedAt: now.toISOString(), missingAtRound1: cov.missing_n, round1At: st.dispatchedAt });
    return { action: 'dispatch', round: 2, missing: cov.missing_n, at: now.toISOString() };
  }

  // ③ 第 2 轮收工后仍漏 → 两轮都补不回 = 号本身有问题 → 立即逐号查验（用户拍板）
  if (st.stage === 2) {
    if (cov.missing_n === 0) {
      await putState(env, key, { stage: 'done', at: now.toISOString(), note: 'round2_filled', round2At: st.dispatchedAt });
      return { action: 'done', note: '第2轮已补齐' };
    }
    const ins = await inspectUids(env, cov.missing || []);
    // cktest 的确认死 verdict 是 'dead'（两次复验一致才会保留），不是 'dead_confirmed'
    const deadList = ins.results.filter(x => x.verdict === 'dead');
    const notPoolList = ins.results.filter(x => x.verdict === 'not_in_pool');
    const otherList = ins.results.filter(x => x.verdict !== 'dead' && x.verdict !== 'not_in_pool');

    // 2026-11-18 晚（用户拍板「判死的号马上发邮件，不要等隔日」）：确认失效 → 当场判死删号
    //（report_dead 带 confirm=true，服务端立即删号 + 把删掉的号入队 dead_notice），
    // 再 dispatch notify-dead.yml（wait_h=0）让 Actions 当场发「账号信息过期」邮件给号主
    // （dead_pending 判定时还会再做一次「号主是否已重登」的活体检查，防误报）。
    // watchdog 只删「两次复验一致」的死号；删除失败/邮件触发失败的号走今晚夜轮兜底，不丢。
    let delReport = null, mailKick = null;
    if (deadList.length) {
      const r = await wdApi(env, '/api/report_dead', {
        pass: env.ADMIN_PASS || '',
        dead: deadList.map(x => x.uid),
        confirm: true,
      });
      if (r.status === 200 && r.body && r.body.ok) {
        delReport = { deleted: (r.body.deleted || []).length };
        if (delReport.deleted > 0) {
          const d2 = await gh(env, '/repos/' + env.GH_OWNER + '/' + env.GH_REPO +
            '/actions/workflows/notify-dead.yml/dispatches', { ref: 'main', inputs: { wait_h: '0' } });
          mailKick = d2.status === 204 ? 'dispatched' : 'HTTP ' + d2.status + ' ' + d2.text;
        }
      } else {
        delReport = { failed: r.status + ' ' + r.text };
      }
    }

    await putState(env, key, {
      stage: 'done', at: now.toISOString(), inspected: ins.results,
      missingFinal: cov.missing_n, round1At: st.round1At, round2At: st.dispatchedAt,
      delReport: delReport, mailKick: mailKick,
    });
    const lines = [];
    lines.push('时间：' + now.toISOString());
    lines.push('补漏两轮后仍有 ' + cov.missing_n + ' 个号漏跑（夜轮收工时漏 ' + (st.missingAtDispatch == null ? '?' : st.missingAtDispatch)
      + ' 个、第1轮后漏 ' + (st.missingAtRound1 == null ? '?' : st.missingAtRound1) + ' 个）。');
    lines.push('已按控制台「验证CK」同口径逐号实时查验（判 dead 后隔 4s 复验，两次一致才确认）：');
    lines.push('');
    if (notPoolList.length) {
      lines.push('【已判死删除 ' + notPoolList.length + ' 个】补漏轮验活时已按既有链路删号+直邮号主，无需再处理：');
      notPoolList.forEach(x => lines.push('  ' + x.uid));
      lines.push('');
    }
    if (deadList.length) {
      if (delReport && delReport.deleted != null) {
        const kickTxt = mailKick === 'dispatched'
          ? '号主邮件已当场触发（notify-dead wait_h=0，几分钟内发出）'
          : '号主邮件当场触发失败（' + mailKick + '），今晚兜底链路会补发';
        lines.push('【确认失效 ' + deadList.length + ' 个 → 已当场判死删号 ' + delReport.deleted + ' 个】' + kickTxt + '：');
      } else {
        lines.push('【确认失效 ' + deadList.length + ' 个】判死删号失败（' + (delReport && delReport.failed || '?') + '），今晚夜轮会兜底判死+直邮：');
      }
      deadList.forEach(x => lines.push('  ' + x.uid + '  ' + (x.message || '')));
      lines.push('');
    }
    if (otherList.length) {
      lines.push('【未确认失效 ' + otherList.length + ' 个】网络异常/受限/单次失败，今晚主轮会自动再跑：');
      otherList.forEach(x => lines.push('  ' + x.uid + '  ' + x.verdict + '  ' + (x.message || '')));
      if (ins.truncated) lines.push('（另有 ' + ins.truncated + ' 个未验，超出单次上限 ' + INSPECT_MAX + '，今晚主轮会覆盖）');
    }
    const subjectTail = deadList.length ? ('其中' + deadList.length + '个确认失效') : '全部为未确认失效';
    const alert = await alertMail(env, '[hz] 补漏2轮后仍漏 ' + cov.missing_n + ' 个号，已自动查验（' + subjectTail + '）',
      lines.join('\n'));
    return { action: 'inspected', missing: cov.missing_n, dead: deadList.length, deleted: delReport && delReport.deleted, mail: mailKick, not_in_pool: notPoolList.length, other: otherList.length, alert: alert };
  }

  return { action: 'skip', reason: 'unknown_stage', state: st };
}

function isPrimaryCron(cron) {
  return cron === PRIMARY_CRON;
}

// 旧固定补漏班（9:30/12:00）：已不再排班，仅保留给手动 ?mode=second 兼容调用。
// 防重复派发：① 有在跑/排队的 run → 跳过；② 近 2 小时内已有 run 创建 → 跳过。
async function secondRound(env) {
  const now = new Date();
  const base = '/repos/' + env.GH_OWNER + '/' + env.GH_REPO;
  // 北京今天 00:00（UTC 时间戳）
  const bj = new Date(now.getTime() + 8 * 3600 * 1000);
  const todayCut = new Date(Date.UTC(bj.getUTCFullYear(), bj.getUTCMonth(), bj.getUTCDate(), 0, 0, 0) - 8 * 3600 * 1000).toISOString();
  let r;
  try {
    r = await gh(env, base + '/actions/workflows/run.yml/runs?per_page=30');
  } catch (e) {
    return { action: 'error', stage: 'list', message: String(e && e.message || e) };
  }
  if (r.status !== 200) {
    return { action: 'error', stage: 'list', status: r.status, message: r.text };
  }
  const runs = ((r.body && r.body.workflow_runs) || []).filter(x => x && x.created_at >= todayCut);
  const ongoing = runs.filter(x => x.status === 'queued' || x.status === 'in_progress');
  if (ongoing.length) {
    return { action: 'skip', reason: 'round_in_progress',
      runs: ongoing.slice(0, 3).map(x => '#' + x.run_number + ' ' + x.event + ' ' + x.status + ' ' + x.created_at) };
  }
  const recentCut = new Date(now.getTime() - 2 * 3600 * 1000).toISOString();
  const recent = runs.filter(x => x.created_at >= recentCut);
  if (recent.length) {
    return { action: 'skip', reason: 'recent_round_exists',
      runs: recent.slice(0, 3).map(x => '#' + x.run_number + ' ' + x.event + ' ' + x.status + ' ' + x.created_at) };
  }
  let d;
  try {
    d = await gh(env, base + '/actions/workflows/run.yml/dispatches', { ref: 'main' });
  } catch (e) {
    const msg = String(e && e.message || e);
    const alert = await alertMail(env, '[hz] relay 白天补漏轮 dispatch 失败',
      '时间：' + now.toISOString() + '\n补漏轮 dispatch run.yml 异常：' + msg + '\n当天漏掉的号要等晚上夜轮才会被再碰到，请人工处理。');
    return { action: 'error', stage: 'dispatch', message: msg, alert: alert };
  }
  if (d.status !== 204) {
    const alert = await alertMail(env, '[hz] relay 白天补漏轮 dispatch 失败',
      '时间：' + now.toISOString() + '\n补漏轮 dispatch run.yml 返回 HTTP ' + d.status + '：' + d.text + '\n当天漏掉的号要等晚上夜轮才会被再碰到，请人工处理。');
    return { action: 'error', stage: 'dispatch', status: d.status, message: d.text, alert: alert };
  }
  return { action: 'dispatch', mode: 'second', at: now.toISOString() };
}

/* ---- 2026-11-19 快照哨兵：堵「CF cron 10:10 静默失败 → 当天全库采集缺失」型事故 ----
 * 背景：11-19 当天 10:10 的 snap650 派发静默失败（cron:snap650:last 停在昨天），
 * 唯一备用路径（workflow_run 触发）又在 09:30 门闩等待中超预算跳过 → hz 全库采集缺失一整天。
 * 机制：北京 11:00 后每天第一班 tick 查 /api/snap_stat（hz 当天快照行数），
 *   0 行 → 补派 /api/cron_snap（大者胜去重，重复采集无害）+ 告警；查过就记 KV 当天不再重复。
 */
async function snapGuard(env) {
  const now = new Date();
  const bjMin = bjMinuteOfDay(now);
  if (bjMin < 11 * 60) return { action: 'skip', reason: 'before_1100' };
  const key = 'snapguard:' + bjDateStr(now);
  const done = await env.WD.get(key);
  if (done) return { action: 'skip', reason: 'already_checked_today' };
  const d = await wdApi(env, '/api/snap_stat?pass=' + encodeURIComponent(env.ASSIGN_PASS || ''));
  if (d.status !== 200 || !d.body || !d.body.ok) {
    return { action: 'skip', reason: 'snap_stat_failed', detail: d.status + ' ' + d.text };
  }
  await env.WD.put(key, JSON.stringify({ at: now.toISOString(), hz: d.body.hz, dz: d.body.dz, hzPost: d.body.hzPost }),
    { expirationTtl: 2 * 86400 });
  // 2026-11-20 体检 P1：判定口径改用「09:30 门闩之后写入」的行数（hzPost）。
  // 旧口径数全天行数 —— 夜轮播完顺手写的播时快照也 >0，会把「主采整班缺失」误判成
  // 已采过而不补（11-20 实锤：14 行播时占坑 + 主采缺席）。worker 未升级时回退旧字段。
  const hzChecked = (d.body.hzPost !== undefined) ? (d.body.hzPost || 0) : (d.body.hz || 0);
  if (hzChecked > 0) {
    return { action: 'ok', hz: d.body.hz, hzPost: d.body.hzPost, dz: d.body.dz };
  }
  // 当天 hz 快照 0 行 → 补派采集 + 告警
  const r = await wdApi(env, '/api/cron_snap?pass=' + encodeURIComponent(env.ASSIGN_PASS || ''), {});
  const kicked = r.status === 200 && r.body && r.body.ok;
  const alert = await alertMail(env, '[hz] 今日快照未采集，watchdog 已自动补派 snap650',
    '时间：' + now.toISOString() + '\n北京 11:00 检查：今天（' + bjDateStr(now) + '）hz 快照 0 行，'
    + '正常应已由 CF cron 10:10 采完。\nwatchdog 已补派 /api/cron_snap（' + (kicked ? '成功' : '失败 ' + r.status) + '），'
    + '采集约 25~40 分钟后落库。请留意控制台「快照更新」与「采集缺失」是否恢复。\n'
    + '根因多半是 10:10 CF cron 静默失败（catch 空吞），可用 KV cron:snap650:last 的时间戳核对。');
  return { action: 'redispatch', kicked: kicked, alert: alert };
}

export default {
  async scheduled(event, env, ctx) {
    const cron = event.cron || '';
    // ⚠ 排障（2026-11-24 定时发令表）：记录每次 scheduled 调用的 cron 原文——
    //   tick 每 5 分钟都有调用（analytics 实证）但 schedTick 没执行，先看 event.cron 到底传了什么。
    try {
      ctx.waitUntil(env.WD.put('sched:event:last',
        cron + ' @ ' + new Date(event.scheduledTime || Date.now()).toISOString()).catch(function () {}));
    } catch (e) {}
    let job;
    if (isPrimaryCron(cron)) job = primary(env);
    else if (cron === LEAK_TICK_CRON) {
      // ⚠ 排障埋点（2026-11-24）：确认进了 tick 分支 + schedTick 到底跑没跑
      try { ctx.waitUntil(env.WD.put('sched:branch:last', 'tick entered @ ' + new Date().toISOString()).catch(function () {})); } catch (e) {}
      job = Promise.all([
        leakTick(env).catch(function (e) { return { action: 'leak_error', message: String(e) }; }),
        snapGuard(env).catch(function (e) { return { action: 'snap_error', message: String(e) }; }),
        schedTick(env, event.scheduledTime).catch(function (e) { return { action: 'sched_error', message: String(e) }; }),
      ]);
    }
    else if (OLD_SECOND_CRONS.indexOf(cron) >= 0) job = secondRound(env);
    else if (FALLBACK_CRONS.indexOf(cron) >= 0) job = fallback(env);
    else job = Promise.resolve({ action: 'skip', reason: 'unknown_cron', cron: cron });
    ctx.waitUntil(job.then(res => console.log('watchdog[' + cron + ']:', JSON.stringify(res)))
      .catch(e => console.error('watchdog[' + cron + '] error:', String(e))));
  },
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname !== '/watchdog') {
      return new Response('not found', { status: 404 });
    }
    // 2026-11-20 体检 P2：RUN_PASS 未配置（空值）时旧写法 ?pass= 空串即可过鉴权 —— 手动
    // 端点（primary/second/leak/snapguard）会被任意人触发。未配置口令=端点关闭。
    if (!env.RUN_PASS || (u.searchParams.get('pass') || '') !== env.RUN_PASS) {
      return new Response('forbidden', { status: 403 });
    }
    const mode = u.searchParams.get('mode') || 'check';
    let res;
    try {
      if (mode === 'primary') res = await primary(env, true);
      else if (mode === 'second') res = await secondRound(env);
      else if (mode === 'leak') res = await leakTick(env);
      else if (mode === 'snapguard') res = await snapGuard(env);
      else if (mode === 'sched') res = await schedTick(env);
      else if (mode === 'schedforce') res = await schedForce(env, u.searchParams.get('name') || '');
      else if (mode === 'leakreset') {
        const key = 'leak:' + bjDateStr(new Date());
        try { await env.WD.delete(key); res = { action: 'reset', key: key }; }
        catch (e) { res = { action: 'error', message: String(e && e.message || e) }; }
      }
      else res = await fallback(env);
    }
    catch (e) { res = { action: 'error', message: String(e && e.message || e) }; }
    return new Response(JSON.stringify(res, null, 2), {
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
  },
};

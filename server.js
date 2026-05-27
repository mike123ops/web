const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const path = require('path');
const os = require('os');
const url = require('url');
const fs = require('fs');

const AUTH_USERNAME = process.env.ADMIN_USER || 'admin';
const AUTH_PASSWORD = process.env.ADMIN_PASS || 'fxdxyb1002';

const PORT = process.env.PORT || 3000;
const app = express();
const server = http.createServer(app);



// BIFE防御盾 v2.0 — AI驱动多层安全防护
const BIFE = {
    enabled: true,
    version: '3.0beta',
    maxPayload: 1024 * 100,           // WebSocket最大消息: 100KB
    maxRoomName: 50,                   // 房间名最大长度
    maxFileName: 100,                  // 文件名最大长度
    maxFileData: 1024 * 50,           // 文件数据最大: 50KB
    maxNickLength: 16,                 // 昵称最大长度
    rateLimit: { window: 8000, maxMessages: 8, maxConnections: 5, maxConnPerWindow: 8, maxPrivate: 10, maxRoomOps: 10 },
    ollama: {
        url: process.env.OLLAMA_URL || 'http://127.0.0.1:11434',
        // 双AI模型协同防御
        models: [
            { name: process.env.OLLAMA_MODEL || 'gemma3:4b', enabled: true },
            { name: process.env.OLLAMA_MODEL2 || 'phi3:3.8b', enabled: true }
        ],
        enabled: true,
        timeout: 30000,
        // 协同策略: consensus=一致通过  any=任一通过  weighted=加权(默认)
        strategy: 'consensus'
    },
    stats: { blocked: 0, scanned: 0, aiScanned: 0, threatsBlocked: 0 }
};

// Railway/云端环境自动检测：如果本地没有 Ollama，关闭 AI 防御
if (process.env.DISABLE_AI === '1' || process.env.RAILWAY_ENVIRONMENT) {
    BIFE.ollama.enabled = false;
    console.log('[CLOUD] 检测到云端环境，Ollama AI 防御已自动关闭');
}

const wss = new WebSocketServer({ server, maxPayload: BIFE.maxPayload });

// 心跳配置 — 防止NAT/防火墙/负载均衡断开空闲连接
const HEARTBEAT_INTERVAL = 45000; // 每45秒发一次ping
const HEARTBEAT_TIMEOUT = 25000;  // 25秒内没收到pong视为超时断开（总缓冲70秒）
const HEARTBEAT_CHECK_INTERVAL = 8000; // 每8秒检查一次超时（比默认5秒更温和）

// 安全响应头
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'; form-action 'self'");
    res.removeHeader('X-Powered-By');
    next();
});

// 静态文件
app.use(express.static(path.join(__dirname, 'public')));
app.use('/games', express.static(path.join(__dirname, 'public', 'games')));
app.use(express.json({ limit: '1mb' }));

// ============ HTTP 封禁拦截中间件 ============
app.use((req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || req.headers['x-forwarded-for'] || '';
    const cleanIp = ip.replace(/^::ffff:/, '');
    const ipBan = bannedIps.get(cleanIp);
    if (ipBan) {
        const now = Date.now();
        if (ipBan.bannedUntil === null || (ipBan.bannedUntil && now < ipBan.bannedUntil)) {
            res.status(403).send(`<!DOCTYPE html><html lang=zh-CN><head><meta charset=UTF-8><title>账号已被封禁</title><style>body{background:#1a1a2e;color:#e0e0e0;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.card{background:#16213e;padding:40px;border-radius:16px;text-align:center;max-width:420px;box-shadow:0 8px 32px rgba(0,0,0,.4)}h1{font-size:48px;margin:0 0 10px}h2{color:#e74c3c;margin:0 0 12px}p{color:#888;font-size:14px;line-height:1.6}.reason{color:#e74c3c;font-size:13px;margin:16px 0}</style></head><body><div class=card><h1>🚫</h1><h2>您的账号已被封禁</h2><p>您因违反服务器规则被限制访问所有服务，包括网页浏览、聊天、游戏等全部功能。</p>` + (ipBan.reason ? `<p class=reason>原因: ${ipBan.reason}</p>` : '') + `<p style=color:#555;font-size:12px>如有疑问请联系管理员</p></div></body></html>`);
            return;
        } else {
            bannedIps.delete(cleanIp);
            saveBans();
        }
    }
    next();
});

// ============ 数据存储 ============
const clients = new Map();       // id -> { ws, name, color, admin, room, status, mutedUntil, ip }
const pendingDisconnect = new Map(); // ip -> { id, info, timer } — 断开后缓冲20秒才清理
const rooms = new Map();         // roomName -> { members: Set<id>, password: string }
const messageHistory = [];       // 最近200条消息
const MAX_HISTORY = 200;
const games = new Map();         // gameId -> { type, players, state }
const defenseLog = [];           // AI防御日志
const MAX_DEFENSE_LOG = 200;
const bifeEventLog = [];         // BIFE事件日志
const MAX_BIFE_LOG = 100;
const attackLog = [];            // 网络攻击日志
const cheatLog = [];             // 外挂检测日志
const rateLimitMap = new Map();  // ip -> { count, resetTime }
const RATE_LIMIT = BIFE.rateLimit;
const ipConnectionCount = new Map(); // ip -> 当前活跃连接数
const bannedIps = new Map();     // ip -> { reason, bannedAt, bannedUntil(时间戳), bannedBy }
const bannedMachines = new Map(); // machineCode -> { reason, bannedAt, bannedUntil, bannedBy, userName }
const bannedNames = new Set();  // 封禁的用户名列表

const BANS_FILE = path.join(__dirname, 'bans.json');

// ============ 封禁持久化 ============
function saveBans() {
    try {
        const data = {
            bannedMachines: Array.from(bannedMachines.entries()).map(([mc, ban]) => ({ mc, ...ban })),
            bannedIps: Array.from(bannedIps.entries()).map(([ip, ban]) => ({ ip, ...ban }))
        };
        fs.writeFileSync(BANS_FILE, JSON.stringify(data, null, 2), 'utf-8');
    } catch (e) {
        console.error('[BANS] 保存封禁数据失败:', e.message);
    }
}

function loadBans() {
    try {
        if (!fs.existsSync(BANS_FILE)) return;
        const raw = fs.readFileSync(BANS_FILE, 'utf-8');
        const data = JSON.parse(raw);
        if (data.bannedMachines) {
            for (const item of data.bannedMachines) {
                const { mc, ...ban } = item;
                bannedMachines.set(mc, ban);
            }
        }
        if (data.bannedIps) {
            for (const item of data.bannedIps) {
                const { ip, ...ban } = item;
                bannedIps.set(ip, ban);
            }
        }
        if (bannedMachines.size > 0 || bannedIps.size > 0) {
            console.log(`[BANS] 已恢复 ${bannedMachines.size} 条设备封禁 + ${bannedIps.size} 条IP封禁`);
        }
    } catch (e) {
        console.error('[BANS] 加载封禁数据失败:', e.message);
    }
}

const mutedUsers = new Map();   // id -> true (保留，兼容)
const machineAccounts = new Map(); // machineCode -> { id, name, color, room, createdAt } — 永久设备账号绑定

let nextId = 1;
let nextGameId = 1;

const COLORS = [
    '#e74c3c','#3498db','#2ecc71','#f39c12','#9b59b6',
    '#1abc9c','#e67e22','#2c3e50','#d35400','#8e44ad',
    '#27ae60','#c0392b','#16a085','#f1c40f','#2980b9'
];

// ============ 工具函数 ============
function getLocalIP() {
    const ifs = os.networkInterfaces();
    for (const name of Object.keys(ifs)) {
        for (const iface of ifs[name]) {
            if (iface.family === 'IPv4' && !iface.internal) return iface.address;
        }
    }
    return '127.0.0.1';
}

function getOnlineCount() { return clients.size; }

function getRoomList() {
    return Array.from(rooms.entries()).map(([name, data]) => ({
        name,
        locked: !!data.password
    }));
}

/** 获取用户列表，excludeAdmin=true 时过滤掉管理员 */
function getUserList(excludeAdmin) {
    return Array.from(clients.entries())
        .filter(([id, info]) => !excludeAdmin || !info.admin)
        .map(([id, info]) => ({
            id, name: info.name || '用户' + id,
            color: info.color,
            room: info.room || '大厅', status: info.status || 'online'
        }));
}

/** 向所有非管理员客户端广播 user_list（排除管理员），再单独给管理员发完整列表 */
function broadcastUserList() {
    const publicList = getUserList(true);
    const publicCount = publicList.length;
    for (const [id, info] of clients) {
        if (info.ws.readyState !== 1) continue;
        // 所有用户都看到普通用户列表（不包括管理员连接）
        send(info.ws, { type: 'user_list', users: publicList, onlineCount: publicCount });
    }
}

function send(ws, data) {
    if (ws.readyState !== 1) return;
    try {
        ws.send(JSON.stringify(data));
    } catch (e) {
        console.error('[SEND_ERROR] 序列化失败:', e.message);
        try { ws.send(JSON.stringify({ type: 'error', message: '服务器内部错误: 数据序列化失败' })); } catch(e2) {}
    }
}

function broadcast(data, excludeId) {
    const json = JSON.stringify(data);
    for (const [id, info] of clients) {
        if (id !== excludeId && info.ws.readyState === 1) info.ws.send(json);
    }
}

function broadcastToRoom(room, data, excludeId) {
    const json = JSON.stringify(data);
    for (const [id, info] of clients) {
        if (id !== excludeId && info.room === room && info.ws.readyState === 1) info.ws.send(json);
    }
}

function addHistory(msg) {
    messageHistory.push(msg);
    if (messageHistory.length > MAX_HISTORY) messageHistory.shift();
}

/** 记录AI防御日志 */
function addDefenseLog(entry) {
    defenseLog.push({ time: new Date().toLocaleTimeString(), ...entry });
    if (defenseLog.length > MAX_DEFENSE_LOG) defenseLog.shift();
}

/** 记录网络攻击日志 */
function addAttackLog(entry) {
    attackLog.push({ time: new Date().toLocaleTimeString(), ...entry });
    if (attackLog.length > MAX_DEFENSE_LOG) attackLog.shift();
}

/** 记录外挂检测日志 */
function addCheatLog(entry) {
    cheatLog.push({ time: new Date().toLocaleTimeString(), ...entry });
    if (cheatLog.length > MAX_DEFENSE_LOG) cheatLog.shift();
}

// ============ 速率限制 ============
function checkRateLimit(ip) {
    const now = Date.now();
    let entry = rateLimitMap.get(ip);
    if (!entry || now > entry.resetTime) {
        entry = { count: 0, resetTime: now + RATE_LIMIT.window };
        rateLimitMap.set(ip, entry);
    }
    entry.count++;
    // 定期清理过期条目
    if (rateLimitMap.size > 1000) {
        for (const [k, v] of rateLimitMap) {
            if (now > v.resetTime) rateLimitMap.delete(k);
        }
    }
    return entry.count;
}

/** 滑动窗口速率限制 — 更精确地限制短时间内的请求数 */
function checkSlidingRateLimit(ip, maxCount, windowMs) {
    const now = Date.now();
    const key = 'sliding_' + ip;
    let entry = rateLimitMap.get(key);
    if (!entry || now > entry.resetTime) {
        entry = { queue: [], resetTime: now + windowMs };
        rateLimitMap.set(key, entry);
    }
    entry.queue = entry.queue.filter(t => now - t < windowMs);
    if (entry.queue.length >= maxCount) {
        entry.queue.push(now);
        return entry.queue.length;
    }
    entry.queue.push(now);
    return 0; // 0 = 未超限
}

// ============ 房间密码防暴力破解 ============
const pwdFailMap = new Map(); // ip -> { count, firstFail }
const PWD_MAX_FAILS = 5;
const PWD_BLOCK_SECONDS = 60;

function checkPwdRateLimit(ip) {
    const now = Date.now();
    const entry = pwdFailMap.get(ip);
    if (entry) {
        if (now - entry.firstFail > PWD_BLOCK_SECONDS * 1000) {
            pwdFailMap.delete(ip);
            return { blocked: false };
        }
        if (entry.count >= PWD_MAX_FAILS) {
            return { blocked: true, remaining: Math.ceil((PWD_BLOCK_SECONDS * 1000 - (now - entry.firstFail)) / 1000) };
        }
    }
    return { blocked: false };
}

function recordPwdFail(ip) {
    const now = Date.now();
    const entry = pwdFailMap.get(ip);
    if (entry) {
        if (now - entry.firstFail > PWD_BLOCK_SECONDS * 1000) {
            pwdFailMap.set(ip, { count: 1, firstFail: now });
        } else {
            entry.count++;
        }
    } else {
        pwdFailMap.set(ip, { count: 1, firstFail: now });
    }
}

// 定期清理过期密码失败记录
setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of pwdFailMap) {
        if (now - entry.firstFail > PWD_BLOCK_SECONDS * 1000) pwdFailMap.delete(ip);
    }
}, 30000);

// 定期推送管理面板数据更新（BIFE事件日志、防御日志等实时展示）
setInterval(() => {
    const adminData = buildAdminInfo();
    for (const [aid, ainfo] of clients) {
        if (ainfo.admin && ainfo.ws.readyState === 1) {
            send(ainfo.ws, { type: 'admin_info_result', data: adminData });
        }
    }
}, 3000);

// ============ 网络攻击检测 ============
const ATTACK_PATTERNS = [
    // SQL 注入 — 覆盖各种变体
    { name: 'SQL注入', regex: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC|UNION|UNION\s+ALL|INTO\s+OUTFILE)\b|\bOR\b.*=|\bAND\b.*=|'--|' #|1=1|\bSLEEP\b|\bWAITFOR\b|\bBENCHMARK\b)/i },
    // XSS
    { name: 'XSS攻击', regex: /(<script|<iframe|<embed|<object|<svg\s|onerror=|onload=|onclick=|onfocus=|onmouseover=|onchange=|onkeyup=|onkeydown=|javascript:|alert\(|prompt\(|confirm\(|eval\(|fromCharCode|<[^>]*on\w+\s*=)/i },
    // 路径穿越
    { name: '路径穿越', regex: /(\.\.\/|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c|\.\.\\\/|\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|\/root\/\.bash_history|\/var\/log|\/boot\.ini|win\.ini|c:\\windows|c:\\boot\.ini)/i },
    // 命令注入
    { name: '命令注入', regex: /(;\s*(ls|cat|rm|wget|curl|bash|sh|cmd|powershell|del|format|whoami|id|ifconfig|ipconfig|systeminfo|nslookup|ping|net\s+user|netstat|taskkill|chmod|chown|kill|pkill|python|perl|php|ruby)\b|`[^`]+`|\$\([^)]+\)|\|\s*(whoami|id|dir|ls|cat|type)\b)/i },
    // NoSQL 注入
    { name: 'NoSQL注入', regex: /(\$gt|\$ne|\$lt|\$gte|\$lte|\$regex|\$where|\$nin|\$in|\$exists|{\s*\$)/i },
    // 缓冲区溢出尝试
    { name: '异常载荷', regex: /(%00|\x00|%0d%0a|%0a%0d){3,}/i },
    // SSRF 尝试
    { name: 'SSRF尝试', regex: /\b(127\.0\.0\.1|0\.0\.0\.0|localhost|169\.254|10\.\d{1,3}\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)\b.*\b(url|fetch|curl|get|request|proxy)\b/i },
    // 超长内容
    { name: '超长消息', check: (content) => content.length > 5000 },
    // 纯二进制/不可见字符
    { name: '二进制载荷', check: (content) => { let nonPrintable = 0; for (const ch of content) { if (ch < ' ' && ch !== '\n' && ch !== '\r' && ch !== '\t') nonPrintable++; } return nonPrintable > content.length * 0.3; } }
];

/** 检测网络攻击模式，返回 { detected, type, detail } 或 null */
function detectAttack(content, ip) {
    for (const pattern of ATTACK_PATTERNS) {
        if (pattern.regex && pattern.regex.test(content)) {
            const match = content.match(pattern.regex);
            return { detected: true, type: pattern.name, detail: `匹配到攻击模式: ${match ? match[0].substring(0, 50) : '未知'}` };
        }
        if (pattern.check && pattern.check(content)) {
            return { detected: true, type: pattern.name, detail: `内容异常: 长度=${content.length}, 非打印字符比例异常` };
        }
    }
    return null;
}

/** BIFE防御盾: 通用内容安全校验 */
function bifeValidate(content, maxLen, label) {
    if (!BIFE.enabled) return null;
    BIFE.stats.scanned++;
    if (!content || typeof content !== 'string') { BIFE.stats.blocked++; addBifeEvent('block', label, '内容无效', '高'); return { blocked: true, reason: `${label}: 内容无效` }; }
    if (content.length > maxLen) { BIFE.stats.blocked++; addBifeEvent('block', label, `超过长度限制 ${maxLen}`, '中'); return { blocked: true, reason: `${label}: 超过长度限制 ${maxLen}` }; }
    const attack = detectAttack(content, 'bife');
    if (attack) { BIFE.stats.blocked++; addBifeEvent('threat', label, `${attack.type}: ${content.slice(0, 60)}`, '高'); return { blocked: true, reason: `${label}: ${attack.type}`, attack: true }; }
    // 验证通过 → 记录放行日志
    addBifeEvent('pass', label, `校验通过（${content.slice(0, 40)}）`, '低');
    return null;
}

function addBifeEvent(type, label, detail, risk) {
    bifeEventLog.push({ time: new Date().toLocaleTimeString(), type, label, detail, risk: risk || '中' });
    if (bifeEventLog.length > MAX_BIFE_LOG) bifeEventLog.shift();
}

// ============ 反外挂检测 ============
const CHEAT_THRESHOLDS = {
    maxMovesPerSecond: 20,      // 每秒最多操作数
    minMoveInterval: 30,        // 两次操作最小间隔(ms)
    maxGameJoinPerMin: 10,      // 每分钟最多加入游戏
    suspiciousWinPatterns: 3    // 可疑获胜模式阈值
};

/** 检测游戏外挂行为 */
function detectCheat(id, info, action) {
    if (!info.cheatData) {
        info.cheatData = { moves: [], joinTimes: [], lastMoveTime: 0, flags: 0 };
    }
    const cd = info.cheatData;
    const now = Date.now();

    if (action === 'move') {
        // 检测过快的操作
        const interval = now - cd.lastMoveTime;
        if (interval < CHEAT_THRESHOLDS.minMoveInterval && cd.lastMoveTime > 0) {
            cd.flags++;
            if (cd.flags > 5) {
                addCheatLog({
                    id: `#${id}`, user: info.name,
                    action: '自动操作',
                    detail: `操作间隔过短: ${interval}ms（阈值: ${CHEAT_THRESHOLDS.minMoveInterval}ms）`,
                    risk: '高'
                });
                return true;
            }
        }
        // 检测每秒操作数
        const oneSecAgo = now - 1000;
        cd.moves = cd.moves.filter(t => t > oneSecAgo);
        cd.moves.push(now);
        if (cd.moves.length > CHEAT_THRESHOLDS.maxMovesPerSecond) {
            addCheatLog({
                id: `#${id}`, user: info.name,
                action: '速度异常',
                detail: `每秒操作: ${cd.moves.length}次（阈值: ${CHEAT_THRESHOLDS.maxMovesPerSecond}次）`,
                risk: '高'
            });
            return true;
        }
        cd.lastMoveTime = now;
    }

    if (action === 'join_game') {
        const oneMinAgo = now - 60000;
        cd.joinTimes = cd.joinTimes.filter(t => t > oneMinAgo);
        cd.joinTimes.push(now);
        if (cd.joinTimes.length > CHEAT_THRESHOLDS.maxGameJoinPerMin) {
            addCheatLog({
                id: `#${id}`, user: info.name,
                action: '游戏刷屏',
                detail: `每分钟加入游戏: ${cd.joinTimes.length}次`,
                risk: '中'
            });
            return true;
        }
    }

    // 定期降低标记
    if (cd.flags > 0 && Math.random() < 0.1) cd.flags--;
    return false;
}

// ============ Ollama AI 双模型协同检测 ============

/**
 * 获取当前可用的AI模型列表
 */
function getActiveModels() {
    return (BIFE.ollama.models || []).filter(m => m.enabled);
}

/**
 * 调用单个 Ollama 模型分析
 */
async function callSingleModel(modelName, prompt, type) {
    try {
        const resp = await fetch(`${BIFE.ollama.url}/api/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model: modelName,
                prompt,
                stream: false,
                options: { temperature: 0 }
            }),
            signal: AbortSignal.timeout(BIFE.ollama.timeout)
        });
        const data = await resp.json();
        const answer = (data.response || '').trim().charAt(0);
        BIFE.stats.aiScanned++;
        return { model: modelName, detected: answer === '是', raw: (data.response || '').trim() };
    } catch (e) {
        return { model: modelName, detected: null, error: e.message };
    }
}

/**
 * 双AI模型协同分析 — 两个模型并行检测，根据策略合并结果
 * @param {string} content - 待分析内容
 * @param {string} type - 分析类型 (toxic/attack/cheat/media)
 * @param {string} label - 日志标签
 * @returns {Promise<{ detected: boolean, detail: string, models: string[], confidence: string }>}
 */
async function analyzeWithAI(content, type = 'toxic', label = '') {
    if (!BIFE.ollama.enabled) return { detected: false, models: [], detail: 'AI引擎已关闭' };
    const activeModels = getActiveModels();
    if (activeModels.length === 0) return { detected: false, models: [], detail: '无可用AI模型' };

    let prompt = '';
    const truncated = content.substring(0, 500);
    if (type === 'toxic') {
        prompt = `你是一个内容安全审查AI。判断以下消息是否包含：辱骂、人身攻击、色情、暴力、引战、广告骚扰。只回答"是"或"否"。\n消息：${truncated}`;
    } else if (type === 'attack') {
        prompt = `你是一个网络安全AI。判断以下输入是否包含：SQL注入、XSS攻击、命令注入、网络扫描、恶意payload。只回答"是"或"否"。\n输入：${truncated}`;
    } else if (type === 'cheat') {
        prompt = `你是一个游戏反外挂AI。判断以下游戏操作是否可疑（自动操作、透视、加速等）。只回答"是"或"否"。\n操作：${truncated}`;
    } else if (type === 'media') {
        prompt = `你是一个内容安全审查AI。判断以下文件/图片信息是否可能包含：色情内容、暴露个人隐私（身份证、手机号、地址、银行卡）、暴力血腥、违法信息。仅根据文件名、类型和用户描述判断，不确定时回答"否"。只回答"是"或"否"。\n文件信息：${truncated}`;
    }

    // 并行调用所有活跃模型
    const results = await Promise.all(
        activeModels.map(m => callSingleModel(m.name, prompt, type))
    );

    const yesVotes = results.filter(r => r.detected === true).length;
    const noVotes = results.filter(r => r.detected === false).length;
    const errorVotes = results.filter(r => r.detected === null).length;
    const votedModels = results.filter(r => r.detected !== null);
    const modelNames = results.map(r => r.model);

    const strategy = BIFE.ollama.strategy || 'consensus';
    let decision = false;
    let confidence = 'low';

    if (strategy === 'consensus') {
        // 都同意才拦截（有错误时只看成功模型）
        const available = votedModels.length;
        decision = available > 0 && yesVotes === available;
        confidence = decision ? 'high' : 'low';
    } else if (strategy === 'any') {
        // 任一模型认为违规就拦截
        decision = yesVotes > 0;
        confidence = yesVotes >= 2 ? 'high' : 'medium';
    } else {
        // weighted: 多数决
        decision = yesVotes > noVotes;
        confidence = yesVotes >= 2 ? 'high' : (yesVotes === 1 ? 'medium' : 'low');
    }

    const modelsDetail = modelNames.join(' + ');
    const voteDetail = `[${results.map(r => `${r.model.split(':')[0]}=${r.detected === true ? '违规' : r.detected === false ? '正常' : '错误'}`).join(', ')}]`;

    addBifeEvent(
        decision ? 'threat' : 'pass',
        `${label}AI检测`,
        `${voteDetail} 策略=${strategy} 置信=${confidence} 模型=${modelsDetail}`,
        decision ? '高' : '低'
    );

    return {
        detected: decision,
        detail: decision ? `AI协同判定违规 (${confidence}置信, ${voteDetail})` : `AI检测正常 (${voteDetail})`,
        models: modelNames,
        confidence
    };
}

/**
 * 调用 Ollama 将中文翻译为英文（使用第一个可用模型）
 */
async function translateToEnglish(text) {
    if (!BIFE.ollama.enabled) return null;
    const activeModels = getActiveModels();
    const modelName = activeModels.length > 0 ? activeModels[0].name : 'gemma3:4b';
    try {
        const resp = await fetch(`${BIFE.ollama.url}/api/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model: modelName,
                prompt: `Translate the following Chinese text to English. Output ONLY the English translation, no explanation, no quotes.\n中文：${text.substring(0, 500)}\nEnglish：`,
                stream: false,
                options: { temperature: 0 }
            }),
            signal: AbortSignal.timeout(15000)
        });
        const data = await resp.json();
        const translation = (data.response || '').trim();
        if (translation && translation.length > 0 && !translation.includes('中文：')) {
            return translation;
        }
        return null;
    } catch (e) {
        return null;
    }
}

// ============ 游戏逻辑 ============
const GAME_HANDLERS = {
    tictactoe: {
        name: '井字棋',
        minPlayers: 2, maxPlayers: 2,
        createState() {
            return { board: Array(9).fill(null), turn: 0, winner: null, moveCount: 0 };
        },
        handleMove(state, playerIdx, data, ws, id) {
            if (state.winner) return send(ws, { type: 'game_error', message: '游戏已结束' });
            if (playerIdx !== state.turn) return send(ws, { type: 'game_error', message: '还没轮到你' });
            const pos = data.pos;
            if (pos < 0 || pos > 8 || state.board[pos]) return send(ws, { type: 'game_error', message: '无效位置' });
            state.board[pos] = playerIdx === 0 ? 'X' : 'O';
            state.moveCount++;
            // 检查胜负
            const lines = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
            for (const [a,b,c] of lines) {
                if (state.board[a] && state.board[a] === state.board[b] && state.board[a] === state.board[c]) {
                    state.winner = playerIdx;
                    return { type: 'game_state', board: state.board, turn: -1, winner: playerIdx, moveCount: state.moveCount };
                }
            }
            if (state.moveCount === 9) {
                state.winner = -1;
                return { type: 'game_state', board: state.board, turn: -1, winner: -1, moveCount: state.moveCount, draw: true };
            }
            state.turn = 1 - state.turn;
            return { type: 'game_state', board: state.board, turn: state.turn, winner: null, moveCount: state.moveCount };
        }
    },
    gomoku: {
        name: '五子棋',
        minPlayers: 2, maxPlayers: 2,
        createState() {
            return { board: Array(15).fill(null).map(() => Array(15).fill(null)), turn: 0, winner: null, moveCount: 0 };
        },
        handleMove(state, playerIdx, data, ws) {
            if (state.winner) return send(ws, { type: 'game_error', message: '游戏已结束' });
            if (playerIdx !== state.turn) return send(ws, { type: 'game_error', message: '还没轮到你' });
            const { r, c } = data;
            if (r < 0 || r > 14 || c < 0 || c > 14 || state.board[r][c]) return send(ws, { type: 'game_error', message: '无效位置' });
            state.board[r][c] = playerIdx;
            state.moveCount++;
            // 检查五子连线
            const dirs = [[1,0],[0,1],[1,1],[1,-1]];
            for (const [dr, dc] of dirs) {
                let count = 1;
                for (let d = 1; d < 5; d++) {
                    const nr = r + dr * d, nc = c + dc * d;
                    if (nr < 0 || nr > 14 || nc < 0 || nc > 14) break;
                    if (state.board[nr][nc] === playerIdx) count++; else break;
                }
                for (let d = 1; d < 5; d++) {
                    const nr = r - dr * d, nc = c - dc * d;
                    if (nr < 0 || nr > 14 || nc < 0 || nc > 14) break;
                    if (state.board[nr][nc] === playerIdx) count++; else break;
                }
                if (count >= 5) {
                    state.winner = playerIdx;
                    return { type: 'game_state', board: state.board, turn: -1, winner: playerIdx, lastMove: { r, c } };
                }
            }
            if (state.moveCount === 225) {
                state.winner = -1;
                return { type: 'game_state', board: state.board, turn: -1, winner: -1, draw: true, lastMove: { r, c } };
            }
            state.turn = 1 - state.turn;
            return { type: 'game_state', board: state.board, turn: state.turn, winner: null, lastMove: { r, c } };
        }
    },
    rps: {
        name: '石头剪刀布',
        minPlayers: 2, maxPlayers: 2,
        createState() {
            return { moves: [null, null], round: 1, result: null };
        },
        handleMove(state, playerIdx, data, ws) {
            if (!['rock','paper','scissors'].includes(data.choice)) return send(ws, { type: 'game_error', message: '无效选择' });
            state.moves[playerIdx] = data.choice;
            if (state.moves[0] && state.moves[1]) {
                const m = state.moves;
                let winner = null;
                if (m[0] === m[1]) winner = -1;
                else if ((m[0]==='rock'&&m[1]==='scissors')||(m[0]==='scissors'&&m[1]==='paper')||(m[0]==='paper'&&m[1]==='rock')) winner = 0;
                else winner = 1;
                const result = { winner, p0: m[0], p1: m[1] };
                state.result = result;
                return { type: 'game_state', round: state.round, result, moves: [null, null], phase: 'result' };
            }
            return { type: 'game_state', round: state.round, result: null, phase: 'waiting', playerMoved: playerIdx };
        },
        resetState(state) {
            state.moves = [null, null];
            state.round++;
            state.result = null;
        }
    },
    guessnumber: {
        name: '猜数字',
        minPlayers: 2, maxPlayers: 10,
        createState() {
            return { picker: null, number: null, guesses: [], phase: 'picking', winner: null };
        },
        handleMove(state, playerIdx, data, ws, id, gameInfo) {
            if (state.phase === 'picking') {
                if (state.picker === null) state.picker = playerIdx;
                if (playerIdx !== state.picker) return send(ws, { type: 'game_error', message: '等待出题人选数字' });
                const n = parseInt(data.number);
                if (isNaN(n) || n < 1 || n > 100) return send(ws, { type: 'game_error', message: '请输入1-100的数字' });
                state.number = n;
                state.phase = 'guessing';
                return { type: 'game_state', phase: 'guessing', guesses: [], picker: state.picker, range: [1, 100], message: '数字已选好，开始猜！' };
            } else {
                if (playerIdx === state.picker) return send(ws, { type: 'game_error', message: '出题人不能猜' });
                const guess = parseInt(data.guess);
                if (isNaN(guess) || guess < 1 || guess > 100) return send(ws, { type: 'game_error', message: '请输入1-100的数字' });
                const playerName = gameInfo.players[id] || '#' + id;
                let hint = '';
                if (guess === state.number) {
                    hint = '🎉 猜对了！';
                    state.winner = playerIdx;
                    const g = { playerId: id, playerName, guess, hint, exact: true };
                    state.guesses.push(g);
                    return { type: 'game_state', phase: 'ended', winner: playerIdx, guesses: state.guesses, number: state.number, message: `${playerName} 猜中了！数字是 ${state.number}` };
                } else if (guess < state.number) {
                    hint = '太小了 ↑';
                } else {
                    hint = '太大了 ↓';
                }
                const g = { playerId: id, playerName, guess, hint };
                state.guesses.push(g);
                return { type: 'game_state', phase: 'guessing', guesses: state.guesses, picker: state.picker, message: `${playerName} 猜了 ${guess}，${hint}` };
            }
        },
        resetState(state) {
            state.picker = null;
            state.number = null;
            state.guesses = [];
            state.phase = 'picking';
            state.winner = null;
        }
    },
    connect4: {
        name: '四子棋',
        minPlayers: 2, maxPlayers: 2,
        createState() {
            return { board: Array(6).fill(null).map(() => Array(7).fill(null)), turn: 0, winner: null, moveCount: 0 };
        },
        handleMove(state, playerIdx, data, ws) {
            if (state.winner) return send(ws, { type: 'game_error', message: '游戏已结束' });
            if (playerIdx !== state.turn) return send(ws, { type: 'game_error', message: '还没轮到你' });
            const col = data.col;
            if (col < 0 || col > 6) return send(ws, { type: 'game_error', message: '无效列' });
            // 找最底部的空位
            let row = -1;
            for (let r = 5; r >= 0; r--) {
                if (!state.board[r][col]) { row = r; break; }
            }
            if (row === -1) return send(ws, { type: 'game_error', message: '该列已满' });
            state.board[row][col] = playerIdx;
            state.moveCount++;
            // 检查四子连线
            const dirs = [[1,0],[0,1],[1,1],[1,-1]];
            for (const [dr, dc] of dirs) {
                let count = 1;
                for (let d = 1; d < 4; d++) {
                    const nr = row + dr*d, nc = col + dc*d;
                    if (nr<0||nr>5||nc<0||nc>6) break;
                    if (state.board[nr][nc] === playerIdx) count++; else break;
                }
                for (let d = 1; d < 4; d++) {
                    const nr = row - dr*d, nc = col - dc*d;
                    if (nr<0||nr>5||nc<0||nc>6) break;
                    if (state.board[nr][nc] === playerIdx) count++; else break;
                }
                if (count >= 4) {
                    state.winner = playerIdx;
                    return { type: 'game_state', board: state.board, turn: -1, winner: playerIdx, lastMove: { row, col } };
                }
            }
            if (state.moveCount === 42) {
                state.winner = -1;
                return { type: 'game_state', board: state.board, turn: -1, winner: -1, draw: true, lastMove: { row, col } };
            }
            state.turn = 1 - state.turn;
            return { type: 'game_state', board: state.board, turn: state.turn, winner: null, lastMove: { row, col } };
        }
    },
    hangman: {
        name: '猜单词',
        minPlayers: 2, maxPlayers: 10,
        createState() {
            return { picker: null, word: null, display: null, guessed: [], wrong: 0, maxWrong: 6, phase: 'picking', winner: null };
        },
        handleMove(state, playerIdx, data, ws, id, gameInfo) {
            if (state.phase === 'picking') {
                if (state.picker === null) state.picker = playerIdx;
                if (playerIdx !== state.picker) return send(ws, { type: 'game_error', message: '等待出题人选单词' });
                const w = (data.word || '').toLowerCase().trim();
                if (w.length < 2 || w.length > 20 || !/^[a-z]+$/.test(w)) return send(ws, { type: 'game_error', message: '请输入2-20个英文字母' });
                state.word = w;
                state.display = w.split('').map(() => '_');
                state.phase = 'guessing';
                return { type: 'game_state', phase: 'guessing', display: state.display, guessed: [], wrong: 0, maxWrong: 6, message: '单词已选好！' };
            } else {
                if (playerIdx === state.picker) return send(ws, { type: 'game_error', message: '出题人不能猜' });
                const letter = (data.letter || '').toLowerCase();
                if (!/^[a-z]$/.test(letter)) return send(ws, { type: 'game_error', message: '请输入一个英文字母' });
                if (state.guessed.includes(letter)) return send(ws, { type: 'game_error', message: '已猜过这个字母' });
                state.guessed.push(letter);
                if (state.word.includes(letter)) {
                    for (let i = 0; i < state.word.length; i++) {
                        if (state.word[i] === letter) state.display[i] = letter;
                    }
                    if (!state.display.includes('_')) {
                        state.winner = playerIdx;
                        return { type: 'game_state', phase: 'ended', winner: playerIdx, display: state.display, word: state.word, guessed: state.guessed };
                    }
                    return { type: 'game_state', phase: 'guessing', display: state.display, guessed: state.guessed, wrong: state.wrong, maxWrong: state.maxWrong, message: `字母 ${letter} 在单词中！` };
                } else {
                    state.wrong++;
                    if (state.wrong >= state.maxWrong) {
                        state.winner = -1; // 出题人赢
                        return { type: 'game_state', phase: 'ended', winner: state.picker, display: state.word.split(''), word: state.word, guessed: state.guessed, wrong: state.wrong, message: `猜词失败！单词是 ${state.word}` };
                    }
                    return { type: 'game_state', phase: 'guessing', display: state.display, guessed: state.guessed, wrong: state.wrong, maxWrong: state.maxWrong, message: `字母 ${letter} 不在单词中（${state.wrong}/${state.maxWrong}）` };
                }
            }
        },
        resetState(state) {
            state.picker = null;
            state.word = null;
            state.display = null;
            state.guessed = [];
            state.wrong = 0;
            state.phase = 'picking';
            state.winner = null;
        }
    }
};

function buildAdminInfo() {
    // 清理过期的禁言和封禁
    const now = Date.now();
    for (const [uid, uinfo] of clients) {
        if (uinfo.mutedUntil && now > uinfo.mutedUntil) {
            uinfo.mutedUntil = null;
        }
    }
    for (const [ip, ban] of bannedIps) {
        if (ban.bannedUntil && now > ban.bannedUntil) {
            bannedIps.delete(ip);
        }
    }
    for (const [mc, ban] of bannedMachines) {
        if (ban.bannedUntil && now > ban.bannedUntil) {
            bannedMachines.delete(mc);
        }
    }
    return {
        onlineCount: clients.size,
        users: Array.from(clients.entries())
            .filter(([uid, uinfo]) => !uinfo.admin)  // 不显示管理员自己的连接
            .map(([uid, uinfo]) => ({
            id: uid, name: uinfo.name, color: uinfo.color,
            room: uinfo.room, status: uinfo.status, admin: !!uinfo.admin,
            muted: !!uinfo.mutedUntil,
            mutedUntil: uinfo.mutedUntil || null
        })),
        bannedIps: Array.from(bannedIps.entries()).map(([ip, ban]) => ({
            ip, reason: ban.reason,
            bannedAt: ban.bannedAt,
            bannedUntil: ban.bannedUntil,
            bannedBy: ban.bannedBy,
            userName: ban.userName || ''
        })),
        bannedMachines: Array.from(bannedMachines.entries()).map(([mc, ban]) => ({
            machineCode: mc,
            reason: ban.reason,
            bannedAt: ban.bannedAt,
            bannedUntil: ban.bannedUntil,
            bannedBy: ban.bannedBy,
            userName: ban.userName || ''
        })),
        rooms: getRoomList(),
        uptime: process.uptime(),
        defenseLog: defenseLog.slice(-50),
        bifeEventLog: bifeEventLog.slice(-50),
        attackLog: attackLog.slice(-50),
        cheatLog: cheatLog.slice(-50),
        bife: {
            version: BIFE.version,
            enabled: BIFE.enabled,
            stats: BIFE.stats,
            ollama: { enabled: BIFE.ollama.enabled, models: BIFE.ollama.models, strategy: BIFE.ollama.strategy },
            config: {
                maxPayload: BIFE.maxPayload,
                maxRoomName: BIFE.maxRoomName,
                maxFileName: BIFE.maxFileName,
                maxFileData: BIFE.maxFileData,
                maxNickLength: BIFE.maxNickLength,
                rateLimit: { ...BIFE.rateLimit }
            }
        }
    };
}

// ============ WebSocket 连接处理 ============
wss.on('connection', (ws, req) => {
    const ip = req.socket.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';
    
    // ===== 解析设备指纹 (machineCode) =====
    const query = url.parse(req.url, true).query || {};
    const machineCode = (query.deviceId || '').trim();
    
    // ===== 设备封禁检查 =====
    if (machineCode) {
        const mcBan = bannedMachines.get(machineCode);
        if (mcBan) {
            const now = Date.now();
            // bannedUntil 为 null 表示永久封禁
            if (mcBan.bannedUntil === null || (mcBan.bannedUntil && now < mcBan.bannedUntil)) {
                const remain = mcBan.bannedUntil ? Math.ceil((mcBan.bannedUntil - now) / 1000) : -1;
                console.log(`[BAN] 拒绝被封设备连接: ${machineCode.slice(0,10)}${remain < 0 ? ' (永久)' : ' (剩余'+remain+'秒)'}`);
                ws.close(4002, `你的设备已被封禁${remain < 0 ? '（永久）' : '，剩余 '+Math.ceil(remain/60)+' 分钟'}`);
                return;
            } else {
                // 封禁已过期，清理
                bannedMachines.delete(machineCode);
            }
        }
    }
    
    // ===== 连接级别速率限制 (双层) =====
    const connCount = checkRateLimit('conn_' + ip);
    const slidingCount = checkSlidingRateLimit('conn_' + ip, RATE_LIMIT.maxConnPerWindow, RATE_LIMIT.window);
    if (connCount > RATE_LIMIT.maxConnections || slidingCount > RATE_LIMIT.maxConnPerWindow) {
        console.log(`[RATE] 连接频率过高，拒绝 ${ip} (计数=${connCount}, 滑动=${slidingCount})`);
        ws.close(4000, '连接过于频繁，请稍后再试');
        return;
    }
    // ===== IP并发连接数限制 =====
    const curConns = (ipConnectionCount.get(ip) || 0) + 1;
    if (curConns > RATE_LIMIT.maxConnections) {
        console.log(`[RATE] IP并发连接过多: ${ip} (${curConns})`);
        ws.close(4000, '连接数过多，请稍后再试');
        return;
    }
    ipConnectionCount.set(ip, curConns);

    // ===== TCP keepalive — 防止NAT/防火墙/负载均衡断开空闲连接 =====
    try {
        const socket = req.socket;
        socket.setKeepAlive(true, 15000);  // 每15秒发TCP keepalive探测
        socket.setNoDelay(true);           // 禁用Nagle算法，减少延迟
    } catch(e) { /* keepalive非关键，失败也无妨 */ }
    
    // ===== 先检查是否同 IP 用户在断开缓冲期内重新连接 =====
    const pending = pendingDisconnect.get(ip);
    if (pending) {
        clearTimeout(pending.timer);
        pendingDisconnect.delete(ip);
        const oldId = pending.id;
        const oldInfo = pending.info;
        oldInfo.ws = ws;
        oldInfo.status = 'online';
        clients.set(oldId, oldInfo);
        console.log(`[RECONNECT] #${oldId} (${oldInfo.name}) 重新连接 (50秒缓冲内)`);
        send(ws, { type: 'welcome', id: oldId, color: oldInfo.color, message: '已重新连接', onlineCount: clients.size });
        send(ws, { type: 'user_list', users: getUserList(false), onlineCount: clients.size });
        if (messageHistory.length > 0) {
            send(ws, { type: 'history', messages: messageHistory.slice(-50) });
        }
        // 延迟说"回来了"
        const rejoinTimer = setTimeout(() => {
            broadcast({ type: 'system', message: `${oldInfo.name} 回来了` }, oldId);
            broadcastUserList();
        }, 1500);
        // 重新启动心跳定时器（使用原生ping）
        ws.on('pong', () => { oldInfo.lastPongTime = Date.now(); });
        if (HEARTBEAT_INTERVAL > 0) {
            oldInfo.heartbeatTimer = setInterval(() => {
                if (ws.readyState !== 1) return;
                ws.ping();
            }, HEARTBEAT_INTERVAL);
            oldInfo.heartbeatTimeoutTimer = setInterval(() => {
                if (Date.now() - oldInfo.lastPongTime > HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT) {
                    console.log(`[HEARTBEAT] #${oldId} 心跳超时，断开连接`);
                    ws.close(4004, '心跳超时');
                }
            }, HEARTBEAT_CHECK_INTERVAL);
        }
        // 设置关闭清理（必须在 return 前注册，否则心跳定时器会泄漏）
        ws.on('close', () => {
            if (oldInfo.heartbeatTimer) clearInterval(oldInfo.heartbeatTimer);
            if (oldInfo.heartbeatTimeoutTimer) clearInterval(oldInfo.heartbeatTimeoutTimer);
        });
        return;
    }

    const id = nextId++;
    const color = COLORS[(id - 1) % COLORS.length];

    // ===== IP 封禁检查 =====
    const ipBan = bannedIps.get(ip);
    if (ipBan) {
        const now = Date.now();
        if (ipBan.bannedUntil === null || (ipBan.bannedUntil && now < ipBan.bannedUntil)) {
            const remain = Math.ceil((ipBan.bannedUntil - now) / 1000);
            console.log(`[BAN] 拒绝被封IP连接: ${ip} (剩余${remain}秒)`);
            ws.close(4001, `你的账号已被封禁，剩余 ${remain} 秒`);
            return;
        } else {
            // 封禁已过期，清理
            bannedIps.delete(ip);
        }
    }

    // ===== 设备账号绑定：检查是否已有账号 =====
    const existingAccount = machineAccounts.get(machineCode);
    if (existingAccount) {
        // 已有账号，恢复使用
        console.log(`[MACHINE] #${existingAccount.id} (${existingAccount.name}) 从设备 ${machineCode.slice(0,10)} 恢复连接`);
        const recoveredInfo = {
            ws, name: existingAccount.name, color: existingAccount.color || color,
            authed: false, admin: existingAccount.admin || false,
            room: existingAccount.room || '大厅',
            status: 'online',
            ip,
            machineCode,
            heartbeatTimer: null,
            heartbeatTimeoutTimer: null,
            lastPongTime: Date.now(),
            mutedUntil: null
        };
        clients.set(existingAccount.id, recoveredInfo);
        existingAccount.room = '大厅'; // 重置房间

        send(ws, { type: 'welcome', id: existingAccount.id, color: existingAccount.color, message: '欢迎回来', onlineCount: clients.size });
        send(ws, { type: 'name_accepted', name: existingAccount.name });
        send(ws, { type: 'user_list', users: getUserList(false), onlineCount: clients.size });
        if (messageHistory.length > 0) {
            send(ws, { type: 'history', messages: messageHistory.slice(-50) });
        }

        // 启动心跳
        ws.on('pong', () => { recoveredInfo.lastPongTime = Date.now(); });
        if (HEARTBEAT_INTERVAL > 0) {
            recoveredInfo.heartbeatTimer = setInterval(() => {
                if (ws.readyState !== 1) return;
                ws.ping();
            }, HEARTBEAT_INTERVAL);
            recoveredInfo.heartbeatTimeoutTimer = setInterval(() => {
                if (Date.now() - recoveredInfo.lastPongTime > HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT) {
                    console.log(`[HEARTBEAT] #${existingAccount.id} 心跳超时，断开连接`);
                    ws.close(4004, '心跳超时');
                }
            }, HEARTBEAT_CHECK_INTERVAL);
        }

        // 设置关闭清理（回收路径同样需要，否则心跳定时器泄漏）
        ws.on('close', () => {
            if (recoveredInfo.heartbeatTimer) clearInterval(recoveredInfo.heartbeatTimer);
            if (recoveredInfo.heartbeatTimeoutTimer) clearInterval(recoveredInfo.heartbeatTimeoutTimer);
        });

        // 延迟广播"回来了"
        const rejoinTimer = setTimeout(() => {
            broadcast({ type: 'system', message: `${existingAccount.name} 回来了` }, existingAccount.id);
            broadcastUserList();
        }, 1500);
        return;
    }

    const clientInfo = {
        ws, name: null, color,
        authed: false, mutedUntil: null,
        room: '大厅', status: 'online',
        ip: req.socket.remoteAddress,
        machineCode,
        heartbeatTimer: null,
        heartbeatTimeoutTimer: null,
        lastPongTime: Date.now()
    };
    
    // ===== IP 去重：同IP的新连接仅通知旧连接，但不强制关闭 =====
    // 以避免多标签页/共享网络环境下频繁断连的问题
    for (const [oldId, oldInfo] of clients) {
        if (oldInfo.ip === clientInfo.ip && oldId !== id) {
            try { oldInfo.ws.send(JSON.stringify({ type: 'warn', message: '检测到新连接来自同一IP' })); } catch(e) {}
        }
    }
    
    clients.set(id, clientInfo);

    // ===== 设备账号绑定：首次连接，永久绑定 =====
    if (machineCode) {
        machineAccounts.set(machineCode, { id, name: null, color, room: '大厅', createdAt: Date.now() });
    }

    // 自动分配默认名字
    const defaultName = '用户' + id;
    clientInfo.name = defaultName;
    clientInfo.room = '大厅';

    console.log(`[+] #${id} 已连接 (${defaultName})`);

    send(ws, { type: 'welcome', id, color, message: '已连接', onlineCount: clients.size });
    send(ws, { type: 'name_accepted', name: defaultName, auto: true });
    // 给新连接发用户列表（管理员连入时不显示在前台）
    send(ws, { type: 'user_list', users: getUserList(false), onlineCount: clients.size });
    // 发送历史消息
    if (messageHistory.length > 0) {
        send(ws, { type: 'history', messages: messageHistory.slice(-50) });
    }

    // 延迟广播"加入聊天室"——如果3秒内收到auth则取消（管理员不可见）
    const joinTimer = setTimeout(() => {
        broadcast({ type: 'system', message: `${defaultName} 加入了聊天室` }, id);
        broadcastUserList();
    }, 3000);

    // 启动心跳定时器 — 使用WebSocket原生ping帧（比JSON ping更可靠，不依赖应用层）
    ws.on('pong', () => {
        clientInfo.lastPongTime = Date.now();
    });
    if (HEARTBEAT_INTERVAL > 0) {
        clientInfo.heartbeatTimer = setInterval(() => {
            if (ws.readyState !== 1) return;
            ws.ping();
        }, HEARTBEAT_INTERVAL);

        clientInfo.heartbeatTimeoutTimer = setInterval(() => {
            if (Date.now() - clientInfo.lastPongTime > HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT) {
                console.log(`[HEARTBEAT] #${id} 心跳超时(间隔${HEARTBEAT_INTERVAL/1000}s+缓冲${HEARTBEAT_TIMEOUT/1000}s)，断开连接`);
                ws.close(4004, '心跳超时');
            }
        }, HEARTBEAT_CHECK_INTERVAL);
    }


    ws.on('message', (raw) => {
        let msg;
        try {
            msg = JSON.parse(raw.toString());
        } catch {
            msg = { type: 'chat', content: raw.toString() };
        }

        const info = clients.get(id);
        if (!info) return;

        const name = info.name || '用户' + id;

        switch (msg.type) {
            // ========= 管理员认证（从后台面板登录） =========
            case 'auth': {
                if (info.authed) return;
                // ===== 登录尝试速率限制（暴力破解防御） =====
                const loginCount = checkRateLimit('login_' + ip);
                const slidingLogin = checkSlidingRateLimit('login_' + ip, 3, 10000);
                if (loginCount > 5 || slidingLogin > 3) {
                    console.log(`[AUTH] 暴力破解尝试 #${ip} (计数=${loginCount}, 滑动=${slidingLogin})`);
                    // 超过8次后临时封禁IP 10分钟
                    if (loginCount > 8) {
                        addAttackLog({ id: `#${id}`, user: ip, ip, action: '暴力破解', detail: `8+次登录失败，临时封禁IP`, risk: '高' });
                        bannedIps.set(ip, { reason: '暴力破解', bannedAt: Date.now(), bannedUntil: Date.now() + 600000, bannedBy: 'system' });
                        saveBans();
                        console.log(`[AUTH] IP ${ip} 因暴力破解被临时封禁10分钟`);
                        ws.close(4001, '因暴力破解被封禁');
                        return;
                    }
                    return send(ws, { type: 'error', message: '登录尝试过于频繁，请60秒后再试' });
                }
                if (msg.username !== AUTH_USERNAME || msg.password !== AUTH_PASSWORD) {
                    addAttackLog({
                        id: `#${id}`, user: ip, ip,
                        action: '登录失败',
                        detail: `尝试登录: username="${msg.username}"`,
                        risk: '中'
                    });
                    return send(ws, { type: 'error', message: '管理员账号或密码错误' });
                }
                info.authed = true;
                info.admin = true;
                info.name = msg.username;
                // 取消初始连接广播（管理员不显示在聊天室）
                clearTimeout(joinTimer);
                console.log(`[ADMIN] #${id} 管理员上线 (${msg.username})`);
                send(ws, { type: 'admin_auth_ok', name: msg.username });
                send(ws, { type: 'user_list', users: getUserList(false), onlineCount: clients.size });
                // 通知前台排除管理员（广播 user_list 自动过滤管理员）
                broadcastUserList();
                break;
            }

            // ========= 管理员命令（只有 authed admin 可执行） =========
            case 'admin_ban': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                const targetId = msg.targetId;
                const target = clients.get(targetId);
                if (!target) return send(ws, { type: 'error', message: `用户 #${targetId} 不存在` });
                if (target.admin) return send(ws, { type: 'error', message: '不能封禁管理员' });
                const banDuration = parseInt(msg.duration) || 0; // 分钟，0=永久
                const banUntil = banDuration > 0 ? Date.now() + banDuration * 60000 : null;
                const banMc = target.machineCode || target.ip;
                bannedMachines.set(banMc, {
                    reason: msg.reason || '违规操作',
                    bannedAt: Date.now(),
                    bannedUntil: banUntil,
                    bannedBy: info.name,
                    userName: target.name,
                    ip: target.ip || ''
                });
                // 同时封禁IP（确保IP级别的拦截也生效）
                if (target.ip) {
                    bannedIps.set(target.ip, {
                        reason: msg.reason || '违规操作',
                        bannedAt: Date.now(),
                        bannedUntil: banUntil,
                        bannedBy: info.name,
                        machineCode: target.machineCode || '',
                        userName: target.name
                    });
                }
                saveBans();
                const timeStr = banDuration > 0 ? ` ${banDuration}分钟` : ' 永久';
                // 先通知用户再断开
                try {
                    send(target.ws, { type: 'banned', reason: msg.reason || '违规操作', duration: banDuration, bannedAt: Date.now(), bannedUntil: banUntil });
                } catch(e) {}
                setTimeout(() => { try { target.ws.close(4002, `你的设备已被封禁${timeStr}`); } catch(e) {} }, 500);
                broadcast({ type: 'system', message: `🚫 用户 ${target.name} 已被管理员封禁${timeStr}` });
                console.log(`[ADMIN] #${id} 封禁 #${targetId} (${target.name}) 机器码=${banMc.slice(0,10)} 时长=${banDuration}分钟`);
                send(ws, { type: 'admin_result', message: `已封禁 ${target.name}${timeStr}` });
                broadcastUserList();
                break;
            }
            case 'admin_unban': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                const unbanKey = msg.machineCode;
                if (!unbanKey) return send(ws, { type: 'error', message: '缺少机器码' });
                let found = false;
                // 1. 精确匹配：直接按 key 删除
                if (bannedMachines.has(unbanKey)) {
                    bannedMachines.delete(unbanKey);
                    found = true;
                }
                if (bannedIps.has(unbanKey)) {
                    bannedIps.delete(unbanKey);
                    found = true;
                }
                // 2. 关联匹配：查找同一名用户的 IP/机器码 封禁一并清除
                //    从 bannedMachines 中查找 user/IP 匹配的项
                for (const [mc, ban] of bannedMachines) {
                    if (ban.ip === unbanKey || ban.userName === msg.userName || mc === unbanKey) {
                        bannedMachines.delete(mc);
                        found = true;
                    }
                }
                //    从 bannedIps 中查找关联项
                for (const [ip, ban] of bannedIps) {
                    if (ban.machineCode === unbanKey || ip === unbanKey) {
                        bannedIps.delete(ip);
                        found = true;
                    }
                }
                if (!found) return send(ws, { type: 'error', message: `设备 ${unbanKey.slice(0,10)} 未被封禁` });
                saveBans();
                console.log(`[ADMIN] #${id} 解封设备: ${unbanKey.slice(0,10)}`);
                send(ws, { type: 'admin_result', message: `已解封设备` });
                // 广播更新用户列表（已解封的用户可能重新连接）
                broadcastUserList();
                break;
            }
            case 'admin_mute': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                const muteId = msg.targetId;
                const muteTarget = clients.get(muteId);
                if (!muteTarget) return send(ws, { type: 'error', message: '用户不存在' });
                if (muteTarget.admin) return send(ws, { type: 'error', message: '不能禁言管理员' });
                const muteDuration = parseInt(msg.duration) || 10; // 默认10分钟
                const muteUntil = Date.now() + muteDuration * 60000;
                muteTarget.mutedUntil = muteUntil;
                const minStr = muteDuration >= 60 ? `${Math.floor(muteDuration/60)}小时${muteDuration%60}分钟` : `${muteDuration}分钟`;
                // 通知目标用户已被禁言
                try {
                    send(muteTarget.ws, { type: 'muted', duration: muteDuration, mutedUntil: muteUntil });
                } catch(e) {}
                broadcast({ type: 'system', message: `🔇 用户 ${muteTarget.name} 已被管理员禁言 ${minStr}` });
                console.log(`[ADMIN] #${id} 禁言 #${muteId} (${muteTarget.name}) 时长=${muteDuration}分钟`);
                send(ws, { type: 'admin_result', message: `已禁言 ${muteTarget.name} ${minStr}` });
                break;
            }
            case 'admin_unmute': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                const unmuteId = msg.targetId;
                const unmuteTarget = clients.get(unmuteId);
                if (!unmuteTarget) return send(ws, { type: 'error', message: '用户不存在' });
                unmuteTarget.mutedUntil = null;
                broadcast({ type: 'system', message: `🔊 用户 ${unmuteTarget.name} 已被解除禁言` });
                console.log(`[ADMIN] #${id} 解除禁言 #${unmuteId} (${unmuteTarget.name})`);
                send(ws, { type: 'admin_result', message: `已解除 ${unmuteTarget.name} 的禁言` });
                break;
            }
            // ===== 一键禁言/一键解禁 =====
            case 'admin_mute_all': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                const muteDuration = parseInt(msg.duration) || 30;
                const muteUntil = Date.now() + muteDuration * 60000;
                let count = 0;
                for (const [mid, minfo] of clients) {
                    if (!minfo.admin && !minfo.mutedUntil) {
                        minfo.mutedUntil = muteUntil;
                        count++;
                        try { send(minfo.ws, { type: 'muted', duration: muteDuration, mutedUntil: muteUntil }); } catch(e) {}
                    }
                }
                broadcast({ type: 'system', message: `🔇 管理员已全员禁言 ${muteDuration} 分钟（共 ${count} 人）` });
                console.log(`[ADMIN] #${id} 一键禁言 ${count} 人，时长=${muteDuration}分钟`);
                send(ws, { type: 'admin_result', message: `已全员禁言 ${count} 人，时长 ${muteDuration} 分钟` });
                broadcastUserList();
                break;
            }
            case 'admin_unmute_all': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                let count = 0;
                for (const [mid, minfo] of clients) {
                    if (!minfo.admin && minfo.mutedUntil) {
                        minfo.mutedUntil = null;
                        count++;
                        try { send(minfo.ws, { type: 'unmuted', message: '管理员已解除全员禁言' }); } catch(e) {}
                    }
                }
                broadcast({ type: 'system', message: `🔊 管理员已解除全员禁言（共解除 ${count} 人）` });
                console.log(`[ADMIN] #${id} 一键解除禁言 ${count} 人`);
                send(ws, { type: 'admin_result', message: `已解除全员禁言 ${count} 人` });
                broadcastUserList();
                break;
            }
            case 'admin_broadcast': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                const ann = msg.content;
                if (!ann) return;
                // 公告用 announcement 类型，前端显示为顶部浮动横幅
                const annMsg = { type: 'announcement', message: ann, time: new Date().toLocaleTimeString() };
                // 尝试自动翻译为英文
                translateToEnglish(ann).then(en => {
                    if (en) annMsg.messageEn = en;
                }).catch(() => {}).finally(() => {
                    // 不管翻译是否完成，先发中文公告
                    for (const [cid, cinfo] of clients) {
                        if (cinfo.ws.readyState !== 1 || cinfo.admin) continue;
                        send(cinfo.ws, annMsg);
                    }
                    console.log(`[ADMIN] #${id} 发布公告: ${ann}` + (annMsg.messageEn ? ` | EN: ${annMsg.messageEn}` : ''));
                });
                send(ws, { type: 'admin_result', message: '公告已发布' });
                break;
            }
            case 'admin_info': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                send(ws, { type: 'admin_info_result', data: buildAdminInfo() });
                break;
            }
            case 'admin_shutdown': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                broadcast({ type: 'system', message: '⚠ 服务器即将关闭...' });
                console.log(`[ADMIN] #${id} 关闭服务器`);
                setTimeout(() => process.exit(0), 1000);
                break;
            }
            case 'admin_clear_log': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                defenseLog.length = 0;
                send(ws, { type: 'admin_result', message: '防御日志已清空' });
                break;
            }
            case 'admin_clear_attack_log': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                attackLog.length = 0;
                send(ws, { type: 'admin_result', message: '攻击日志已清空' });
                break;
            }
            case 'admin_clear_cheat_log': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                cheatLog.length = 0;
                send(ws, { type: 'admin_result', message: '外挂日志已清空' });
                break;
            }
            case 'admin_clear_bife_log': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                bifeEventLog.length = 0;
                send(ws, { type: 'admin_bife_log_cleared', message: 'BIFE事件日志已清空' });
                break;
            }

            // ========= BIFE 管理命令 =========
            case 'admin_bife_toggle': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                if (msg.target === 'bife') BIFE.enabled = !BIFE.enabled;
                if (msg.target === 'ollama') BIFE.ollama.enabled = !BIFE.ollama.enabled;
                send(ws, { type: 'admin_result', message: `BIFE.${msg.target}: ${msg.target === 'bife' ? BIFE.enabled : BIFE.ollama.enabled}` });
                break;
            }
            case 'admin_bife_config': {
                if (!info.admin) return send(ws, { type: 'error', message: '无权限' });
                if (msg.key && msg.value !== undefined) {
                    const keys = msg.key.split('.');
                    let obj = BIFE;
                    for (let i = 0; i < keys.length - 1; i++) obj = obj[keys[i]];
                    obj[keys[keys.length - 1]] = msg.value;
                }
                send(ws, { type: 'admin_bife_config_result', config: BIFE });
                break;
            }

            // ========= 基础聊天（带AI防御+攻击检测+反外挂） =========
            case 'chat':
                if (!msg.content || !msg.content.trim()) return;
                // 禁言检查
                if (info.mutedUntil && Date.now() < info.mutedUntil) {
                    return send(ws, { type: 'error', message: '你已被禁言，暂时无法发言' });
                }
                // ===== 速率限制 (双重检测) =====
                const msgCount = checkRateLimit('msg_' + ip);
                const slidingMsg = checkSlidingRateLimit('msg_' + ip, RATE_LIMIT.maxMessages, RATE_LIMIT.window);
                if (msgCount > RATE_LIMIT.maxMessages || slidingMsg > RATE_LIMIT.maxMessages) {
                    addAttackLog({
                        id: `#${id}`, user: name, ip,
                        action: '消息频率超限',
                        detail: `10秒内发送${Math.max(msgCount, slidingMsg)}次（阈值: ${RATE_LIMIT.maxMessages}次）`,
                        risk: '中'
                    });
                    // CC攻击加剧时临时禁言
                    if (msgCount > RATE_LIMIT.maxMessages * 3) {
                        info.mutedUntil = Date.now() + 60000;
                        console.log(`[CC] ${name}(${ip}) 消息洪泛，临时禁言1分钟`);
                    }
                    return send(ws, { type: 'error', message: '发送过于频繁，请稍后再试' });
                }
                const chatContent = msg.content.trim();

                // ===== 网络攻击模式检测（同步快速检查） =====
                BIFE.stats.scanned++;
                const attackResult = detectAttack(chatContent, ip);
                if (attackResult) {
                    BIFE.stats.blocked++;
                    addAttackLog({
                        id: `#${id}`, user: name, ip,
                        action: attackResult.type,
                        detail: attackResult.detail,
                        content: chatContent.substring(0, 200),
                        risk: '高'
                    });
                    addDefenseLog({
                        action: attackResult.type,
                        target: name,
                        detail: chatContent.substring(0, 200),
                        result: '已拦截'
                    });
                    // 严重攻击直接断开
                    if (['SQL注入', '命令注入', 'XSS攻击'].includes(attackResult.type)) {
                        console.log(`[ATTACK] 严重攻击 - #${id} ${name} (${ip}): ${attackResult.type}`);
                        console.log(`[ATTACK] 攻击内容: ${chatContent.substring(0, 100)}`);
                        send(ws, { type: 'error', message: `⚠ 检测到${attackResult.type}行为，连接已断开` });
                        setTimeout(() => ws.close(4003, '检测到攻击行为'), 500);
                    } else {
                        console.log(`[ATTACK] 拦截攻击 - #${id} ${name} (${ip}): ${attackResult.type}`);
                        send(ws, { type: 'error', message: `⚠ 消息被拦截: ${attackResult.type}` });
                    }
                    return;
                }

                // ===== 攻击检测通过 → 记录放行日志 =====
                addDefenseLog({
                    action: '攻击检测',
                    target: name,
                    detail: chatContent.substring(0, 100),
                    result: '检测通过 ✅'
                });

                // ===== 同步威胁关键词检测（中英文） =====
                const threatWords = [
                    '杀', '死', '操', '你妈', 'fuck', 'kill', 'die', 'bastard', 'shit', 'asshole',
                    '威胁', '炸', '死全家', 'kill you', 'i will kill', 'bomb'
                ];
                const lower = chatContent.toLowerCase();
                const hasThreat = threatWords.some(w => lower.includes(w));
                if (hasThreat && !info.admin) {
                    BIFE.stats.threatsBlocked++;
                    info.mutedUntil = Date.now() + 30 * 60000; // 禁言30分钟
                    addDefenseLog({
                        action: '威胁关键词拦截',
                        id: `#${id}`,
                        user: name,
                        detail: chatContent.substring(0, 200),
                        result: '已屏蔽并禁言',
                        risk: '高'
                    });
                    send(ws, { type: 'error', message: '⚠ 发言含不当内容，已被屏蔽并自动禁言' });
                    broadcast({ type: 'system', message: `🔇 ${name} 因发言不当已被自动禁言` });
                    broadcastUserList();
                    return;
                }

                // 先广播消息（立即显示，不等AI，包括发送者自己）
                const chatMsg = {
                    type: 'chat', id,
                    name, color: info.color,
                    content: chatContent,
                    time: new Date().toLocaleTimeString(),
                    room: info.room
                };
                if (info.room && info.room !== '大厅') {
                    broadcastToRoom(info.room, chatMsg);
                } else {
                    broadcast(chatMsg); // 不排除发送者，让发送者也看到自己的消息
                }
                addHistory(chatMsg);

                // ===== AI 双模型协同检测（后台异步，不阻塞聊天） =====
                analyzeWithAI(chatContent, 'toxic', '聊天').then(aiResult => {
                    if (aiResult.detected) {
                        const muteMin = aiResult.confidence === 'high' ? 30 : 15;
                        info.mutedUntil = Date.now() + muteMin * 60000;
                        BIFE.stats.threatsBlocked++;
                        addDefenseLog({
                            action: 'AI协同拦截',
                            id: `#${id}`,
                            user: name,
                            detail: `${aiResult.detail} | ${chatContent.substring(0, 150)}`,
                            result: '已屏蔽并禁言',
                            aiModel: (aiResult.models || []).join(' + ')
                        });
                        send(ws, { type: 'error', message: '⚠ 发言含不良内容，已被屏蔽并自动禁言' });
                        broadcast({ type: 'system', message: `🔇 ${name} 因发言不当已被自动禁言` });
                        console.log(`[AI] 协同拦截 - #${id} ${name}: ${chatContent.substring(0, 100)} (${aiResult.models.join('+')})`);
                        broadcastUserList();
                    }
                    // 未检测到违规 → 记录放行日志
                    else {
                        addDefenseLog({
                            action: 'AI协同检测',
                            id: `#${id}`,
                            user: name,
                            detail: `${chatContent.substring(0, 100)} | ${aiResult.detail}`,
                            result: '检测通过 ✅',
                            aiModel: (aiResult.models || []).join(' + ')
                        });
                    }
                }).catch(() => {
                    // AI 不可用时记录日志
                    addDefenseLog({
                        action: 'AI检测',
                        id: `#${id}`,
                        user: name,
                        detail: chatContent.substring(0, 100),
                        result: 'AI引擎不可用',
                        risk: '低'
                    });
                });
                break;

            case 'private': {
                // BIFE: 私聊内容安全校验（先于target检查，拦截攻击内容）
                const pv = bifeValidate(msg.content, 5000, '私聊');
                if (pv) return send(ws, { type: 'error', message: pv.reason });
                const target = clients.get(msg.targetId);
                if (!target || target.ws.readyState !== 1) {
                    return send(ws, { type: 'error', message: `用户 #${msg.targetId} 不在线` });
                }
                // BIFE: 私聊速率限制
                const pCount = checkRateLimit('priv_' + ip);
                if (pCount > BIFE.rateLimit.maxPrivate) return send(ws, { type: 'error', message: '私聊发送过于频繁' });
                const pMsg = {
                    type: 'private', from: id, fromName: name, fromColor: info.color,
                    content: msg.content, time: new Date().toLocaleTimeString()
                };
                // 先发送私聊消息（不阻塞聊天）
                send(target.ws, pMsg);
                send(ws, { type: 'private_sent', to: msg.targetId, toName: target.name || '用户' + msg.targetId, content: msg.content, time: pMsg.time });
                // AI 双模型协同检测（后台异步，不阻塞私聊）
                BIFE.stats.aiScanned++;
                analyzeWithAI(msg.content, 'toxic', '私聊').then(aiResult => {
                    if (aiResult.detected) {
                        BIFE.stats.threatsBlocked++;
                        const muteMin = aiResult.confidence === 'high' ? 30 : 15;
                        info.mutedUntil = Date.now() + muteMin * 60000;
                        addDefenseLog({
                            action: 'AI协同拦截',
                            target: name,
                            detail: `违规私聊: ${msg.content.substring(0, 100)} | ${aiResult.detail}`,
                            result: '已屏蔽并禁言',
                            aiModel: (aiResult.models || []).join(' + ')
                        });
                        send(ws, { type: 'error', message: '⚠ 私聊内容违规，已被自动禁言' });
                        broadcast({ type: 'system', message: `🔇 ${name} 因私聊违规已被自动禁言` });
                        console.log(`[AI] 私聊拦截 - #${id} ${name}: ${msg.content.substring(0, 100)} (${aiResult.models.join('+')})`);
                        broadcastUserList();
                    }
                    // 未检测到违规 → 记录放行日志
                    else {
                        addDefenseLog({
                            action: 'AI协同检测',
                            target: name,
                            detail: `私聊通过: ${msg.content.substring(0, 100)} | ${aiResult.detail}`,
                            result: '检测通过 ✅',
                            aiModel: (aiResult.models || []).join(' + ')
                        });
                    }
                }).catch(() => {
                    addDefenseLog({
                        action: 'AI检测',
                        target: name,
                        detail: `私聊: ${msg.content.substring(0, 100)}`,
                        result: 'AI引擎不可用，已放行',
                        risk: '低'
                    });
                });
                break;
            }

            case 'set_name': {
                const old = name;
                const newName = (msg.name || '').trim();
                if (!newName) return send(ws, { type: 'error', message: '昵称不能为空' });
                if (newName.length > 20) return send(ws, { type: 'error', message: '昵称最长20个字符' });
                // 检查昵称是否已被其他用户使用
                for (const [otherId, other] of clients) {
                    if (otherId !== id && other.name === newName) {
                        return send(ws, { type: 'error', message: `昵称「${newName}」已被使用，请换一个` });
                    }
                }
                info.name = newName;
                clients.set(id, info);
                // ===== 绑定IP账号名称 =====
                const ipAcc = ipAccounts.get(ip);
                if (ipAcc) {
                    ipAcc.name = newName;
                    ipAcc.color = info.color;
                }
                console.log(`[~] #${id}: ${old || '(未命名)'} → ${newName}`);
                // 告知客户端昵称已生效
                send(ws, { type: 'name_accepted', name: newName });
                if (old) {
                    broadcast({ type: 'system', message: `${old} 改名为 ${newName}` });
                } else {
                    send(ws, { type: 'system', message: `欢迎 ${newName}！` });
                }
                broadcastUserList();
                break;
            }

            case 'set_status': {
                info.status = msg.status || 'online';
                broadcastUserList();
                break;
            }

            // ========= 房间 =========
            case 'create_room': {
                const roomName = (msg.name || '').trim();
                if (!roomName) return send(ws, { type: 'error', message: '房间名不能为空' });
                // BIFE: 房间名长度限制
                if (roomName.length > BIFE.maxRoomName) return send(ws, { type: 'error', message: `房间名最长${BIFE.maxRoomName}个字符` });
                const rv = bifeValidate(roomName, BIFE.maxRoomName, '房间名');
                if (rv) return send(ws, { type: 'error', message: rv.reason });
                if (rooms.has(roomName)) return send(ws, { type: 'error', message: '房间名已存在' });
                const roomPwd = msg.password || '';
                rooms.set(roomName, { members: new Set([id]), password: roomPwd });
                info.room = roomName;
                broadcast({ type: 'room_list', rooms: getRoomList() });
                broadcast({ type: 'system', message: `${name} 创建了房间「${roomName}」${roomPwd ? '🔒' : ''}` });
                send(ws, { type: 'room_joined', room: roomName });
                broadcastUserList();
                break;
            }

            case 'join_room': {
                const roomName = msg.name;
                if (!rooms.has(roomName)) return send(ws, { type: 'error', message: '房间不存在' });
                const room = rooms.get(roomName);
                if (room.password) {
                    // 防暴力破解检查
                    const pwdCheck = checkPwdRateLimit(ip);
                    if (pwdCheck.blocked) {
                        return send(ws, { type: 'error', message: `🔒 密码尝试过于频繁，请 ${pwdCheck.remaining} 秒后再试` });
                    }
                    if (room.password !== msg.password) {
                        recordPwdFail(ip);
                        return send(ws, { type: 'error', message: '🔒 房间密码错误' });
                    }
                    // 成功后清除失败记录
                    pwdFailMap.delete(ip);
                }
                // 离开旧房间
                if (info.room && rooms.has(info.room)) {
                    rooms.get(info.room).members.delete(id);
                    broadcastToRoom(info.room, { type: 'system', message: `${name} 离开了房间` });
                }
                info.room = roomName;
                room.members.add(id);
                send(ws, { type: 'room_joined', room: roomName });
                broadcastToRoom(roomName, { type: 'system', message: `${name} 加入了房间` });
                broadcastUserList();
                break;
            }

            case 'leave_room': {
                if (info.room && rooms.has(info.room)) {
                    rooms.get(info.room).members.delete(id);
                    broadcastToRoom(info.room, { type: 'system', message: `${name} 离开了房间` });
                    if (rooms.get(info.room).members.size === 0) {
                        rooms.delete(info.room);
                        broadcast({ type: 'room_list', rooms: getRoomList() });
                    }
                }
                info.room = '大厅';
                send(ws, { type: 'room_joined', room: '大厅' });
                broadcastUserList();
                break;
            }

            case 'get_rooms':
                send(ws, { type: 'room_list', rooms: getRoomList() });
                break;

            // ========= 文件分享（带AI内容检测） =========
            case 'file_share': {
                // BIFE: 文件共享安全检查
                const fv = bifeValidate(msg.fileName, BIFE.maxFileName, '文件名');
                if (fv) return send(ws, { type: 'error', message: fv.reason });
                const dv = bifeValidate(msg.data, BIFE.maxFileData, '文件数据');
                if (dv) return send(ws, { type: 'error', message: dv.reason });

                // AI 双模型协同检测（后台异步）
                const mediaInfo = `文件名:${msg.fileName} 类型:${msg.mime} 大小:${msg.fileSize}字节`;
                BIFE.stats.aiScanned++;
                analyzeWithAI(mediaInfo, 'media', '文件').then(aiMediaResult => {
                    if (aiMediaResult.detected) {
                        BIFE.stats.threatsBlocked++;
                        const muteMin = aiMediaResult.confidence === 'high' ? 30 : 15;
                        info.mutedUntil = Date.now() + muteMin * 60000;
                        addDefenseLog({
                            action: 'AI协同拦截',
                            target: name,
                            detail: `违规文件: ${msg.fileName} (${msg.mime}) | ${aiMediaResult.detail}`,
                            result: '已屏蔽并禁言',
                            aiModel: (aiMediaResult.models || []).join(' + ')
                        });
                        send(ws, { type: 'error', message: '⚠ 文件内容违规，已被屏蔽并自动禁言' });
                        broadcast({ type: 'system', message: `🔇 ${name} 因发送违规文件已被自动禁言` });
                        console.log(`[AI] 拦截文件 - #${id} ${name}: ${msg.fileName} (${aiMediaResult.models.join('+')})`);
                        broadcastUserList();
                        return;
                    }
                    // AI 检测通过 → 记录放行日志
                    addDefenseLog({
                        action: 'AI协同检测',
                        target: name,
                        detail: `文件通过: ${msg.fileName} ${msg.mime} | ${aiMediaResult.detail}`,
                        result: '检测通过 ✅',
                        aiModel: (aiMediaResult.models || []).join(' + ')
                    });
                }).catch(() => {
                    addDefenseLog({
                        action: 'AI检测',
                        target: name,
                        detail: `文件: ${msg.fileName} (${msg.mime})`,
                        result: 'AI引擎不可用，已放行',
                        risk: '低'
                    });
                });

                const fileMsg = {
                    type: 'file_share', id, name, color: info.color,
                    fileName: msg.fileName, fileSize: msg.fileSize,
                    data: msg.data, mime: msg.mime,
                    time: new Date().toLocaleTimeString()
                };
                broadcast(fileMsg);
                addHistory(fileMsg);
                break;
            }

            // ========= 游戏系统 =========
            case 'game_invite': {
                const gameType = msg.game;
                if (!GAME_HANDLERS[gameType]) return send(ws, { type: 'error', message: '未知游戏' });
                // 外挂检测: 游戏邀请频率
                if (detectCheat(id, info, 'join_game')) return send(ws, { type: 'error', message: '操作过于频繁' });
                const target = clients.get(msg.targetId);
                if (!target) return send(ws, { type: 'error', message: '用户不在线' });
                send(target.ws, {
                    type: 'game_invite', from: id, fromName: name,
                    game: gameType, gameName: GAME_HANDLERS[gameType].name
                });
                send(ws, { type: 'game_invite_sent', to: msg.targetId, game: gameType });
                break;
            }

            case 'game_accept': {
                const fromId = msg.from;
                const gameType = msg.game;
                const from = clients.get(fromId);
                const to = clients.get(id);
                if (!from || !to) return send(ws, { type: 'error', message: '对方已离线' });
                if (!GAME_HANDLERS[gameType]) return;
                // 外挂检测: 接受游戏频率
                if (detectCheat(id, info, 'join_game')) return send(ws, { type: 'error', message: '操作过于频繁' });
                const gameId = nextGameId++;
                const handler = GAME_HANDLERS[gameType];
                const state = handler.createState();
                const gameInfo = {
                    type: gameType,
                    state,
                    players: { [fromId]: from.name || '用户'+fromId, [id]: to.name || '用户'+id },
                    playerOrder: [fromId, id],
                    handler,
                    startTime: Date.now()
                };
                games.set(gameId, gameInfo);
                const startData = {
                    type: 'game_start',
                    gameId, game: gameType,
                    gameName: handler.name,
                    players: gameInfo.players,
                    playerOrder: gameInfo.playerOrder,
                    yourId: null // 各自填充
                };
                send(from.ws, { ...startData, yourId: fromId, state: JSON.parse(JSON.stringify(state)) });
                send(to.ws, { ...startData, yourId: id, state: JSON.parse(JSON.stringify(state)) });
                broadcast({ type: 'system', message: `${from.name || '#'+fromId} 和 ${to.name || '#'+id} 开始玩${handler.name}` });
                break;
            }

            case 'game_decline': {
                const from = clients.get(msg.from);
                if (from) send(from.ws, { type: 'game_declined', by: id, name });
                break;
            }

            case 'game_move': {
                const gi = games.get(msg.gameId);
                if (!gi) return send(ws, { type: 'error', message: '游戏不存在' });
                const playerIdx = gi.playerOrder.indexOf(id);
                if (playerIdx === -1) return;
                // 外挂检测: 操作频率/速度检查
                if (detectCheat(id, info, 'move')) return send(ws, { type: 'error', message: '操作过于频繁' });
                const result = gi.handler.handleMove(gi.state, playerIdx, msg.data, ws, id, gi);
                if (result) {
                    const playerNames = gi.playerOrder.map(pid => gi.players[pid] || '用户'+pid);
                    for (let i = 0; i < gi.playerOrder.length; i++) {
                        const pid = gi.playerOrder[i];
                        const p = clients.get(pid);
                        if (p) send(p.ws, { ...result, playerIndex: i, playerNames });
                    }
                    if (result.winner !== null && result.winner !== undefined) {
                        const winnerName = result.winner === -1 ? '平局' : (gi.players[gi.playerOrder[result.winner]] || '玩家' + (result.winner+1));
                        broadcast({ type: 'system', message: `游戏结束：${winnerName} 获胜！` });
                    }
                }
                break;
            }

            case 'game_leave': {
                const gi = games.get(msg.gameId);
                if (gi) {
                    const otherId = gi.playerOrder.find(pid => pid !== id);
                    if (otherId) {
                        const other = clients.get(otherId);
                        if (other) send(other.ws, { type: 'game_ended', reason: '对手离开了游戏' });
                    }
                    games.delete(msg.gameId);
                    broadcast({ type: 'system', message: `${name} 离开了游戏` });
                }
                break;
            }

            case 'game_rematch': {
                const gi = games.get(msg.gameId);
                if (!gi) return;
                gi.handler.resetState(gi.state);
                const state = gi.handler.createState();
                gi.state = state;
                const startData = {
                    type: 'game_start',
                    gameId: msg.gameId, game: gi.type,
                    gameName: gi.handler.name,
                    players: gi.players,
                    playerOrder: gi.playerOrder,
                    yourId: null,
                    state: JSON.parse(JSON.stringify(state))
                };
                for (const pid of gi.playerOrder) {
                    const p = clients.get(pid);
                    if (p) send(p.ws, { ...startData, yourId: pid });
                }
                break;
            }

            case 'game_rematch_req': {
                const gi = games.get(msg.gameId);
                if (gi) {
                    const otherId = gi.playerOrder.find(pid => pid !== id);
                    if (otherId) {
                        const other = clients.get(otherId);
                        if (other) send(other.ws, { type: 'game_rematch_req', from: id, fromName: name, gameId: msg.gameId });
                    }
                }
                break;
            }

            // ========= 图库 =========
            case 'get_gallery':
                // 简单返回预设表情
                send(ws, {
                    type: 'gallery',
                    emojis: ['😀','😂','🤣','😍','🥰','😎','🤩','😢','😡','🥳','🤔','🙄','😴','🤮','🥶','🤯','😈','👻','🎃','💀','☠️','👽','🤖','🎉','🎊','🎈','💪','👍','👎','👏','🙌','🤝','❤️','💔','🔥','⭐','🌟','✨','💯','✅','❌','❓','❗','🎮','💻','📱','⌨️','🖥️','📷','🎧','🏆','🥇','🥈','🥉','🎯','🎲','♟️','🎨','🎵','🎶','📢','🔔','💡','🔑','🗝️','📂','📁','📎','🖇️','📌','📍','✂️','🔒','🔓','🌍','🌎','🌏','🌈','☀️','🌙','⭐','⚡','☁️','❄️','🔥','🌊','🍕','🍔','🌭','🥤','☕','🍺','🍻','🍷','🧊','🍦','🍩','🍪','🎂','🍫','🍭','🍬']
                });
                break;

            // ========= get_history =========
            case 'get_history':
                send(ws, { type: 'history', messages: messageHistory.slice(-(msg.count || 50)) });
                break;
        }
    });

    ws.on('close', (code, reason) => {
        const disconnectedInfo = clients.get(id);
        // 减少IP并发计数
        const curIp = disconnectedInfo ? disconnectedInfo.ip : ip;
        const curCnt = ipConnectionCount.get(curIp) || 1;
        if (curCnt <= 1) ipConnectionCount.delete(curIp);
        else ipConnectionCount.set(curIp, curCnt - 1);
        if (!disconnectedInfo) return; // 已经清理过了
        console.log(`[-] #${id} (${disconnectedInfo.name || '未知'}) 断开 (code=${code}, reason=${reason.toString()})`);
        
        // 清理心跳定时器
        if (disconnectedInfo.heartbeatTimer) {
            clearInterval(disconnectedInfo.heartbeatTimer);
        }
        if (disconnectedInfo.heartbeatTimeoutTimer) {
            clearInterval(disconnectedInfo.heartbeatTimeoutTimer);
        }
        
        // 从 clients 中移除，但暂不广播"离开"
        clients.delete(id);
        // 清理房间（房间状态需要立即更新）
        if (disconnectedInfo.room && rooms.has(disconnectedInfo.room)) {
            rooms.get(disconnectedInfo.room).members.delete(id);
            if (rooms.get(disconnectedInfo.room).members.size === 0) {
                rooms.delete(disconnectedInfo.room);
                broadcast({ type: 'room_list', rooms: getRoomList() });
            }
        }
        // 清理游戏（立即清理，游戏不能等）
        for (const [gid, gi] of games) {
            if (gi.playerOrder.includes(id)) {
                const otherId = gi.playerOrder.find(pid => pid !== id);
                if (otherId) {
                    const other = clients.get(otherId);
                    if (other) send(other.ws, { type: 'game_ended', reason: '对手断开了连接' });
                }
                games.delete(gid);
            }
        }
        const disName = disconnectedInfo.name || '用户' + id;
        // 管理员直接断开，不做缓冲
        if (disconnectedInfo.admin) {
            console.log(`[-] #${id} (管理员 ${disName}) 断开`);
            return;
        }
        // 50秒缓冲：如果用户刷新页面/短暂离开后回来，不显示离开
        const ip = disconnectedInfo.ip;
        // 清除该 IP 之前的待清理记录（如果有）
        if (pendingDisconnect.has(ip)) {
            const old = pendingDisconnect.get(ip);
            clearTimeout(old.timer);
            pendingDisconnect.delete(ip);
        }
        const timer = setTimeout(() => {
            // 缓冲到期，真的广播"离开了"
            pendingDisconnect.delete(ip);
            broadcast({ type: 'leave', id, message: `${disName} 离开了`, onlineCount: clients.size });
            // 给管理员单独发更新
            for (const [aid, ainfo] of clients) {
                if (ainfo.admin && ainfo.ws.readyState === 1) {
                    send(ainfo.ws, { type: 'admin_info_result', data: buildAdminInfo() });
                }
            }
            broadcastUserList();
            console.log(`[-] #${id} 断开 (${disName}) [缓冲到期]`);
        }, 50000);
        pendingDisconnect.set(ip, { id, info: disconnectedInfo, timer });
        console.log(`[PENDING] #${id} (${disName}) 断开，50秒内重新连接将恢复`);
    });

    ws.on('error', (err) => {
        if (disconnectedInfo && !disconnectedInfo.admin) {
            console.log(`[WS_ERROR] #${id} (${disconnectedInfo.name || '未知'}): ${err.message || err}`);
        } else {
            console.log(`[WS_ERROR] #${id}: ${err.message || err}`);
        }
    });
});

// ============ HTTP API ============
app.get('/api/status', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress || '';
    const cleanIp = ip.replace(/^::ffff:/, '');
    if (bannedIps.has(cleanIp)) return res.status(403).json({ error: 'blocked' });
    res.json({
        status: 'running', uptime: Math.floor(process.uptime())
    });
});

app.get('/api/bife', (req, res) => {
    const ip = req.ip || req.socket.remoteAddress || '';
    const cleanIp = ip.replace(/^::ffff:/, '');
    if (bannedIps.has(cleanIp)) return res.status(403).json({ error: 'blocked' });
    res.json({
        version: BIFE.version,
        enabled: BIFE.enabled
    });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ============ 全局异常处理 ============
process.on('uncaughtException', (err) => {
    console.error(`[FATAL] 未捕获的异常: ${err.message}`);
    console.error(err.stack);
});
process.on('unhandledRejection', (reason) => {
    console.error(`[FATAL] 未处理的Promise拒绝: ${reason?.message || reason}`);
});

// HTTP服务器错误处理 — 防止端口冲突等情况导致服务器无声崩溃
server.on('error', (err) => {
    console.error(`[SERVER_ERROR] HTTP服务器错误: ${err.message}`);
    if (err.code === 'EADDRINUSE') {
        console.error(`[SERVER_ERROR] 端口 ${PORT} 已被占用，请先关闭占用该端口的程序`);
    }
});

server.listen(PORT, '0.0.0.0', () => {
    // 清除封禁和禁言列表
    loadBans();
    mutedUsers.clear();
    rateLimitMap.clear();
    clients.clear();
    pendingDisconnect.clear();
    
    const ip = getLocalIP();
    console.log('');
    console.log('══════════════════════════════════════════');
    console.log('  ☁️  云端多功能服务器 v2.0');
    console.log('══════════════════════════════════════════');
    console.log('  🛡️   BIFE防御盾 v' + BIFE.version + ' 已激活');
    console.log('  ╔══════════════════════════════════════╗');
    console.log('  ║   ██████╗ ██╗███████╗███████╗       ║');
    console.log('  ║   ██╔══██╗██║██╔════╝██╔════╝       ║');
    console.log('  ║   ██████╔╝██║█████╗  █████╗         ║');
    console.log('  ║   ██╔══██╗██║██╔══╝  ██╔══╝         ║');
    console.log('  ║   ██████╔╝██║██║     ██║            ║');
    console.log('  ║   ╚═════╝ ╚═╝╚═╝     ╚═╝            ║');
    console.log('  ╚══════════════════════════════════════╝');
    console.log('  ✅ 防护规则:');
    console.log('     • WebSocket maxPayload: ' + (BIFE.maxPayload / 1024) + 'KB');
    console.log('     • 房间名最大: ' + BIFE.maxRoomName + '字符');
    console.log('     • 文件数据最大: ' + (BIFE.maxFileData / 1024) + 'KB');
    console.log('     • 消息频率: ' + BIFE.rateLimit.maxMessages + '条/' + (BIFE.rateLimit.window / 1000) + '秒');
    console.log('     • 私聊频率: ' + BIFE.rateLimit.maxPrivate + '条/' + (BIFE.rateLimit.window / 1000) + '秒');
    console.log('     • 全类型内容检测: 已开启');
    console.log('  ✅ 心跳加固:');
    console.log('     • TCP keepalive: 15秒');
    console.log('     • Ping间隔: ' + (HEARTBEAT_INTERVAL / 1000) + '秒');
    console.log('     • 超时缓冲: ' + (HEARTBEAT_TIMEOUT / 1000) + '秒');
    console.log('  ' + (BIFE.ollama.enabled ? '🤖' : '💤') + ' Ollama AI智能分析: ' + (BIFE.ollama.enabled ? '已开启 (' + BIFE.ollama.models.filter(m => m.enabled).map(m => m.name).join(' + ') + ')' : '已关闭'));
    console.log('     API: ' + BIFE.ollama.url);
    console.log('  ✅ 已清除封禁列表、禁言列表和速率限制');
    console.log(`  本机:     http://localhost:${PORT}`);
    console.log(`  局域网:   http://${ip}:${PORT}`);
    console.log('──────────────────────────────────────────');
    console.log('  管理员后台:');
    console.log(`     http://localhost:${PORT}/admin.html`);
    console.log(`     http://${ip}:${PORT}/admin.html`);
    console.log('     账号: ' + AUTH_USERNAME + ' / 密码: ' + AUTH_PASSWORD);
    console.log('──────────────────────────────────────────');
    console.log('  功能：聊天 · 房间 · 文件 · 游戏');
    console.log('  🎮 在线游戏: 井字棋/五子棋/猜拳/猜数字/四子棋/猜单词');
    console.log('  离线游戏: 蛇/方块/扫雷/2048/数独/拼图/记忆翻牌等');
    console.log('──────────────────────────────────────────');
    console.log('  外网访问方式:');
    console.log(`  1. 端口映射: 路由器将 ${PORT} 端口映射到本机`);
    console.log(`  2. ngrok:    ngrok http ${PORT}  (临时)`);
    console.log('  3. frp:      配置 frpc 连接固定服务器');
    console.log('══════════════════════════════════════════');
});

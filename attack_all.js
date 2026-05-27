/**
 * 全能攻击测试脚本 - 测试 server.js 各项安全防护
 * 覆盖: DDoS/CC/TOP/暴力破解/注入/消息泛洪
 */
const WebSocket = require('ws');
const http = require('http');

const TARGET = 'ws://localhost:3000';
const API = 'http://localhost:3000';
const CONCURRENCY = 50;      // DDoS并发连接数
const FLOOD_MSGS = 30;       // CC消息泛洪数
const RAPID_RECONNECT = 30;  // TOP攻击快速重连次数

let attackLogs = [];
let totalConnections = 0;
let succeedConnections = 0;
let blockedCount = 0;
let errors = [];

function logAttack(name, result, detail) {
    const entry = `[${result === '✅' ? 'PASS' : '⚠️ BLOCKED'}] ${name}: ${detail}`;
    attackLogs.push(entry);
    console.log(entry);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function httpGet(path) { return new Promise((resolve) => { http.get(API + path, res => { let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve(d)); }).on('error', e => resolve(null)); }); }

// ============ 1. DDoS 连接洪泛测试 ============
async function testDDoSFLOOD() {
    console.log('\n═══ [1] DDoS 连接洪泛测试 ═══');
    const conns = [];
    const start = Date.now();
    for (let i = 0; i < CONCURRENCY; i++) {
        try {
            const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
            ws.on('open', () => { succeedConnections++; });
            ws.on('message', () => {});
            ws.on('error', (e) => { errors.push(e.message); });
            conns.push(ws);
            totalConnections++;
        } catch(e) { errors.push(e.message); }
    }
    await sleep(2000);
    const elapsed = Date.now() - start;
    logAttack('DDoS洪泛', succeedConnections > 10 ? '✅' : '⚠️', `${CONCURRENCY}并发连接, ${succeedConnections}个成功, 耗时${elapsed}ms`);
    // 清理
    conns.forEach(ws => { try { ws.close(); } catch(e){} });
}

// ============ 2. CC 消息泛洪测试 ============
async function testCCFlood() {
    console.log('\n═══ [2] CC 消息泛洪测试 ═══');
    const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
    await new Promise((resolve, reject) => {
        ws.on('open', resolve);
        ws.on('error', reject);
        setTimeout(() => reject('timeout'), 3000);
    }).catch(() => { logAttack('CC泛洪', '⚠️', '连接失败，无法测试'); return; });

    let blocked = false;
    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            if (msg.type === 'error' && msg.message.includes('频繁')) { blocked = true; }
        } catch(e) {}
    });

    const start = Date.now();
    for (let i = 0; i < FLOOD_MSGS; i++) {
        ws.send(JSON.stringify({ type: 'chat', content: `洪水消息 #${i}` }));
    }
    await sleep(3000);
    const elapsed = Date.now() - start;
    logAttack('CC消息泛洪', blocked ? '⚠️' : '✅', `${FLOOD_MSGS}条消息, 速率限制${blocked ? '已触发' : '未触发'}, 耗时${elapsed}ms`);
    try { ws.close(); } catch(e) {}
}

// ============ 3. TOP 快速断连测试 ============
async function testTOPAttack() {
    console.log('\n═══ [3] TOP 快速断连测试 ═══');
    let leakedTimers = 0;
    const start = Date.now();
    for (let i = 0; i < RAPID_RECONNECT; i++) {
        try {
            const ws = new WebSocket(TARGET, { handshakeTimeout: 1000 });
            await new Promise((resolve) => {
                ws.on('open', () => {
                    ws.close();
                    resolve();
                });
                ws.on('error', () => resolve());
                setTimeout(() => resolve(), 500);
            });
        } catch(e) {}
    }
    const elapsed = Date.now() - start;
    logAttack('TOP快速断连', '⚠️', `${RAPID_RECONNECT}次快速连接/断开, 耗时${elapsed}ms (潜在定时器泄漏)`);
    await sleep(1000);
}

// ============ 4. 暴力破解测试 ============
async function testBruteForce() {
    console.log('\n═══ [4] 暴力破解测试 ═══');
    const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
    await new Promise((resolve, reject) => {
        ws.on('open', resolve);
        ws.on('error', reject);
        setTimeout(() => reject('timeout'), 3000);
    }).catch(() => { logAttack('暴力破解', '⚠️', '连接失败'); return; });

    let blocked = false;
    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            if (msg.type === 'error' && (msg.message.includes('频繁') || msg.message.includes('错误'))) {
                if (msg.message.includes('频繁')) blocked = true;
            }
        } catch(e) {}
    });

    for (let i = 0; i < 15; i++) {
        ws.send(JSON.stringify({ type: 'auth', username: 'admin', password: 'wrong' + i }));
    }
    await sleep(2000);
    logAttack('暴力破解', blocked ? '⚠️' : '✅', `15次登录尝试, 速率限制${blocked ? '已触发' : '未触发'}`);
    try { ws.close(); } catch(e) {}
}

// ============ 5. SQL注入/XSS测试 ============
async function testInjection() {
    console.log('\n═══ [5] SQL注入/XSS/命令注入测试 ═══');
    const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
    let disconnected = false;
    await new Promise((resolve, reject) => {
        ws.on('open', resolve);
        ws.on('error', reject);
        setTimeout(() => reject('timeout'), 3000);
    }).catch(() => { logAttack('注入攻击', '⚠️', '连接失败'); return; });

    ws.on('close', (code) => { if (code === 4003) disconnected = true; });
    
    const payloads = [
        { type: 'chat', content: "1' OR '1'='1" },
        { type: 'chat', content: '<script>alert(1)</script>' },
        { type: 'chat', content: '; rm -rf /' },
        { type: 'chat', content: '${7*7}' },
        { type: 'chat', content: '../../../etc/passwd' },
    ];

    for (const p of payloads) {
        ws.send(JSON.stringify(p));
    }
    await sleep(2000);
    logAttack('注入攻击', disconnected ? '⚠️' : '✅', `5种注入payload, 连接${disconnected ? '已断开' : '正常'}`);
    try { ws.close(); } catch(e) {}
}

// ============ 6. 超大消息测试 ============
async function testLargeMessage() {
    console.log('\n═══ [6] 超大消息/内存耗尽测试 ═══');
    const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
    await new Promise((resolve, reject) => {
        ws.on('open', resolve);
        ws.on('error', reject);
        setTimeout(() => reject('timeout'), 3000);
    }).catch(() => { logAttack('超大消息', '⚠️', '连接失败'); return; });

    // 尝试发送接近 maxPayload (100KB) 的消息
    const bigContent = 'A'.repeat(95000);
    let errorReceived = false;
    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            if (msg.type === 'error') errorReceived = true;
        } catch(e) {}
    });
    ws.send(JSON.stringify({ type: 'chat', content: bigContent }));
    await sleep(2000);
    logAttack('超大消息', errorReceived ? '⚠️' : '⚠️', `95KB消息已发送 (可能被WS层或应用层拦截)`);
    try { ws.close(); } catch(e) {}
}

// ============ 7. API信息泄露测试 ============
async function testAPILeak() {
    console.log('\n═══ [7] API信息泄露测试 ═══');
    const status = await httpGet('/api/status');
    const bife = await httpGet('/api/bife');
    logAttack('API信息泄露', status ? '✅' : '⚠️', `/api/status 返回: ${status ? status.substring(0,80)+'...' : 'null'}`);
    logAttack('API信息泄露', bife ? '✅' : '⚠️', `/api/bife 返回: ${bife ? bife.substring(0,80)+'...' : 'null'}`);
}

// ============ 8. 文件炸弹测试 ============
async function testFileBomb() {
    console.log('\n═══ [8] 文件炸弹测试 ═══');
    const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
    await new Promise((resolve, reject) => {
        ws.on('open', resolve);
        ws.on('error', reject);
        setTimeout(() => reject('timeout'), 3000);
    }).catch(() => { logAttack('文件炸弹', '⚠️', '连接失败'); return; });

    // 发大量小文件，测试广播压力
    for (let i = 0; i < 10; i++) {
        ws.send(JSON.stringify({
            type: 'file_share',
            fileName: `bomb_${i}.txt`,
            fileSize: 1000,
            data: 'A'.repeat(8000),  // 8KB base64 → ~6KB real
            mime: 'text/plain'
        }));
    }
    await sleep(2000);
    logAttack('文件炸弹', '⚠️', `10个文件广播已发送, 检查服务器内存`);

    // 测试超大文件名
    ws.send(JSON.stringify({
        type: 'file_share',
        fileName: 'A'.repeat(500) + '.txt',
        fileSize: 100,
        data: 'test',
        mime: 'text/plain'
    }));
    await sleep(1000);
    logAttack('超长文件名', '⚠️', `500字符文件名已发送`);
    try { ws.close(); } catch(e) {}
}

// ============ 9. 房间创建Crack测试 ============
async function testRoomFlood() {
    console.log('\n═══ [9] 房间创建洪泛测试 ═══');
    const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
    await new Promise((resolve, reject) => {
        ws.on('open', resolve);
        ws.on('error', reject);
        setTimeout(() => reject('timeout'), 3000);
    }).catch(() => { logAttack('房间创建', '⚠️', '连接失败'); return; });

    let blocked = false;
    ws.on('message', (data) => {
        try { const m = JSON.parse(data.toString()); if (m.type === 'error') blocked = true; } catch(e){}
    });

    for (let i = 0; i < 20; i++) {
        ws.send(JSON.stringify({ type: 'create_room', name: `room_${i}`, password: '' }));
    }
    await sleep(2000);
    logAttack('房间创建洪泛', blocked ? '⚠️' : '✅', `20个房间创建请求, 速率限制${blocked ? '触发' : '未触发'}`);
    try { ws.close(); } catch(e) {}
}

// ============ 10. 恶意昵称测试 ============
async function testMaliciousName() {
    console.log('\n═══ [10] 恶意昵称测试 ═══');
    const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
    await new Promise((resolve, reject) => {
        ws.on('open', resolve);
        ws.on('error', reject);
        setTimeout(() => reject('timeout'), 3000);
    }).catch(() => { logAttack('恶意昵称', '⚠️', '连接失败'); return; });

    let blocked = false;
    ws.on('message', (data) => {
        try { const m = JSON.parse(data.toString()); if (m.type === 'error') blocked = true; } catch(e){}
    });

    // 空昵称、超长昵称、脚本昵称
    ws.send(JSON.stringify({ type: 'set_name', name: '' }));
    ws.send(JSON.stringify({ type: 'set_name', name: 'A'.repeat(50) }));
    ws.send(JSON.stringify({ type: 'set_name', name: '<script>alert(1)</script>' }));
    ws.send(JSON.stringify({ type: 'set_name', name: 'admin' }));

    await sleep(2000);
    logAttack('恶意昵称', blocked ? '⚠️' : '⚠️', `4种恶意昵称尝试, 验证长度/空值/XSS过滤`);
    try { ws.close(); } catch(e) {}
}

// ============ 主流程 ============
async function main() {
    console.log('═══════════════════════════════════════════');
    console.log('  ☢️  全能攻击测试 v1.0');
    console.log('  目标: ' + TARGET);
    console.log('═══════════════════════════════════════════\n');

    // 检查服务器是否在线
    const status = await httpGet('/');
    if (!status) {
        console.log('❌ 服务器不在线，请先启动服务器');
        return;
    }
    console.log('✅ 服务器在线，开始攻击测试\n');

    await testDDoSFLOOD();
    await sleep(1000);
    await testCCFlood();
    await sleep(500);
    await testTOPAttack();
    await sleep(500);
    await testBruteForce();
    await sleep(500);
    await testInjection();
    await sleep(500);
    await testLargeMessage();
    await sleep(500);
    await testAPILeak();
    await sleep(500);
    await testFileBomb();
    await sleep(500);
    await testRoomFlood();
    await sleep(500);
    await testMaliciousName();
    await sleep(500);

    // 汇总
    console.log('\n═══════════════════════════════════════════');
    console.log('  📊 攻击测试汇总');
    console.log('═══════════════════════════════════════════');
    console.log(`  总连接数: ${totalConnections}`);
    console.log(`  成功连接: ${succeedConnections}`);
    console.log(`  测试用例: 10个`);
    console.log('───────────────────────────────────────────');
    attackLogs.forEach(l => console.log('  ' + l));
    console.log('═══════════════════════════════════════════');
}

main().catch(console.error);

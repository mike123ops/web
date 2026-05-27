/**
 * BIFE 防御盾 v2.0 — 综合压力/攻击测试
 * 
 * 测试场景：
 *   1. TOP 攻击：慢速连接，不发送数据，保持打开
 *   2. DDoS 攻击：大量快速短连接
 *   3. CC 攻击：大量高频消息发送
 *   4. 超大Payload攻击：发送超大消息
 *   5. 暴力破解攻击：快速轮换密码尝试
 *   6. 消息洪泛攻击：海量不同内容消息
 */

const WebSocket = require('ws');
const http = require('http');

const TARGET = 'ws://127.0.0.1:3000/';
const HTTP_TARGET = 'http://127.0.0.1:3000/';
const STATS = { totalConns: 0, rejected: 0, accepted: 0, errors: 0, timedout: 0 };
let running = true;

function log(prefix, msg) {
    const t = new Date().toLocaleTimeString();
    process.stdout.write(`[${t}][${prefix}] ${msg}\n`);
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

// ============================================================
// 测试1: TOP 攻击 — 慢速连接，打开后不通信
// ============================================================
async function testTop(count = 100) {
    log('TOP', `启动 ${count} 个慢速连接（只连接不通信）...`);
    let opened = 0, failed = 0;
    const conns = [];
    for (let i = 0; i < count; i++) {
        if (!running) break;
        try {
            const ws = new WebSocket(TARGET, { handshakeTimeout: 5000 });
            ws.on('open', () => { opened++; STATS.accepted++; });
            ws.on('error', () => { failed++; STATS.rejected++; });
            ws.on('close', () => {});
            conns.push(ws);
        } catch(e) { failed++; }
    }
    await sleep(2000);
    log('TOP', `结果: 打开=${opened} 失败=${failed}`);
    log('TOP', `关闭 ${conns.length} 个慢速连接...`);
    conns.forEach(ws => { try { ws.close(); } catch(e) {} });
    await sleep(500);
    return { opened, failed };
}

// ============================================================
// 测试2: DDoS — 大量短连接洪泛
// ============================================================
async function testDdos(count = 200) {
    log('DDOS', `启动 ${count} 个快速短连接...`);
    let accepted = 0, rejected = 0, errors = 0;
    const start = Date.now();
    
    // 分批并行，每批50个
    const batchSize = 50;
    for (let b = 0; b < Math.ceil(count / batchSize); b++) {
        if (!running) break;
        const batch = [];
        const n = Math.min(batchSize, count - b * batchSize);
        for (let i = 0; i < n; i++) {
            batch.push(new Promise(resolve => {
                try {
                    const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
                    ws.on('open', () => { 
                        accepted++; STATS.accepted++;
                        ws.close();
                        resolve('accepted');
                    });
                    ws.on('error', () => { 
                        rejected++; STATS.rejected++;
                        resolve('rejected');
                    });
                    ws.on('unexpected-response', () => {
                        rejected++; STATS.rejected++;
                        resolve('rejected');
                    });
                    setTimeout(() => { resolve('timeout'); STATS.timedout++; }, 3000);
                } catch(e) { errors++; resolve('error'); }
            }));
        }
        await Promise.all(batch);
        await sleep(100); // 批次间隔
    }
    
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    log('DDOS', `结果(${elapsed}s): 接受=${accepted} 拒绝=${rejected} 超时=${STATS.timedout} 错误=${errors}`);
    return { accepted, rejected, errors };
}

// ============================================================
// 测试3: CC 攻击 — 连接后快速发送大量消息
// ============================================================
async function testCc(connections = 10, messages = 50) {
    log('CC', `启动 CC 攻击: ${connections}个连接 × 每人${messages}条消息...`);
    let sent = 0, blocked = 0;
    const start = Date.now();
    
    const workers = [];
    for (let c = 0; c < connections; c++) {
        workers.push(new Promise(resolve => {
            try {
                const ws = new WebSocket(TARGET, { handshakeTimeout: 5000 });
                let localSent = 0, localBlocked = 0;
                ws.on('open', () => {
                    // 先登录
                    ws.send(JSON.stringify({type:'auth', username:`cc_test_${c}`, password:''}));
                    // 疯狂发消息
                    for (let i = 0; i < messages; i++) {
                        try {
                            ws.send(JSON.stringify({type:'chat', content:`CC攻击测试消息 #${i} from worker ${c} - 这是一条CC攻击测试消息，用于模拟僵尸网络发送垃圾消息洪泛服务器`}));
                            localSent++;
                        } catch(e) { localBlocked++; }
                    }
                });
                ws.on('message', d => {
                    const m = JSON.parse(d);
                    if (m.type === 'error') localBlocked++;
                });
                ws.on('error', () => {});
                ws.on('close', () => {
                    sent += localSent;
                    blocked += localBlocked;
                    resolve({ sent: localSent, blocked: localBlocked });
                });
                setTimeout(() => {
                    try { ws.close(); } catch(e) {}
                    sent += localSent;
                    blocked += localBlocked;
                    resolve({ sent: localSent, blocked: localBlocked });
                }, 5000);
            } catch(e) {
                resolve({ sent: 0, blocked: 0 });
            }
        }));
    }
    await Promise.all(workers);
    
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    log('CC', `结果(${elapsed}s): 发送=${sent} 被拦截=${blocked}`);
    return { sent, blocked };
}

// ============================================================
// 测试4: 超大Payload攻击
// ============================================================
async function testPayload() {
    log('PAYLOAD', '启动超大Payload攻击测试...');
    
    const sizes = [
        { name: '100KB (边界)', size: 100 * 1024 },
        { name: '200KB (超标)', size: 200 * 1024 },
        { name: '500KB (大包)', size: 500 * 1024 },
        { name: '1MB (超大)', size: 1024 * 1024 },
    ];
    
    for (const s of sizes) {
        if (!running) break;
        const bigData = 'A'.repeat(s.size);
        log('PAYLOAD', `尝试发送 ${s.name} 消息...`);
        try {
            const ws = new WebSocket(TARGET, { handshakeTimeout: 5000 });
            const result = await new Promise(resolve => {
                ws.on('open', () => {
                    try {
                        ws.send(JSON.stringify({type:'chat', content:bigData}), err => {
                            resolve(err ? '发送失败:' + err.message : '发送成功');
                            try { ws.close(); } catch(e) {}
                        });
                    } catch(e) {
                        resolve('异常:' + e.message);
                        try { ws.close(); } catch(e) {}
                    }
                });
                ws.on('error', e => resolve('连接错误:' + e.message));
                ws.on('unexpected-response', () => resolve('HTTP拒绝'));
                setTimeout(() => resolve('超时'), 5000);
            });
            log('PAYLOAD', `  ${s.name}: ${result}`);
        } catch(e) {
            log('PAYLOAD', `  ${s.name}: 异常 - ${e.message}`);
        }
        await sleep(500);
    }
}

// ============================================================
// 测试5: 暴力破解攻击
// ============================================================
async function testBruteForce() {
    log('BRUTE', '启动暴力破解攻击测试...');
    let attempts = 0, blocked = 0;
    const start = Date.now();
    
    for (let i = 0; i < 30; i++) {
        if (!running) break;
        try {
            const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
            await new Promise(resolve => {
                ws.on('open', () => {
                    ws.send(JSON.stringify({type:'auth', username:'admin', password:`wrong_pwd_${i}`}));
                    attempts++;
                });
                ws.on('message', d => {
                    const m = JSON.parse(d);
                    if (m.type === 'error' && m.message.includes('频繁')) {
                        blocked++;
                    }
                    try { ws.close(); } catch(e) {}
                    resolve();
                });
                ws.on('error', () => { resolve(); });
                setTimeout(() => { try { ws.close(); } catch(e) {} resolve(); }, 2000);
            });
        } catch(e) {}
        await sleep(50);
    }
    
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    log('BRUTE', `结果(${elapsed}s): 尝试=${attempts} 被拦截=${blocked}`);
    return { attempts, blocked };
}

// ============================================================
// 测试6: 消息洪泛（CC加强版）- 大量连接同时密集发消息
// ============================================================
async function testFlood(connections = 20) {
    log('FLOOD', `启动消息洪泛: ${connections}个连接同时密集发送...`);
    let totalSent = 0, totalBlocked = 0;
    const start = Date.now();
    
    const workers = [];
    for (let c = 0; c < connections; c++) {
        workers.push(new Promise(resolve => {
            let sent = 0, blocked = 0;
            try {
                const ws = new WebSocket(TARGET, { handshakeTimeout: 3000 });
                ws.on('open', () => {
                    ws.send(JSON.stringify({type:'auth', username:`flood_${c}`, password:''}));
                    // 瞬间喷射50条
                    for (let i = 0; i < 50; i++) {
                        try {
                            ws.send(JSON.stringify({type:'chat', content:`洪水消息_${c}_${i}_测试洪水攻击服务器稳定性看看能不能打垮这个聊天服务器`}));
                            sent++;
                        } catch(e) { blocked++; }
                    }
                });
                ws.on('message', d => {
                    const m = JSON.parse(d);
                    if (m.type === 'error') blocked++;
                });
                ws.on('error', () => {});
                ws.on('close', () => resolve({sent,blocked}));
                setTimeout(() => { try{ws.close()}catch(e){} resolve({sent,blocked}); }, 4000);
            } catch(e) {
                resolve({sent:0,blocked:0});
            }
        }));
    }
    await Promise.all(workers);
    workers.forEach((r, i) => { totalSent += r.sent; totalBlocked += r.blocked; });
    
    // Wait for workers and aggregate
    const results = await Promise.all(workers);
    results.forEach(r => { totalSent += r.sent; totalBlocked += r.blocked; });
    
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    log('FLOOD', `结果(${elapsed}s): 发送=${totalSent} 被拦截=${totalBlocked}`);
    return { totalSent, totalBlocked };
}

// ============================================================
// 主测试流程
// ============================================================
async function main() {
    console.log('═══════════════════════════════════════════════');
    console.log('  BIFE 防御盾 v2.0 — 压力/攻击测试套件');
    console.log('  目标: ' + TARGET);
    console.log('  时间: ' + new Date().toLocaleString());
    console.log('═══════════════════════════════════════════════\n');

    // 先检测服务器是否在线
    log('INIT', '检查服务器状态...');
    try {
        const res = await new Promise((resolve, reject) => {
            http.get(HTTP_TARGET + 'api/status', r => {
                let d = '';
                r.on('data', c => d += c);
                r.on('end', () => resolve(JSON.parse(d)));
            }).on('error', reject);
        });
        log('INIT', `在线用户: ${res.online}, 状态: ${res.status}`);
    } catch(e) {
        log('INIT', `服务器不可达: ${e.message}`);
        log('INIT', '跳过测试');
        return;
    }

    // ===== 测试1: TOP 攻击 =====
    console.log('\n--- [测试1] TOP 攻击（慢速连接保持） ---');
    const topResult = await testTop(150);
    
    // 冷却
    await sleep(2000);
    
    // ===== 测试2: DDoS 短连接洪泛 =====
    console.log('\n--- [测试2] DDoS 短连接洪泛 ---');
    const ddosResult = await testDdos(300);
    
    // 冷却
    await sleep(2000);
    
    // ===== 测试5: 暴力破解 =====
    console.log('\n--- [测试3] 暴力破解登录 ---');
    const bruteResult = await testBruteForce();
    
    // 冷却
    await sleep(1000);
    
    // ===== 测试4: 超大Payload =====
    console.log('\n--- [测试4] 超大Payload攻击 ---');
    await testPayload();
    
    // 冷却
    await sleep(1000);
    
    // ===== CC攻击 =====
    console.log('\n--- [测试5] CC 攻击（高速消息） ---');
    const ccResult = await testCc(8, 30);

    // 冷却
    await sleep(1000);
    
    // ===== 消息洪泛 =====
    console.log('\n--- [测试6] 消息洪泛攻击 ---');
    const floodResult = await testFlood(15);
    
    // ===== 报告 =====
    console.log('\n═══════════════════════════════════════════════');
    console.log('  测试报告');
    console.log('═══════════════════════════════════════════════');
    console.log(`  TOP攻击:     ${topResult.opened} 连接存活 / ${topResult.failed} 连接失败`);
    console.log(`  DDoS洪泛:    ${ddosResult.accepted} 接受 / ${ddosResult.rejected} 拒绝 / ${STATS.timedout} 超时`);
    console.log(`  暴力破解:    ${bruteResult.attempts} 尝试 / ${bruteResult.blocked} 被拦截`);
    console.log(`  CC攻击:      ${ccResult.sent} 发送 / ${ccResult.blocked} 被拦截`);
    console.log(`  消息洪泛:    ${floodResult.totalSent} 发送 / ${floodResult.totalBlocked} 被拦截`);
    console.log('');
    
    // 再次检查服务器是否活着
    try {
        const res2 = await new Promise((resolve, reject) => {
            http.get(HTTP_TARGET + 'api/status', r => {
                let d = '';
                r.on('data', c => d += c);
                r.on('end', () => resolve(JSON.parse(d)));
            }).on('error', reject);
        });
        log('RESULT', `服务器状态: 在线 (${res2.online}用户), 存活检测: ✅`);
    } catch(e) {
        log('RESULT', `服务器状态: 离线, 存活检测: ❌ ${e.message}`);
    }
    
    console.log('\n测试完成');
}

main().catch(e => {
    console.error('主流程异常:', e);
    process.exit(1);
});

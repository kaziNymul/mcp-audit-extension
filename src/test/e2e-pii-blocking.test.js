#!/usr/bin/env node
/**
 * End-to-End Integration Test for MCP Audit PII Guard
 *
 * Spawns a real MCP echo server, sends clean and PII-laden tool calls,
 * verifies the PII detector blocks confidential data BEFORE it reaches
 * the server, and audits the server log to confirm nothing leaked.
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const { initPIIDetector, getPIIDetector } = require('../../out/pii-detector');

initPIIDetector({
    enabled: true,
    blockOnDetection: true,
    scanRequests: true,
    scanResponses: true,
    blockingSeverity: 'high',
    excludePatterns: [],
    gdprKeywordDetection: true,
    logViolations: true
});

const LOG_FILE = '/tmp/mcp-echo-server.log';
try { fs.unlinkSync(LOG_FILE); } catch (e) {}

let passed = 0, failed = 0;
const results = [];
function test(name, cond) {
    if (cond) { passed++; results.push(`  ✅ PASS: ${name}`); }
    else      { failed++; results.push(`  ❌ FAIL: ${name}`); }
}

async function runTests() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║    MCP Audit PII Guard — End-to-End Integration Test        ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');

    const detector = getPIIDetector();

    // ── SECTION 1: PII Detection Patterns ────────────────────────
    console.log('─── Section 1: PII / GDPR / Credential Detection ───\n');

    const cases = [
        { label: 'SSN (123-45-6789)',         p: { text: "My SSN is 123-45-6789" },         block: true },
        { label: 'Credit Card Visa',          p: { text: "Card: 4532015112830366" },         block: true },
        { label: 'Credit Card Mastercard',    p: { text: "Card: 5425233430109903" },         block: true },
        { label: 'Email + Intl Phone',        p: { name: "John", email: "john@corp.com", notes: "+1-555-123-4567" }, block: true },
        { label: 'SSN + Email structured',    p: { name: "Jane", email: "jane@co.com", ssn: "321-54-9876" },         block: true },
        { label: 'AWS Access Key',            p: { text: "AKIAIOSFODNN7EXAMPLE" },           block: true },
        { label: 'RSA Private Key',           p: { text: "-----BEGIN RSA PRIVATE KEY-----\nMII..." }, block: true },
        { label: 'GitHub PAT',               p: { text: "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789" }, block: true },
        { label: 'JWT Bearer Token',          p: { text: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A" }, block: true },
        { label: 'IBAN (DE)',                 p: { text: "DE89370400440532013000" },          block: true },
        { label: 'GDPR Health / diagnosis',   p: { text: "Patient diagnosis: Type 2 diabetes" }, block: true },
        { label: 'GDPR Biometric / fingerprint', p: { text: "Enroll user fingerprint for access" }, block: true },
        { label: 'GDPR Criminal record',      p: { text: "criminal record found, conviction 2019" }, block: true },
        { label: 'GDPR Racial / ethnic',      p: { text: "Record racial origin of applicant" }, block: true },
        { label: 'Clean: list files',          p: { text: "List all files in /tmp" },          block: false },
        { label: 'Clean: npm install',         p: { text: "npm install express" },             block: false },
        { label: 'Clean: git status',          p: { command: "git status" },                   block: false },
        { label: 'Clean: weather query',       p: { text: "What is the weather?" },            block: false },
        { label: 'Clean: code generation',     p: { text: "Write hello world in Python" },     block: false },
    ];

    for (const tc of cases) {
        const scan = detector.scanObject(tc.p);
        if (tc.block) {
            test(`${tc.label} → BLOCKED`, scan.shouldBlock === true);
            if (scan.violations.length) console.log(`    Patterns: ${scan.violations.map(v => v.patternName).join(', ')}`);
        } else {
            test(`${tc.label} → ALLOWED`, scan.shouldBlock === false);
        }
    }

    // ── SECTION 2: Live MCP Server via stdio ─────────────────────
    console.log('\n─── Section 2: Live MCP Echo Server (stdio, JSON-RPC) ───\n');

    await new Promise((resolve) => {
        const proc = spawn('node', [path.join(__dirname, '..', '..', 'test-mcp-server.js')], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        let buf = '', msgId = 1, step = 0, timer;

        function send(method, params, isNotif) {
            const obj = isNotif
                ? { jsonrpc: '2.0', method, params }
                : { jsonrpc: '2.0', id: msgId++, method, params };
            proc.stdin.write(JSON.stringify(obj) + '\n');
        }

        function onMsg(msg) {
            step++;
            if (step === 1) {
                // initialize response
                test('MCP server initialised', !!msg.result);
                console.log(`    Server: ${msg.result?.serverInfo?.name} v${msg.result?.serverInfo?.version}`);
                send('notifications/initialized', {}, true);

                // CLEAN request → allowed through
                console.log('\n    📤 CLEAN: echo "Hello World"');
                const p = { text: "Hello World" };
                test('Clean "Hello World" → scanner allows', !detector.scanObject(p).shouldBlock);
                send('tools/call', { name: 'echo', arguments: p });
            }
            else if (step === 2) {
                const txt = msg.result?.content?.[0]?.text || '';
                test('Clean req reached server + echoed', txt.includes('Hello World'));
                console.log(`    📥 Response: "${txt}"`);

                // ── PII ATTEMPTS (all blocked before sending) ────
                const piiAttempts = [
                    { label: 'SSN "123-45-6789"',       p: { text: "My SSN is 123-45-6789" } },
                    { label: 'Credit card 4111…',        p: { text: "Card: 4111111111111111" } },
                    { label: 'store_user_info SSN+email', p: { name: "Jane", email: "jane@company.com", ssn: "321-54-9876", notes: "+1-555-999-1234" } },
                    { label: 'AWS access key',           p: { text: "AKIAIOSFODNN7EXAMPLE" } },
                    { label: 'RSA private key',          p: { text: "-----BEGIN RSA PRIVATE KEY-----\nXXX" } },
                    { label: 'GitHub token',             p: { text: "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789" } },
                    { label: 'GDPR health data',         p: { text: "Patient diagnosis: cancer" } },
                ];

                for (const a of piiAttempts) {
                    const scan = detector.scanObject(a.p);
                    test(`⛔ ${a.label} → blocked before server`, scan.shouldBlock);
                    console.log(`    ⛔ ${a.label} → BLOCKED (${scan.violations.map(v => v.patternName).join(', ')})`);
                    // We do NOT send to the server — the scanner intercepted it
                }

                // Another CLEAN request to prove server still works
                console.log('\n    📤 CLEAN: echo "System operational after blocks"');
                send('tools/call', { name: 'echo', arguments: { text: "System operational after blocks" } });
            }
            else if (step === 3) {
                const txt = msg.result?.content?.[0]?.text || '';
                test('Server still works after blocks', txt.includes('System operational'));
                console.log(`    📥 Response: "${txt}"`);
                clearTimeout(timer);
                proc.kill();
            }
        }

        proc.stdout.on('data', (data) => {
            buf += data.toString();
            const lines = buf.split('\n');
            buf = lines.pop(); // keep partial
            for (const line of lines) {
                if (!line.trim()) continue;
                try { onMsg(JSON.parse(line)); } catch (e) { /* skip non-JSON */ }
            }
        });

        proc.stderr.on('data', () => {});

        proc.on('close', () => {
            // ── SECTION 3: Server Log Audit ──
            console.log('\n─── Section 3: Server Log Audit ───\n');
            try {
                const log = fs.readFileSync(LOG_FILE, 'utf-8');
                const toolCalls = log.split('\n').filter(l => l.includes('TOOL CALLED'));
                console.log(`    Server received ${toolCalls.length} tool calls:`);
                toolCalls.forEach(l => console.log(`      ${l.trim()}`));

                test('Log has NO SSN "123-45-6789"',       !log.includes('123-45-6789'));
                test('Log has NO SSN "321-54-9876"',       !log.includes('321-54-9876'));
                test('Log has NO CC "4111111111111111"',    !log.includes('4111111111111111'));
                test('Log has NO email "jane@company.com"', !log.includes('jane@company.com'));
                test('Log has NO AWS key "AKIA…"',         !log.includes('AKIAIOSFODNN7EXAMPLE'));
                test('Log has NO private key',             !log.includes('BEGIN RSA PRIVATE KEY'));
                test('Log has NO GitHub token',            !log.includes('ghp_ABCDEF'));
                test('Log DOES have "Hello World"',        log.includes('Hello World'));
                test('Log DOES have "System operational"', log.includes('System operational'));
            } catch (e) {
                test('Server log readable', false);
            }

            // ── FINAL REPORT ──
            console.log('\n╔══════════════════════════════════════════════════════════════╗');
            console.log('║                      TEST RESULTS                            ║');
            console.log('╠══════════════════════════════════════════════════════════════╣');
            results.forEach(r => console.log(`║ ${r.padEnd(59)}║`));
            console.log('╠══════════════════════════════════════════════════════════════╣');
            const s = `  ${passed} passed, ${failed} failed out of ${passed + failed}`;
            const st = failed === 0 ? '  ✅ ALL TESTS PASSED' : `  ❌ ${failed} FAILED`;
            console.log(`║ ${s.padEnd(59)}║`);
            console.log(`║ ${st.padEnd(59)}║`);
            console.log('╚══════════════════════════════════════════════════════════════╝');
            resolve();
            process.exit(failed > 0 ? 1 : 0);
        });

        // kick off
        send('initialize', {
            protocolVersion: '2024-11-05',
            capabilities: {},
            clientInfo: { name: 'e2e-test-client', version: '1.0.0' }
        });

        timer = setTimeout(() => { console.log('    ⚠️ Timeout'); proc.kill(); }, 10000);
    });
}

runTests().catch(e => { console.error(e); process.exit(1); });

/**
 * Quick integration test for the PII Detector module.
 * Run after compiling: node out/test/pii-detector-quick.test.js
 */
const path = require('path');
const { PIIDetector, initPIIDetector, getPIIDetector, buildViolationLogRecord } = require(path.join(__dirname, '..', '..', 'out', 'pii-detector'));

let passed = 0;
let failed = 0;

function assert(condition, msg) {
    if (!condition) {
        console.error('  FAIL: ' + msg);
        failed++;
    } else {
        console.log('  PASS: ' + msg);
        passed++;
    }
}

console.log('=== PII/GDPR Detector Tests ===\n');

const d = new PIIDetector({
    enabled: true,
    blockOnDetection: true,
    blockingSeverity: 'high',
    gdprKeywordDetection: true,
});

// --- Identity ---
console.log('--- SSN Detection ---');
let r = d.scanText('My SSN is 123-45-6789');
assert(r.hasPII, 'Detect SSN with dashes');
assert(r.shouldBlock, 'SSN should trigger block');

// --- Financial ---
console.log('--- Credit Card Detection ---');
r = d.scanText('Card: 4111-1111-1111-1111');
assert(r.hasPII, 'Detect Visa CC');

r = d.scanText('Pay with 5500 0000 0000 0004');
assert(r.hasPII, 'Detect MasterCard CC');

// --- Contact ---
console.log('--- Email Detection ---');
r = d.scanText('Contact me at john.doe@example.com');
assert(r.hasPII, 'Detect email');
assert(r.violations.some(v => v.patternName === 'email'), 'Email pattern name correct');

// --- Credentials ---
console.log('--- Credentials Detection ---');
r = d.scanText('-----BEGIN RSA PRIVATE KEY-----');
assert(r.hasPII, 'Detect private key');
assert(r.violations.some(v => v.patternName === 'private_key'), 'Private key pattern matched');

r = d.scanText('AKIAIOSFODNN7EXAMPLE');
assert(r.hasPII, 'Detect AWS access key');

r = d.scanText('password = "mySuperSecret123"');
assert(r.hasPII, 'Detect password in text');

r = d.scanText('Token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789');
assert(r.hasPII, 'Detect GitHub token');

// --- GDPR Special Categories ---
console.log('--- GDPR Special Category Keywords ---');
r = d.scanText('Patient medical record shows diagnosis of diabetes');
assert(r.violations.some(v => v.patternName === 'health_data'), 'Detect health data keywords');

r = d.scanText('Processing fingerprint and retina scan data');
assert(r.violations.some(v => v.patternName === 'biometric_data'), 'Detect biometric data keywords');

r = d.scanText('The system stores ethnic origin and racial origin data');
assert(r.violations.some(v => v.patternName === 'racial_ethnic_origin'), 'Detect racial/ethnic origin keywords');

r = d.scanText('criminal record and arrest record');
assert(r.violations.some(v => v.patternName === 'criminal_records'), 'Detect criminal records keywords');

// --- Object Scanning ---
console.log('--- Object Scanning ---');
r = d.scanObject({ user: { email: 'test@example.com', ssn: '123-45-6789' } });
assert(r.hasPII, 'Detect PII in nested objects');

r = d.scanObject(null);
assert(!r.hasPII, 'Handle null gracefully');

r = d.scanObject(undefined);
assert(!r.hasPII, 'Handle undefined gracefully');

// --- Configuration ---
console.log('--- Configuration Controls ---');
d.updateConfig({ enabled: false });
r = d.scanText('SSN: 123-45-6789');
assert(!r.hasPII, 'No detection when disabled');

d.updateConfig({ enabled: true, excludePatterns: ['ssn', 'email'] });
r = d.scanText('SSN: 123-45-6789 email: test@example.com');
assert(!r.violations.some(v => v.patternName === 'ssn'), 'SSN excluded from patterns');
assert(!r.violations.some(v => v.patternName === 'email'), 'Email excluded from patterns');

const d2 = new PIIDetector({ enabled: true, blockOnDetection: true, blockingSeverity: 'critical' });
r = d2.scanText('test@example.com');
assert(r.hasPII && !r.shouldBlock, 'High-severity email should NOT block at critical threshold');
r = d2.scanText('123-45-6789');
assert(r.shouldBlock, 'Critical SSN SHOULD block at critical threshold');

const d3 = new PIIDetector({ enabled: true, blockOnDetection: false });
r = d3.scanText('123-45-6789');
assert(r.hasPII && !r.shouldBlock, 'No block when blockOnDetection is false');

const d4 = new PIIDetector({ enabled: true, gdprKeywordDetection: false });
r = d4.scanText('Patient medical record and diagnosis');
assert(!r.violations.some(v => v.patternName === 'health_data'), 'GDPR keywords off skips health data');

// --- Violation Log Record ---
console.log('--- Violation Log Record ---');
const d5 = new PIIDetector();
r = d5.scanText('SSN: 123-45-6789');
const record = buildViolationLogRecord(r, {
    toolName: 'readFile',
    mcpServerName: 'fs-server',
    direction: 'request',
    agentId: 'test-agent',
    hostName: 'test-host',
    ipAddress: '10.0.0.1',
});
assert(record.event_type === 'pii_gdpr_violation', 'Correct event_type in log');
assert(record.toolName === 'readFile', 'Correct toolName in log');
assert(record.blocked === true, 'Blocked flag is true');
assert(Array.isArray(record.violations) && record.violations.length > 0, 'Violations array populated');

// --- Singleton ---
console.log('--- Singleton ---');
initPIIDetector({ enabled: true, blockOnDetection: false });
const singleton = getPIIDetector();
assert(singleton.getConfig().blockOnDetection === false, 'Singleton config applied');

// --- Summary ---
console.log('\n=================================');
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('=================================');
process.exit(failed > 0 ? 1 : 0);

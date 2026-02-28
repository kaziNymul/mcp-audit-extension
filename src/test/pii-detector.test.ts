import { expect } from 'chai';
import { PIIDetector, PIIDetectorConfig, initPIIDetector, getPIIDetector, buildViolationLogRecord } from '../pii-detector';

describe('PIIDetector', () => {
    let detector: PIIDetector;

    beforeEach(() => {
        detector = new PIIDetector({
            enabled: true,
            blockOnDetection: true,
            scanRequests: true,
            scanResponses: true,
            blockingSeverity: 'high',
            excludePatterns: [],
            customPatterns: [],
            gdprKeywordDetection: true,
            logViolations: true,
        });
    });

    // ─── SSN Detection ──────────────────────────────────────────────

    describe('SSN Detection', () => {
        it('should detect US SSN with dashes', () => {
            const result = detector.scanText('My SSN is 123-45-6789');
            expect(result.hasPII).to.be.true;
            expect(result.shouldBlock).to.be.true;
            const ssn = result.violations.find(v => v.patternName === 'ssn');
            expect(ssn).to.not.be.undefined;
            expect(ssn!.severity).to.equal('critical');
        });

        it('should not false positive on random text', () => {
            const result = detector.scanText('Hello world, how are you today?');
            // May still match some patterns like phone, but no SSN
            const ssn = result.violations.find(v => v.patternName === 'ssn');
            expect(ssn).to.be.undefined;
        });
    });

    // ─── Credit Card Detection ──────────────────────────────────────

    describe('Credit Card Detection', () => {
        it('should detect Visa card numbers', () => {
            const result = detector.scanText('Card: 4111-1111-1111-1111');
            expect(result.hasPII).to.be.true;
            const visa = result.violations.find(v => v.patternName === 'credit_card_visa');
            expect(visa).to.not.be.undefined;
        });

        it('should detect MasterCard numbers', () => {
            const result = detector.scanText('Pay with 5500 0000 0000 0004');
            expect(result.hasPII).to.be.true;
            const mc = result.violations.find(v => v.patternName === 'credit_card_mastercard');
            expect(mc).to.not.be.undefined;
        });

        it('should detect Amex numbers', () => {
            const result = detector.scanText('Amex: 3782-822463-10005');
            expect(result.hasPII).to.be.true;
            const amex = result.violations.find(v => v.patternName === 'credit_card_amex');
            expect(amex).to.not.be.undefined;
        });
    });

    // ─── Email Detection ────────────────────────────────────────────

    describe('Email Detection', () => {
        it('should detect email addresses', () => {
            const result = detector.scanText('Contact me at john.doe@example.com');
            expect(result.hasPII).to.be.true;
            const email = result.violations.find(v => v.patternName === 'email');
            expect(email).to.not.be.undefined;
        });
    });

    // ─── Credentials Detection ──────────────────────────────────────

    describe('Credentials Detection', () => {
        it('should detect API keys in text', () => {
            const result = detector.scanText('api_key = sk_live_abc123def456ghi789jkl012');
            expect(result.hasPII).to.be.true;
            const apiKey = result.violations.find(v => v.patternName === 'api_key_generic');
            expect(apiKey).to.not.be.undefined;
        });

        it('should detect private key headers', () => {
            const result = detector.scanText('-----BEGIN RSA PRIVATE KEY-----\nMIIE...');
            expect(result.hasPII).to.be.true;
            const pk = result.violations.find(v => v.patternName === 'private_key');
            expect(pk).to.not.be.undefined;
        });

        it('should detect AWS access keys', () => {
            const result = detector.scanText('AWS key: AKIAIOSFODNN7EXAMPLE');
            expect(result.hasPII).to.be.true;
            const aws = result.violations.find(v => v.patternName === 'aws_access_key');
            expect(aws).to.not.be.undefined;
        });

        it('should detect passwords in plain text', () => {
            const result = detector.scanText('password = "mySuperSecret123"');
            expect(result.hasPII).to.be.true;
            const pwd = result.violations.find(v => v.patternName === 'password_in_text');
            expect(pwd).to.not.be.undefined;
        });

        it('should detect GitHub tokens', () => {
            const result = detector.scanText('Token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789');
            expect(result.hasPII).to.be.true;
            const gh = result.violations.find(v => v.patternName === 'github_token');
            expect(gh).to.not.be.undefined;
        });
    });

    // ─── IBAN Detection ─────────────────────────────────────────────

    describe('IBAN Detection', () => {
        it('should detect IBAN numbers', () => {
            const result = detector.scanText('Account IBAN: DE89 3704 0044 0532 0130 00');
            expect(result.hasPII).to.be.true;
            const iban = result.violations.find(v => v.patternName === 'iban');
            expect(iban).to.not.be.undefined;
        });
    });

    // ─── GDPR Special Category Keywords ─────────────────────────────

    describe('GDPR Special Category Detection', () => {
        it('should detect health/medical data keywords', () => {
            const result = detector.scanText('Patient medical record shows diagnosis of diabetes');
            expect(result.hasPII).to.be.true;
            const health = result.violations.find(v => v.patternName === 'health_data');
            expect(health).to.not.be.undefined;
            expect(health!.category).to.equal('gdpr_special');
        });

        it('should detect biometric data keywords', () => {
            const result = detector.scanText('Processing fingerprint and retina scan data');
            expect(result.hasPII).to.be.true;
            const bio = result.violations.find(v => v.patternName === 'biometric_data');
            expect(bio).to.not.be.undefined;
        });

        it('should detect racial/ethnic origin keywords', () => {
            const result = detector.scanText('The system stores ethnic origin and racial origin data');
            expect(result.hasPII).to.be.true;
            const race = result.violations.find(v => v.patternName === 'racial_ethnic_origin');
            expect(race).to.not.be.undefined;
        });

        it('should detect criminal records keywords', () => {
            const result = detector.scanText('Background check includes criminal record and arrest record');
            expect(result.hasPII).to.be.true;
            const crim = result.violations.find(v => v.patternName === 'criminal_records');
            expect(crim).to.not.be.undefined;
        });
    });

    // ─── Object Scanning ────────────────────────────────────────────

    describe('Object Scanning', () => {
        it('should scan nested objects for PII', () => {
            const obj = {
                user: {
                    name: 'John Doe',
                    email: 'john@example.com',
                    ssn: '123-45-6789',
                },
            };
            const result = detector.scanObject(obj);
            expect(result.hasPII).to.be.true;
            expect(result.violations.length).to.be.greaterThan(0);
        });

        it('should handle null/undefined gracefully', () => {
            expect(detector.scanObject(null).hasPII).to.be.false;
            expect(detector.scanObject(undefined).hasPII).to.be.false;
        });
    });

    // ─── Configuration ──────────────────────────────────────────────

    describe('Configuration', () => {
        it('should not scan when disabled', () => {
            detector.updateConfig({ enabled: false });
            const result = detector.scanText('SSN: 123-45-6789');
            expect(result.hasPII).to.be.false;
        });

        it('should exclude specified patterns', () => {
            detector.updateConfig({ excludePatterns: ['ssn', 'email'] });
            const result = detector.scanText('SSN: 123-45-6789 email: test@example.com');
            const ssn = result.violations.find(v => v.patternName === 'ssn');
            const email = result.violations.find(v => v.patternName === 'email');
            expect(ssn).to.be.undefined;
            expect(email).to.be.undefined;
        });

        it('should respect blocking severity threshold', () => {
            detector.updateConfig({ blockingSeverity: 'critical' });
            // Email is 'high' severity — should not trigger block
            const emailResult = detector.scanText('test@example.com');
            expect(emailResult.hasPII).to.be.true;
            expect(emailResult.shouldBlock).to.be.false;

            // SSN is 'critical' severity — should block
            const ssnResult = detector.scanText('123-45-6789');
            expect(ssnResult.hasPII).to.be.true;
            expect(ssnResult.shouldBlock).to.be.true;
        });

        it('should not block when blockOnDetection is false', () => {
            detector.updateConfig({ blockOnDetection: false });
            const result = detector.scanText('SSN: 123-45-6789');
            expect(result.hasPII).to.be.true;
            expect(result.shouldBlock).to.be.false;
        });

        it('should disable GDPR keyword detection when configured', () => {
            detector.updateConfig({ gdprKeywordDetection: false });
            const result = detector.scanText('Patient medical record and diagnosis');
            const health = result.violations.find(v => v.patternName === 'health_data');
            expect(health).to.be.undefined;
        });
    });

    // ─── Singleton / Init ───────────────────────────────────────────

    describe('Singleton', () => {
        it('should initialize and return detector via singleton', () => {
            const det = initPIIDetector({ enabled: true, blockOnDetection: false });
            const retrieved = getPIIDetector();
            expect(retrieved.getConfig().blockOnDetection).to.be.false;
        });
    });

    // ─── Violation Log Record ───────────────────────────────────────

    describe('buildViolationLogRecord', () => {
        it('should build a properly structured violation log', () => {
            const scanResult = detector.scanText('SSN: 123-45-6789, email: test@example.com');
            const record = buildViolationLogRecord(scanResult, {
                toolName: 'readFile',
                mcpServerName: 'fs-server',
                direction: 'request',
                agentId: 'test-agent',
                hostName: 'test-host',
                ipAddress: '10.0.0.1',
            });

            expect(record.event_type).to.equal('pii_gdpr_violation');
            expect(record.toolName).to.equal('readFile');
            expect(record.mcpServerName).to.equal('fs-server');
            expect(record.direction).to.equal('request');
            expect((record.violations as any[]).length).to.be.greaterThan(0);
        });
    });
});

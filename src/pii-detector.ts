/**
 * PII / GDPR / Confidential Data Detection and Blocking Module
 *
 * Scans text content for Personally Identifiable Information (PII),
 * GDPR-sensitive data, and other confidential information patterns.
 * When a violation is detected the request/response can be blocked
 * and a violation event is emitted for audit logging.
 */

import { logger } from './logger';

// ─── Pattern Definitions ────────────────────────────────────────────────

export interface PIIPattern {
    name: string;
    category: PIICategory;
    regex: RegExp;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
}

export type PIICategory =
    | 'identity'
    | 'financial'
    | 'contact'
    | 'health'
    | 'biometric'
    | 'gdpr_special'
    | 'credentials'
    | 'location';

export interface PIIViolation {
    patternName: string;
    category: PIICategory;
    severity: string;
    description: string;
    matchCount: number;
    /** Redacted sample (first few chars + masking) */
    redactedSample: string;
}

export interface PIIScanResult {
    hasPII: boolean;
    violations: PIIViolation[];
    shouldBlock: boolean;
    summary: string;
}

// ─── Built-in PII Regex Patterns ────────────────────────────────────────

const BUILTIN_PATTERNS: PIIPattern[] = [
    // === Identity Documents ===
    {
        name: 'ssn',
        category: 'identity',
        regex: /\b\d{3}-\d{2}-\d{4}\b/g,
        severity: 'critical',
        description: 'US Social Security Number',
    },
    {
        name: 'ssn_no_dashes',
        category: 'identity',
        regex: /\b(?!000|666|9\d{2})\d{9}\b/g,
        severity: 'high',
        description: 'US SSN without dashes (9-digit)',
    },
    {
        name: 'uk_nino',
        category: 'identity',
        regex: /\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b/gi,
        severity: 'critical',
        description: 'UK National Insurance Number',
    },
    {
        name: 'passport_number',
        category: 'identity',
        regex: /\b[A-Z]{1,2}\d{6,9}\b/g,
        severity: 'high',
        description: 'Passport Number pattern',
    },
    {
        name: 'drivers_license',
        category: 'identity',
        regex: /\b[A-Z]{1,2}\d{4,8}\b/g,
        severity: 'medium',
        description: 'Drivers License Number pattern',
    },

    // === Financial ===
    {
        name: 'credit_card_visa',
        category: 'financial',
        regex: /\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
        severity: 'critical',
        description: 'Visa Credit Card Number',
    },
    {
        name: 'credit_card_mastercard',
        category: 'financial',
        regex: /\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
        severity: 'critical',
        description: 'MasterCard Credit Card Number',
    },
    {
        name: 'credit_card_amex',
        category: 'financial',
        regex: /\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b/g,
        severity: 'critical',
        description: 'American Express Credit Card Number',
    },
    {
        name: 'iban',
        category: 'financial',
        regex: /\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){1,7}[\dA-Z]{1,4}\b/g,
        severity: 'critical',
        description: 'IBAN (International Bank Account Number)',
    },
    {
        name: 'swift_bic',
        category: 'financial',
        regex: /\b[A-Z]{6}[A-Z2-9][A-NP-Z0-9](?:[A-Z0-9]{3})?\b/g,
        severity: 'high',
        description: 'SWIFT/BIC code',
    },
    {
        name: 'us_bank_routing',
        category: 'financial',
        regex: /\b(?:0[1-9]|[12]\d|3[0-2])\d{7}\b/g,
        severity: 'high',
        description: 'US Bank Routing Number (ABA)',
    },

    // === Contact Information ===
    {
        name: 'email',
        category: 'contact',
        regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
        severity: 'high',
        description: 'Email Address',
    },
    {
        name: 'phone_international',
        category: 'contact',
        regex: /\b\+?[1-9]\d{0,2}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}\b/g,
        severity: 'medium',
        description: 'Phone Number (international format)',
    },
    {
        name: 'phone_us',
        category: 'contact',
        regex: /\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
        severity: 'medium',
        description: 'US Phone Number',
    },

    // === Network / Location ===
    {
        name: 'ipv4_address',
        category: 'location',
        regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
        severity: 'medium',
        description: 'IPv4 Address',
    },
    {
        name: 'ipv6_address',
        category: 'location',
        regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
        severity: 'medium',
        description: 'IPv6 Address',
    },

    // === Credentials / Secrets ===
    {
        name: 'api_key_generic',
        category: 'credentials',
        regex: /\b(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|secret[_-]?key|auth[_-]?token)[\s]*[:=]\s*["']?[A-Za-z0-9_\-./+]{16,}["']?\b/gi,
        severity: 'critical',
        description: 'API Key or Token',
    },
    {
        name: 'private_key',
        category: 'credentials',
        regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
        severity: 'critical',
        description: 'Private Key block',
    },
    {
        name: 'aws_access_key',
        category: 'credentials',
        regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
        severity: 'critical',
        description: 'AWS Access Key ID',
    },
    {
        name: 'github_token',
        category: 'credentials',
        regex: /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/g,
        severity: 'critical',
        description: 'GitHub Personal Access Token',
    },
    {
        name: 'jwt_token',
        category: 'credentials',
        regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
        severity: 'high',
        description: 'JWT Token',
    },
    {
        name: 'password_in_text',
        category: 'credentials',
        regex: /\b(?:password|passwd|pwd)[\s]*[:=]\s*["']?[^\s"']{6,}["']?\b/gi,
        severity: 'critical',
        description: 'Password in plain text',
    },

    // === Health / Medical (GDPR Special Category) ===
    {
        name: 'date_of_birth',
        category: 'health',
        regex: /\b(?:dob|date[_\s]of[_\s]birth|birth[_\s]?date)[\s]*[:=]\s*["']?\d{1,4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,4}["']?\b/gi,
        severity: 'high',
        description: 'Date of Birth',
    },
];

// ─── GDPR Special Category Keyword Patterns ─────────────────────────────
// These detect mentions of GDPR Article 9 special category data in context

const GDPR_SPECIAL_KEYWORDS: { name: string; keywords: string[]; severity: 'critical' | 'high' | 'medium'; description: string }[] = [
    {
        name: 'health_data',
        keywords: [
            'medical record', 'diagnosis', 'patient id', 'health condition',
            'prescription', 'medical history', 'blood type', 'allergy',
            'treatment plan', 'clinical trial', 'icd-10', 'icd-9',
            'hospital number', 'nhs number', 'health insurance',
            'mental health', 'disability status',
        ],
        severity: 'critical',
        description: 'Health / Medical data (GDPR Art. 9)',
    },
    {
        name: 'biometric_data',
        keywords: [
            'fingerprint', 'retina scan', 'face recognition', 'voice print',
            'biometric', 'iris scan', 'palm print', 'dna sample',
            'genetic data', 'facial geometry',
        ],
        severity: 'critical',
        description: 'Biometric data (GDPR Art. 9)',
    },
    {
        name: 'racial_ethnic_origin',
        keywords: [
            'racial origin', 'ethnic origin', 'ethnicity', 'race data',
        ],
        severity: 'critical',
        description: 'Racial or ethnic origin data (GDPR Art. 9)',
    },
    {
        name: 'political_opinions',
        keywords: [
            'political opinion', 'political affiliation', 'party membership',
            'political belief',
        ],
        severity: 'high',
        description: 'Political opinions data (GDPR Art. 9)',
    },
    {
        name: 'religious_beliefs',
        keywords: [
            'religious belief', 'religion data', 'philosophical belief',
            'religious affiliation',
        ],
        severity: 'high',
        description: 'Religious or philosophical beliefs (GDPR Art. 9)',
    },
    {
        name: 'trade_union',
        keywords: [
            'trade union membership', 'union member', 'labor union',
        ],
        severity: 'high',
        description: 'Trade union membership (GDPR Art. 9)',
    },
    {
        name: 'sexual_orientation',
        keywords: [
            'sexual orientation', 'sex life data', 'gender identity data',
        ],
        severity: 'critical',
        description: 'Sexual orientation / sex life data (GDPR Art. 9)',
    },
    {
        name: 'criminal_records',
        keywords: [
            'criminal record', 'criminal conviction', 'criminal offense',
            'arrest record', 'court record', 'felony',
        ],
        severity: 'critical',
        description: 'Criminal records data (GDPR Art. 10)',
    },
];

// ─── Configuration ──────────────────────────────────────────────────────

export interface PIIDetectorConfig {
    /** Master switch for PII detection */
    enabled: boolean;
    /** Block requests/responses when PII is found */
    blockOnDetection: boolean;
    /** Scan MCP tool request parameters */
    scanRequests: boolean;
    /** Scan MCP tool response data */
    scanResponses: boolean;
    /** Minimum severity to trigger blocking: critical, high, medium, low */
    blockingSeverity: 'critical' | 'high' | 'medium' | 'low';
    /** Pattern names to exclude from detection (false positives) */
    excludePatterns: string[];
    /** Additional custom regex patterns */
    customPatterns: PIIPattern[];
    /** Enable GDPR special category keyword detection */
    gdprKeywordDetection: boolean;
    /** Log violations to forwarders (Splunk etc.) even if not blocking */
    logViolations: boolean;
}

const DEFAULT_CONFIG: PIIDetectorConfig = {
    enabled: true,
    blockOnDetection: true,
    scanRequests: true,
    scanResponses: true,
    blockingSeverity: 'high',
    excludePatterns: [],
    customPatterns: [],
    gdprKeywordDetection: true,
    logViolations: true,
};

const SEVERITY_ORDER: Record<string, number> = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3,
};

// ─── Detector Class ─────────────────────────────────────────────────────

let detectorInstance: PIIDetector | null = null;

export class PIIDetector {
    private config: PIIDetectorConfig;
    private patterns: PIIPattern[];

    constructor(config?: Partial<PIIDetectorConfig>) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.patterns = this.buildPatternList();
    }

    /** Rebuild the active pattern list from built-in + custom, minus excluded */
    private buildPatternList(): PIIPattern[] {
        const excluded = new Set(this.config.excludePatterns.map(p => p.toLowerCase()));

        const builtIn = BUILTIN_PATTERNS.filter(
            p => !excluded.has(p.name.toLowerCase())
        );

        const custom = (this.config.customPatterns || []).filter(
            p => !excluded.has(p.name.toLowerCase())
        );

        return [...builtIn, ...custom];
    }

    /** Update configuration at runtime */
    updateConfig(config: Partial<PIIDetectorConfig>): void {
        this.config = { ...this.config, ...config };
        this.patterns = this.buildPatternList();
    }

    /** Get current configuration */
    getConfig(): PIIDetectorConfig {
        return { ...this.config };
    }

    // ── Core Scanning ───────────────────────────────────────────────────

    /**
     * Scan arbitrary text content for PII violations.
     */
    scanText(text: string): PIIScanResult {
        if (!this.config.enabled || !text || text.length === 0) {
            return { hasPII: false, violations: [], shouldBlock: false, summary: '' };
        }

        const violations: PIIViolation[] = [];

        // 1. Regex-based pattern matching
        for (const pattern of this.patterns) {
            // Reset lastIndex for global regex
            pattern.regex.lastIndex = 0;

            const matches: string[] = [];
            let match: RegExpExecArray | null;
            while ((match = pattern.regex.exec(text)) !== null) {
                matches.push(match[0]);
            }

            if (matches.length > 0) {
                violations.push({
                    patternName: pattern.name,
                    category: pattern.category,
                    severity: pattern.severity,
                    description: pattern.description,
                    matchCount: matches.length,
                    redactedSample: redactValue(matches[0]),
                });
            }
        }

        // 2. GDPR special-category keyword detection
        if (this.config.gdprKeywordDetection) {
            const lowerText = text.toLowerCase();
            for (const kw of GDPR_SPECIAL_KEYWORDS) {
                const matchedKeywords = kw.keywords.filter(k => lowerText.includes(k));
                if (matchedKeywords.length > 0) {
                    violations.push({
                        patternName: kw.name,
                        category: 'gdpr_special',
                        severity: kw.severity,
                        description: kw.description,
                        matchCount: matchedKeywords.length,
                        redactedSample: matchedKeywords[0],
                    });
                }
            }
        }

        // 3. Determine whether to block
        const blockingThreshold = SEVERITY_ORDER[this.config.blockingSeverity] ?? SEVERITY_ORDER['high'];
        const shouldBlock =
            this.config.blockOnDetection &&
            violations.some(v => SEVERITY_ORDER[v.severity] >= blockingThreshold);

        const summary = violations.length > 0
            ? `Detected ${violations.length} PII/GDPR violation(s): ${violations
                  .map(v => `${v.description} (${v.severity}, ${v.matchCount} match(es))`)
                  .join('; ')}`
            : '';

        return {
            hasPII: violations.length > 0,
            violations,
            shouldBlock,
            summary,
        };
    }

    /**
     * Scan a structured object (e.g. tool call params or result) by
     * serialising it to JSON and scanning the text.
     */
    scanObject(obj: unknown): PIIScanResult {
        if (obj === null || obj === undefined) {
            return { hasPII: false, violations: [], shouldBlock: false, summary: '' };
        }

        let text: string;
        if (typeof obj === 'string') {
            text = obj;
        } else {
            try {
                text = JSON.stringify(obj);
            } catch {
                return { hasPII: false, violations: [], shouldBlock: false, summary: '' };
            }
        }

        return this.scanText(text);
    }

    /** Convenience: is PII detection enabled? */
    isEnabled(): boolean {
        return this.config.enabled;
    }

    /** Should we scan requests? */
    shouldScanRequests(): boolean {
        return this.config.enabled && this.config.scanRequests;
    }

    /** Should we scan responses? */
    shouldScanResponses(): boolean {
        return this.config.enabled && this.config.scanResponses;
    }

    /** Should violations be logged to forwarders? */
    shouldLogViolations(): boolean {
        return this.config.logViolations;
    }
}

// ─── Singleton Access ───────────────────────────────────────────────────

export function initPIIDetector(config?: Partial<PIIDetectorConfig>): PIIDetector {
    detectorInstance = new PIIDetector(config);
    logger.info(`PII/GDPR Detector initialised. Enabled: ${detectorInstance.isEnabled()}, ` +
        `Blocking: ${detectorInstance.getConfig().blockOnDetection}, ` +
        `Severity threshold: ${detectorInstance.getConfig().blockingSeverity}`);
    return detectorInstance;
}

export function getPIIDetector(): PIIDetector {
    if (!detectorInstance) {
        // Lazy-init with defaults so callers never get null
        detectorInstance = new PIIDetector();
    }
    return detectorInstance;
}

// ─── Helpers ────────────────────────────────────────────────────────────

/** Redact a matched value for safe logging – show first 3 chars + mask */
function redactValue(value: string): string {
    if (value.length <= 4) return '****';
    return value.substring(0, 3) + '*'.repeat(Math.min(value.length - 3, 10));
}

/**
 * Build a violation log record suitable for forwarding to Splunk / SIEM.
 */
export function buildViolationLogRecord(
    scanResult: PIIScanResult,
    context: {
        toolName: string;
        mcpServerName: string;
        direction: 'request' | 'response';
        agentId?: string;
        hostName: string;
        ipAddress?: string;
    }
): Record<string, unknown> {
    return {
        event_type: 'pii_gdpr_violation',
        blocked: scanResult.shouldBlock,
        direction: context.direction,
        toolName: context.toolName,
        mcpServerName: context.mcpServerName,
        agentId: context.agentId,
        hostName: context.hostName,
        ipAddress: context.ipAddress,
        timestamp: new Date().toJSON(),
        violationCount: scanResult.violations.length,
        violations: scanResult.violations.map(v => ({
            pattern: v.patternName,
            category: v.category,
            severity: v.severity,
            description: v.description,
            matchCount: v.matchCount,
            redactedSample: v.redactedSample,
        })),
        summary: scanResult.summary,
    };
}

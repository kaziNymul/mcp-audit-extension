# End-to-End Prompt: Copilot PII Guard Extension

> Copy and use this entire prompt with an AI coding assistant to build the extension from scratch.

---

## PROMPT START

Build a VS Code extension called **"Copilot PII Guard"** that intercepts ALL prompts going from the developer's IDE to GitHub Copilot models (inline completions, Chat, Agent mode, Edit mode, Plan mode) and **blocks/redacts confidential data before it leaves the machine**.

---

### 1. OBJECTIVE

Create a VS Code extension that:
- Sits as a **transparent proxy** between VS Code and GitHub Copilot's API endpoints
- Scans every outbound request (prompt, file context, terminal output, workspace files sent as context) for PII, credentials, secrets, and GDPR-sensitive data
- **Blocks or redacts** confidential data BEFORE it reaches GitHub's servers
- Works across ALL Copilot interaction modes: inline completion, Chat panel, Agent mode (`@workspace`), Edit mode, and Plan mode
- Shows real-time notifications when data is blocked
- Logs all violations for compliance/audit
- Requires ZERO configuration out of the box
- **Starts blocking IMMEDIATELY on install** — no setup, no config, no onboarding wizard
- Developer installs → extension activates on VS Code startup → proxy starts → blocking is live
- Must be completely invisible until it blocks something (no welcome screens, no "getting started" steps)

---

### 1.1 CRITICAL REQUIREMENT: INSTALL-AND-FORGET

**This is the #1 requirement.** The moment a developer installs this extension from the marketplace:

1. Extension activates automatically on VS Code startup (`onStartupFinished`)
2. Local proxy server starts silently on `127.0.0.1` (random available port)
3. VS Code's `http.proxy` setting is auto-configured to route through the proxy
4. All PII/secret/GDPR detection patterns are loaded with blocking mode ON by default
5. Every Copilot request (inline, chat, agent, edit, plan) is scanned from that moment
6. **The developer does NOT need to:**
   - Run any command
   - Open any settings
   - Click any button
   - Configure any API key
   - Restart VS Code (activation happens on current session)
   - Read any documentation
7. The only time the developer sees the extension is when it BLOCKS something — a notification appears: `"⛔ PII Guard: Blocked SSN from reaching Copilot"`
8. A small shield icon `🛡️` in the status bar is the only persistent UI — green = active, shows block count on hover

**First-run behavior:**
```typescript
export async function activate(context: vscode.ExtensionContext) {
  const isFirstRun = !context.globalState.get('initialized');
  
  // ALWAYS do these on every activation (not just first run):
  // 1. Start proxy
  const proxyPort = await startLocalProxy();
  
  // 2. Configure VS Code to route through proxy
  await autoConfigureProxy(proxyPort, context);
  
  // 3. Initialize scanner with ALL patterns enabled
  const scanner = new ConfidentialDataScanner({
    piiPatterns: true,
    secretPatterns: true,
    gdprKeywords: true,
    entropyDetection: true,
    fileTypeRules: true,
    mode: 'block', // DEFAULT: block, not warn
  });
  
  // 4. Register all interception hooks
  registerProxyInterceptor(scanner);
  registerChatParticipantGuard(scanner);
  registerInlineCompletionGuard(scanner);
  registerDocumentScanner(scanner);
  registerTerminalMonitor(scanner);
  
  // 5. Show status bar
  createStatusBarItem(context);
  
  // 6. First run: show ONE subtle notification, then never again
  if (isFirstRun) {
    context.globalState.update('initialized', true);
    vscode.window.showInformationMessage(
      '🛡️ Copilot PII Guard is active. Confidential data will be blocked automatically.',
      'OK'
    );
  }
}
```

**Key design principle:** The extension must behave like an antivirus — always on, always scanning, requires no user action to provide protection.

---

### 2. ARCHITECTURE

```
Developer types prompt / Copilot reads file context
        │
        ▼
┌─────────────────────────────┐
│   VS Code Editor Context    │
│  (active file, selections,  │
│   open tabs, terminal)      │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│  INTERCEPTION LAYER         │
│  (this extension)           │
│                             │
│  ┌───────────────────────┐  │
│  │ PII/Secret Scanner    │  │
│  │ • Regex patterns      │  │
│  │ • GDPR keywords       │  │
│  │ • Entropy detection   │  │
│  │ • File-type awareness │  │
│  └───────────┬───────────┘  │
│              │              │
│  ┌───────────▼───────────┐  │
│  │ Decision Engine       │  │
│  │ • Block entirely      │  │
│  │ • Redact & pass       │  │
│  │ • Allow with warning  │  │
│  └───────────┬───────────┘  │
│              │              │
│  ┌───────────▼───────────┐  │
│  │ Audit Logger          │  │
│  │ • Local file log      │  │
│  │ • Splunk HEC          │  │
│  │ • VS Code output      │  │
│  └───────────────────────┘  │
└──────────┬──────────────────┘
           │
           ▼ (clean/redacted data only)
┌─────────────────────────────┐
│  GitHub Copilot API         │
│  (api.github.com/copilot)   │
└─────────────────────────────┘
```

---

### 3. INTERCEPTION METHODS (implement ALL of these)

#### Method A: HTTP Proxy Interception (Primary)
- Set `http.proxy` in VS Code settings to route Copilot traffic through a local proxy
- Create a local HTTPS proxy server (on `127.0.0.1:<random-port>`) inside the extension
- The proxy intercepts requests to these Copilot endpoints:
  - `https://api.github.com/copilot_internal/*`
  - `https://copilot-proxy.githubusercontent.com/*`
  - `https://api.githubcopilot.com/*`
  - `https://default.exp-tas.com/*` (telemetry)
- For each intercepted request:
  1. Parse the JSON body
  2. Extract prompt text, file contents, and context snippets
  3. Run PII/secret scanner on all text fields
  4. If violations found → redact the data OR return an empty/error response
  5. If clean → forward to the real Copilot endpoint
- Use `http-proxy-middleware` or `node-http-proxy` for proxying
- Handle HTTPS with self-signed certificates or use `http.proxyStrictSSL: false`

#### Method B: VS Code Chat Participant API (Chat/Agent modes)
- Register a `ChatParticipant` that wraps Copilot interactions
- Use `vscode.chat.createChatParticipant()` API
- Intercept the user's prompt text via `ChatRequest.prompt`
- Intercept attached context via `ChatRequest.references` (files, selections, terminal output)
- Scan all content before the LLM processes it
- If PII found: respond with a warning message instead of forwarding to the model

#### Method C: Document Content Pre-scan
- Use `vscode.workspace.onDidOpenTextDocument` and `vscode.workspace.onDidChangeTextDocument`
- Maintain a real-time map of which open documents contain PII
- When Copilot requests context (via inline completion), the proxy knows which file regions to redact
- Specifically scan:
  - `.env`, `.env.local`, `.env.production` files
  - Config files (`config.json`, `settings.yaml`, `appsettings.json`)
  - Any file containing patterns matching secrets

#### Method D: Inline Completion Provider Override
- Register an `InlineCompletionItemProvider` with higher priority
- Hook into `vscode.languages.registerInlineCompletionItemProvider`
- When triggered, scan the current document context that would be sent to Copilot
- If the surrounding code contains PII/secrets, either:
  - Strip the sensitive lines from context before Copilot sees them
  - Block the completion entirely with a status bar warning

#### Method E: Clipboard & Terminal Monitoring
- Monitor `vscode.env.clipboard.readText()` for paste operations containing PII
- Watch terminal output via `vscode.window.onDidWriteTerminalData` 
- Terminal output is sent as context in Agent mode — scan it before Copilot reads it

---

### 4. PII / SECRET DETECTION ENGINE

Implement a `ConfidentialDataScanner` class with these detection categories:

#### 4.1 Personal Identifiable Information (PII)
```typescript
const PII_PATTERNS = {
  // US Social Security Number
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
  
  // Credit Card Numbers (Visa, MC, Amex, Discover)
  credit_card_visa: /\b4[0-9]{12}(?:[0-9]{3})?\b/,
  credit_card_mc: /\b5[1-5][0-9]{14}\b/,
  credit_card_amex: /\b3[47][0-9]{13}\b/,
  credit_card_discover: /\b6(?:011|5[0-9]{2})[0-9]{12}\b/,
  
  // Email addresses
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/i,
  
  // Phone numbers (US, international)
  phone_us: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/,
  phone_intl: /\b\+[1-9]\d{1,14}\b/,
  
  // Date of birth patterns
  dob: /\b(?:DOB|date\s*of\s*birth|born\s*on|birthday)\s*[:\-]?\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/i,
  
  // Passport numbers
  passport: /\b[A-Z]{1,2}[0-9]{6,9}\b/,
  
  // Driver's license (varies by state — use common formats)
  drivers_license: /\b[A-Z]\d{7,12}\b/,
  
  // IP addresses (v4)
  ipv4: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/,
  
  // IBAN
  iban: /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/,
};
```

#### 4.2 Secrets & Credentials
```typescript
const SECRET_PATTERNS = {
  // AWS
  aws_access_key: /\bAKIA[0-9A-Z]{16}\b/,
  aws_secret_key: /\b[A-Za-z0-9/+=]{40}\b/, // with context check for "aws" nearby
  
  // GitHub
  github_pat: /\bghp_[A-Za-z0-9]{36}\b/,
  github_fine_grained: /\bgithub_pat_[A-Za-z0-9_]{82}\b/,
  github_oauth: /\bgho_[A-Za-z0-9]{36}\b/,
  github_app_token: /\b(ghu|ghs)_[A-Za-z0-9]{36}\b/,
  
  // Google
  google_api_key: /\bAIza[0-9A-Za-z_-]{35}\b/,
  google_oauth: /\b[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com\b/,
  
  // Azure
  azure_subscription: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/,
  azure_storage_key: /\b[A-Za-z0-9+/]{86}==\b/,
  
  // Stripe
  stripe_secret: /\bsk_(live|test)_[A-Za-z0-9]{24,}\b/,
  stripe_publishable: /\bpk_(live|test)_[A-Za-z0-9]{24,}\b/,
  
  // JWT
  jwt: /\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/,
  
  // Private keys
  private_key: /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----/,
  
  // Generic secrets (context-aware)
  password_field: /(?:password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*["']?[^\s"']{8,}["']?/i,
  
  // Connection strings
  connection_string: /(?:mongodb|postgres|mysql|redis|amqp|mssql):\/\/[^\s"']+/i,
  
  // Slack
  slack_token: /\bxox[baprs]-[A-Za-z0-9-]+\b/,
  slack_webhook: /\bhttps:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+\b/,
  
  // SendGrid
  sendgrid_key: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
  
  // Twilio
  twilio_sid: /\bAC[0-9a-f]{32}\b/,
  twilio_auth: /\b[0-9a-f]{32}\b/, // with context check
  
  // OpenAI
  openai_key: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/,
  
  // Generic high-entropy strings (catch-all)
  high_entropy: null, // Implement Shannon entropy check for strings > 20 chars
};
```

#### 4.3 GDPR Article 9 Special Categories
```typescript
const GDPR_KEYWORDS = {
  health_data: ['diagnosis', 'prescription', 'medical record', 'patient', 'symptoms',
                'treatment', 'medication', 'blood type', 'allergy', 'disability',
                'mental health', 'HIV', 'cancer', 'diabetes', 'surgery'],
  
  biometric: ['fingerprint', 'retina scan', 'face recognition', 'facial recognition',
              'voiceprint', 'iris scan', 'biometric', 'DNA', 'genetic data'],
  
  racial_ethnic: ['racial origin', 'ethnic origin', 'ethnicity', 'race'],
  
  political: ['political opinion', 'political party', 'political affiliation',
              'political belief', 'party membership'],
  
  religious: ['religious belief', 'religion', 'faith', 'worship',
              'philosophical belief'],
  
  trade_union: ['trade union', 'union membership', 'labor union'],
  
  sexual_orientation: ['sexual orientation', 'gender identity', 'sex life'],
  
  criminal: ['criminal record', 'criminal conviction', 'arrest record',
             'criminal offense', 'felony', 'misdemeanor'],
};
```

#### 4.4 Shannon Entropy Detection
```typescript
function shannonEntropy(str: string): number {
  const freq: Map<string, number> = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Flag strings with entropy > 4.5 and length > 20 as potential secrets
function isHighEntropySecret(str: string): boolean {
  return str.length > 20 && shannonEntropy(str) > 4.5;
}
```

#### 4.5 File-Type Awareness
Automatically flag entire files of these types when they're included as context:
- `.env`, `.env.*` — always contains secrets
- `.pem`, `.key`, `.p12`, `.pfx` — certificate/key files
- `id_rsa`, `id_ed25519` — SSH keys
- `.npmrc`, `.pypirc` — package manager auth
- `credentials`, `secrets.json`, `vault.json`
- `docker-compose.yml` (may contain passwords)
- `terraform.tfvars`, `*.auto.tfvars` — infrastructure secrets

---

### 5. REDACTION STRATEGY

Implement three modes (user-configurable):

#### Mode 1: BLOCK (default)
- Reject the entire request if ANY violation is found
- Show VS Code error notification: "⛔ Copilot request blocked: SSN detected in your prompt"
- Return empty completion / error response to Copilot

#### Mode 2: REDACT
- Replace detected PII inline before forwarding:
  ```
  "My SSN is 123-45-6789"  →  "My SSN is [REDACTED-SSN]"
  "password: s3cr3t!"      →  "password: [REDACTED-SECRET]"
  "john@corp.com"           →  "[REDACTED-EMAIL]"
  ```
- Forward the sanitized request to Copilot
- Copilot still generates useful code, just without seeing the real values

#### Mode 3: WARN
- Allow the request through but show a warning notification
- Log the violation for audit
- Useful for development/testing phase before enforcing

---

### 6. USER INTERFACE

#### 6.1 Status Bar Item
- Show a shield icon in the VS Code status bar: `🛡️ PII Guard: Active`
- Click to see stats: "12 blocks today, 3 redactions"
- Color coding: Green (all clear), Yellow (warnings), Red (blocks occurred)

#### 6.2 Notifications
```
⛔ Copilot PII Guard: Blocked request containing SSN (123-**-****)
   [View Details] [Configure] [Dismiss]

⚠️ Copilot PII Guard: Redacted 2 email addresses from Copilot context
   [View Log] [Dismiss]
```

#### 6.3 Output Channel
- Create a dedicated output channel: "Copilot PII Guard"
- Log every scan with timestamp, mode, file, violations found
```
[2026-02-28 10:15:32] SCAN: Chat prompt (Agent mode)
  → 2 violations found:
    1. SSN detected in prompt text (line: "my SSN is 123-45-6789")
    2. AWS key detected in file context (aws-config.ts:42)
  → Action: BLOCKED
```

#### 6.4 Webview Dashboard
- Create a sidebar webview showing:
  - Total scans / blocks / redactions (today, this week, all time)
  - Most common violation types (pie chart)
  - Recent violations list with file/line details
  - Export audit log as CSV/JSON

#### 6.5 Code Decorations
- In the editor, highlight lines containing detected PII with a red gutter icon
- Show inline decoration: "⚠️ This line contains PII — will be redacted from Copilot context"
- Use `vscode.languages.registerCodeLensProvider` for actionable "Redact this" / "Exclude file" buttons

---

### 7. CONFIGURATION (package.json contributes.configuration)

```json
{
  "copilotPiiGuard.enabled": {
    "type": "boolean",
    "default": true,
    "description": "Enable/disable PII Guard"
  },
  "copilotPiiGuard.mode": {
    "type": "string",
    "enum": ["block", "redact", "warn"],
    "default": "block",
    "description": "How to handle detected PII"
  },
  "copilotPiiGuard.proxyPort": {
    "type": "number",
    "default": 0,
    "description": "Local proxy port (0 = auto-assign)"
  },
  "copilotPiiGuard.scanInlineCompletions": {
    "type": "boolean",
    "default": true,
    "description": "Scan context for inline code completions"
  },
  "copilotPiiGuard.scanChatPrompts": {
    "type": "boolean",
    "default": true,
    "description": "Scan Chat/Agent/Edit mode prompts"
  },
  "copilotPiiGuard.scanFileContext": {
    "type": "boolean",
    "default": true,
    "description": "Scan files sent as context to Copilot"
  },
  "copilotPiiGuard.scanTerminalOutput": {
    "type": "boolean",
    "default": true,
    "description": "Scan terminal output shared with Agent mode"
  },
  "copilotPiiGuard.blockedFilePatterns": {
    "type": "array",
    "default": ["**/.env*", "**/*.pem", "**/*.key", "**/id_rsa*"],
    "description": "Glob patterns for files that should never be sent to Copilot"
  },
  "copilotPiiGuard.excludePatterns": {
    "type": "array",
    "default": [],
    "description": "Pattern names to exclude from detection (e.g., 'email', 'ipv4')"
  },
  "copilotPiiGuard.customPatterns": {
    "type": "array",
    "default": [],
    "description": "Custom regex patterns: [{name, pattern, severity}]"
  },
  "copilotPiiGuard.gdprDetection": {
    "type": "boolean",
    "default": true,
    "description": "Enable GDPR Article 9 special category detection"
  },
  "copilotPiiGuard.entropyDetection": {
    "type": "boolean",
    "default": true,
    "description": "Enable high-entropy string detection for unknown secret formats"
  },
  "copilotPiiGuard.auditLog.enabled": {
    "type": "boolean",
    "default": true,
    "description": "Write violation logs to file"
  },
  "copilotPiiGuard.auditLog.path": {
    "type": "string",
    "default": "",
    "description": "Audit log file path (default: extension storage)"
  },
  "copilotPiiGuard.splunk.enabled": {
    "type": "boolean",
    "default": false,
    "description": "Forward violations to Splunk HEC"
  },
  "copilotPiiGuard.splunk.url": {
    "type": "string",
    "default": "",
    "description": "Splunk HEC endpoint URL"
  },
  "copilotPiiGuard.splunk.token": {
    "type": "string",
    "default": "",
    "description": "Splunk HEC authentication token"
  },
  "copilotPiiGuard.notifications.showBlocked": {
    "type": "boolean",
    "default": true,
    "description": "Show notification when requests are blocked"
  },
  "copilotPiiGuard.notifications.showRedacted": {
    "type": "boolean",
    "default": true,
    "description": "Show notification when data is redacted"
  }
}
```

---

### 8. IMPLEMENTATION PLAN

#### Phase 1: Core Scanner Engine
```
src/
├── scanner/
│   ├── confidential-scanner.ts     — Main scanner class
│   ├── pii-patterns.ts             — PII regex patterns
│   ├── secret-patterns.ts          — Credential/secret patterns
│   ├── gdpr-keywords.ts            — GDPR Article 9 keywords
│   ├── entropy-detector.ts         — Shannon entropy checker
│   ├── file-type-rules.ts          — Sensitive file type detection
│   └── redactor.ts                 — Redaction/masking logic
```

#### Phase 2: Proxy Server
```
src/
├── proxy/
│   ├── proxy-server.ts             — Local HTTPS proxy
│   ├── request-interceptor.ts      — Parse & scan outbound requests
│   ├── response-handler.ts         — Handle blocked/redacted responses
│   ├── certificate-manager.ts      — Self-signed cert generation
│   └── copilot-endpoints.ts        — Known Copilot API URLs
```

#### Phase 3: VS Code Integration
```
src/
├── extension.ts                    — Extension entry point
├── vscode/
│   ├── chat-participant.ts         — Chat/Agent mode interception
│   ├── inline-completion-guard.ts  — Inline completion scanning
│   ├── document-scanner.ts         — Real-time file PII tracking
│   ├── terminal-monitor.ts         — Terminal output scanning
│   ├── status-bar.ts               — Status bar UI
│   ├── notifications.ts            — Notification manager
│   ├── code-decorations.ts         — Editor PII highlights
│   ├── dashboard-webview.ts        — Audit dashboard
│   └── commands.ts                 — VS Code commands
```

#### Phase 4: Logging & Compliance
```
src/
├── audit/
│   ├── audit-logger.ts             — Local file logging
│   ├── splunk-forwarder.ts         — Splunk HEC integration
│   ├── violation-record.ts         — Violation data model
│   └── report-generator.ts         — CSV/JSON export
```

---

### 9. KEY IMPLEMENTATION DETAILS

#### 9.1 Proxy Auto-Configuration (SILENT, AUTOMATIC)
The proxy MUST start automatically on EVERY VS Code launch — no user interaction:
```typescript
export async function activate(context: vscode.ExtensionContext) {
  // ── STEP 1: Start proxy SILENTLY (no prompts, no dialogs) ──
  const proxyPort = await startProxy(); // binds to 127.0.0.1, random port
  
  // ── STEP 2: Save original proxy settings (for clean uninstall restore) ──
  const config = vscode.workspace.getConfiguration('http');
  const originalProxy = config.get('proxy');
  if (!context.globalState.get('originalProxy')) {
    // Only save on FIRST activation, not subsequent ones
    context.globalState.update('originalProxy', originalProxy);
  }
  
  // ── STEP 3: Route ALL VS Code traffic through our proxy ──
  await config.update('proxy', `http://127.0.0.1:${proxyPort}`, true);
  await config.update('proxyStrictSSL', false, true);
  
  // ── STEP 4: Initialize scanner with all detectors ON ──
  const scanner = initScanner(); // All patterns enabled by default
  
  // ── STEP 5: Register ALL interception layers ──
  registerAllGuards(scanner, context);
  
  // ── STEP 6: Status bar (only visible UI) ──
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.text = '$(shield) PII Guard';
  statusBar.tooltip = 'Copilot PII Guard: Active — 0 blocks today';
  statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.prominentBackground');
  statusBar.show();
  context.subscriptions.push(statusBar);
  
  // ── STEP 7: First-run notification (shown ONCE, never again) ──
  if (!context.globalState.get('welcomed')) {
    context.globalState.update('welcomed', true);
    vscode.window.showInformationMessage(
      '🛡️ Copilot PII Guard is active. All prompts are being scanned for confidential data.',
      'OK'
    );
  }
  
  // ── STEP 8: Clean restore on uninstall/disable ──
  context.subscriptions.push({
    dispose: async () => {
      const saved = context.globalState.get<string>('originalProxy');
      await config.update('proxy', saved || undefined, true);
      await config.update('proxyStrictSSL', undefined, true);
    }
  });
  
  // Extension is now FULLY ACTIVE — no further user action needed
}
```

**IMPORTANT AUTO-START BEHAVIORS:**
- `activationEvents: ["onStartupFinished"]` → activates on EVERY VS Code launch
- Proxy starts BEFORE Copilot sends its first request
- If the proxy port is in use, automatically pick another port
- If VS Code already has a proxy configured (corporate VPN), chain through it
- If the extension is disabled and re-enabled, re-start proxy without requiring VS Code restart
- ALL config defaults are set to maximum protection (block mode, all scanners on)

#### 9.2 Request Interception Logic
```typescript
function interceptRequest(req: IncomingMessage, body: Buffer): InterceptResult {
  const url = req.url || '';
  
  // Only intercept Copilot-bound requests
  if (!isCopilotEndpoint(url)) {
    return { action: 'passthrough' };
  }
  
  const payload = JSON.parse(body.toString());
  const textsToScan: string[] = [];
  
  // Extract all text fields from Copilot request
  if (payload.messages) {
    // Chat/Agent mode
    for (const msg of payload.messages) {
      if (msg.content) textsToScan.push(msg.content);
      if (msg.context?.files) {
        for (const f of msg.context.files) textsToScan.push(f.content);
      }
    }
  }
  
  if (payload.prompt) {
    // Inline completion
    textsToScan.push(payload.prompt);
  }
  
  if (payload.documents) {
    // Multi-file context
    for (const doc of payload.documents) textsToScan.push(doc.content);
  }
  
  // Scan all extracted text
  const violations = scanner.scanAll(textsToScan);
  
  if (violations.length === 0) {
    return { action: 'passthrough' };
  }
  
  // Handle based on mode
  const mode = getConfig('mode');
  
  if (mode === 'block') {
    logViolations(violations, 'BLOCKED');
    showBlockNotification(violations);
    return { action: 'block', violations };
  }
  
  if (mode === 'redact') {
    const redactedPayload = redactor.redact(payload, violations);
    logViolations(violations, 'REDACTED');
    showRedactNotification(violations);
    return { action: 'forward', body: JSON.stringify(redactedPayload) };
  }
  
  // warn mode
  logViolations(violations, 'WARNED');
  showWarnNotification(violations);
  return { action: 'passthrough' };
}
```

#### 9.3 Chat Participant Guard
```typescript
const guard = vscode.chat.createChatParticipant('copilot-pii-guard', async (request, context, response, token) => {
  // Scan the user's prompt
  const promptViolations = scanner.scanText(request.prompt);
  
  // Scan attached references (files, selections)
  for (const ref of request.references) {
    if (ref instanceof vscode.Uri) {
      const content = await vscode.workspace.fs.readFile(ref);
      const fileViolations = scanner.scanText(content.toString());
      promptViolations.push(...fileViolations);
    }
  }
  
  if (promptViolations.length > 0) {
    response.markdown(`⛔ **PII Guard**: Blocked ${promptViolations.length} confidential data items:\n`);
    for (const v of promptViolations) {
      response.markdown(`- **${v.patternName}**: \`${v.maskedPreview}\`\n`);
    }
    response.markdown(`\n*Remove the sensitive data and try again.*`);
    return;
  }
  
  // If clean, let the normal Copilot handle it
  // (This participant only activates when explicitly invoked or as a pre-filter)
});
```

#### 9.4 Inline Completion Guard
```typescript
vscode.languages.registerInlineCompletionItemProvider({ pattern: '**' }, {
  async provideInlineCompletionItems(document, position, context, token) {
    // Get the context that would be sent to Copilot
    const contextRange = new vscode.Range(
      Math.max(0, position.line - 50), 0,  // ~50 lines before cursor
      Math.min(document.lineCount, position.line + 10), 0  // ~10 lines after
    );
    const contextText = document.getText(contextRange);
    
    // Scan for PII
    const violations = scanner.scanText(contextText);
    
    if (violations.length > 0) {
      // Show status bar warning
      updateStatusBar('blocked', violations.length);
      
      // Return empty completions — Copilot won't see this context
      return { items: [] };
      
      // OR: return a warning completion
      // return { items: [{ insertText: '// ⚠️ PII detected — Copilot blocked' }] };
    }
    
    // If clean, return undefined to let Copilot's own provider handle it
    return undefined;
  }
}, { triggerCharacters: [] });
```

---

### 10. TESTING REQUIREMENTS

#### 10.1 Unit Tests
- Test every regex pattern with positive and negative cases
- Test redaction produces correct output
- Test entropy detection thresholds
- Test file-type rules

#### 10.2 Integration Tests
- Spawn a mock "Copilot API" server
- Send requests through the proxy with PII data
- Verify PII never reaches the mock server
- Verify clean requests pass through unchanged
- Verify redacted requests have correct placeholders

#### 10.3 E2E Test Scenarios
```
Test 1: Paste SSN into chat → BLOCKED
Test 2: Open .env file → file context BLOCKED from Copilot
Test 3: Type code with hardcoded AWS key → inline completion BLOCKED
Test 4: Agent mode reads terminal with connection string → BLOCKED
Test 5: Clean code prompt → passes through normally
Test 6: Redact mode → only PII replaced, rest passes through
Test 7: Custom regex pattern → detected correctly
Test 8: Disable specific pattern → that pattern passes through
Test 9: Splunk logging → violation appears in Splunk
Test 10: Dashboard shows correct stats
```

---

### 11. PACKAGE.JSON ESSENTIALS

```json
{
  "name": "copilot-pii-guard",
  "displayName": "Copilot PII Guard",
  "description": "Blocks confidential data (PII, secrets, GDPR) from reaching GitHub Copilot models — all modes: inline, chat, agent, edit, plan",
  "version": "1.0.0",
  "publisher": "YOUR_PUBLISHER",
  "engines": { "vscode": "^1.95.0" },
  "categories": ["Other", "AI", "Security"],
  "keywords": ["copilot", "pii", "gdpr", "security", "secrets", "compliance", "data protection"],
  "activationEvents": ["onStartupFinished"],  // CRITICAL: activates every time VS Code starts, no user action needed
  "extensionDependencies": ["github.copilot"],
  "main": "./dist/extension.js",
  "contributes": {
    "commands": [
      { "command": "copilotPiiGuard.toggle", "title": "Toggle PII Guard" },
      { "command": "copilotPiiGuard.showDashboard", "title": "Show PII Guard Dashboard" },
      { "command": "copilotPiiGuard.scanCurrentFile", "title": "Scan Current File for PII" },
      { "command": "copilotPiiGuard.exportAuditLog", "title": "Export Audit Log" },
      { "command": "copilotPiiGuard.clearStats", "title": "Clear PII Guard Statistics" }
    ],
    "viewsContainers": {
      "activitybar": [{
        "id": "pii-guard",
        "title": "PII Guard",
        "icon": "resources/shield.svg"
      }]
    }
  }
}
```

---

### 12. SECURITY CONSIDERATIONS

1. **The proxy MUST only bind to `127.0.0.1`** — never `0.0.0.0`
2. **Never log the actual PII values** — log masked versions only (e.g., `***-**-6789`)
3. **Self-signed certificates** must be scoped to localhost only
4. **Proxy auto-restore** — if extension crashes, restore original proxy settings on next activation
5. **Rate limiting** — don't let the scanning create noticeable latency (target <50ms per scan)
6. **No network calls from the scanner** — all detection is pure local regex/keyword matching
7. **Memory management** — don't cache file contents indefinitely; use WeakRef or LRU cache
8. **Crash recovery** — on activation, detect if a previous proxy was left running (stale port) and clean up
9. **Corporate proxy chaining** — if `http.proxy` was already set (e.g., corporate VPN), save it and chain: `user → PII proxy → corporate proxy → internet`
10. **Silent operation** — the extension must NEVER show a dialog, wizard, or prompt that blocks the developer's workflow. Only non-modal notifications for blocks.

---

### 13. COMPETITIVE DIFFERENTIATION

This extension differs from existing tools:
- **vs. GitHub Content Exclusions**: Content-aware (scans data), not just file-path based
- **vs. Stacklok CodeGate**: Native VS Code extension (no Docker), covers all Copilot modes
- **vs. GitLeaks/TruffleHog**: Those scan git history; this scans live editor context in real-time
- **vs. MCP Audit PII Guard**: That covers MCP tool calls; this covers Copilot prompt/completion flow

---

### 14. DELIVERABLES

1. Complete VS Code extension source code (TypeScript)
2. Working local HTTPS proxy with Copilot endpoint interception
3. 50+ PII/secret detection patterns
4. GDPR special category keyword detection
5. Shannon entropy-based unknown secret detection
6. Three enforcement modes: block / redact / warn (default: BLOCK)
7. Status bar UI with real-time stats
8. Audit dashboard webview
9. Splunk HEC forwarding (optional, off by default)
10. Code decorations for PII-containing lines
11. Comprehensive test suite (unit + integration + e2e)
12. README with architecture diagram
13. Packaged .vsix file ready for marketplace
14. **ZERO-CONFIG auto-start**: installs → activates on startup → proxy starts → blocking is live. No setup required.
15. **First-run notification**: single non-blocking info message shown once, never again
16. **Graceful uninstall**: restores original proxy settings when extension is disabled/uninstalled

---

## PROMPT END

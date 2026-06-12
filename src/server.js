const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execFile } = require('child_process');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.DASHBOARD_HOST || '127.0.0.1';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const MAX_BODY_BYTES = 1024 * 1024;
const ALERT_WEBHOOK_HOSTS = new Set(
  (process.env.ALERT_WEBHOOK_HOSTS || '')
    .split(',')
    .map(host => host.trim().toLowerCase())
    .filter(Boolean),
);

if (!ADMIN_TOKEN) {
  console.error('ADMIN_TOKEN is required. Set a strong token before starting the dashboard.');
  process.exit(1);
}

function validateWebhookUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return 'alerting.webhookUrl must be a valid URL';
  }
  if (parsed.protocol !== 'https:') {
    return 'alerting.webhookUrl must use https';
  }
  if (!ALERT_WEBHOOK_HOSTS.has(parsed.hostname.toLowerCase())) {
    return 'alerting.webhookUrl host must be listed in ALERT_WEBHOOK_HOSTS';
  }
  return '';
}

fs.mkdirSync(DATA_DIR, { recursive: true });

const state = loadState();
const processes = new Map();

function defaultState() {
  return {
    streams: [],
    audit: [],
    alerts: [],
    metrics: {
      startedAt: new Date().toISOString(),
      ffmpegAvailable: false,
      host: os.hostname(),
    },
  };
}

function loadState() {
  try {
    if (!fs.existsSync(STATE_FILE)) {
      return defaultState();
    }
    return { ...defaultState(), ...JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) };
  } catch (error) {
    console.error(`Failed to load state: ${error.message}`);
    return defaultState();
  }
}

function saveState() {
  const serialized = JSON.stringify(state, null, 2);
  const tmp = `${STATE_FILE}.tmp`;
  fs.writeFileSync(tmp, serialized);
  fs.renameSync(tmp, STATE_FILE);
}

function audit(action, details = {}) {
  state.audit.unshift({
    id: crypto.randomUUID(),
    at: new Date().toISOString(),
    action,
    details: sanitize(details),
  });
  state.audit = state.audit.slice(0, 500);
  saveState();
}

function alert(streamId, level, message, details = {}) {
  const entry = {
    id: crypto.randomUUID(),
    at: new Date().toISOString(),
    streamId,
    level,
    message,
    details: sanitize(details),
  };
  state.alerts.unshift(entry);
  state.alerts = state.alerts.slice(0, 500);
  saveState();
  notifyAlert(entry);
}

function sanitize(value) {
  if (Array.isArray(value)) {
    return value.map(sanitize);
  }

  function notifyAlert(entry) {
    const stream = getStream(entry.streamId);
    const webhookUrl = stream?.alerting?.webhookUrl;
    if (!webhookUrl) return;
    let parsed;
    try {
      parsed = new URL(webhookUrl);
    } catch {
      return;
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) return;
    if (!ALERT_WEBHOOK_HOSTS.has(parsed.hostname.toLowerCase())) {
      audit('alert.webhook.blocked', { streamId: entry.streamId, host: parsed.hostname });
      return;
    }
    const payload = JSON.stringify({
      id: entry.id,
      at: entry.at,
      level: entry.level,
      message: entry.message,
      streamId: entry.streamId,
      platform: stream.platform,
      streamName: stream.name,
    });
    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.request(parsed, {
      method: 'POST',
      timeout: 5000,
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
      },
    });
    req.on('error', error => audit('alert.webhook.failed', { streamId: entry.streamId, message: error.message }));
    req.on('timeout', () => req.destroy(new Error('webhook timeout')));
    req.end(payload);
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      /token|key|secret|password|url/i.test(key) ? '[redacted]' : sanitize(item),
    ]),
  );
}

function send(res, status, payload, headers = {}) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': typeof payload === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(body);
}

function sendFile(res, filePath) {
  const relative = path.relative(PUBLIC_DIR, filePath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    send(res, 403, 'Forbidden');
    return;
  }
  fs.readFile(filePath, (error, content) => {
    if (error) {
      send(res, 404, 'Not found');
      return;
    }
    const ext = path.extname(filePath);
    const type = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.svg': 'image/svg+xml',
    }[ext] || 'application/octet-stream';
    res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' });
    res.end(content);
  });
}

function requireAuth(req, res) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const expected = Buffer.from(ADMIN_TOKEN);
  const actual = Buffer.from(token);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    send(res, 401, { error: 'Unauthorized' });
    return false;
  }
  return true;
}

function readJson(req, res) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (Buffer.byteLength(body) > MAX_BODY_BYTES) {
        reject(new Error('Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  }).catch(error => {
    send(res, 400, { error: error.message });
    return undefined;
  });
}

function validateStream(input) {
  const errors = [];
  const platform = String(input.platform || '').toLowerCase();
  if (!['bilibili', 'douyin'].includes(platform)) {
    errors.push('platform must be bilibili or douyin');
  }
  if (!input.name || String(input.name).trim().length < 2) {
    errors.push('name is required');
  }
  if (!input.authorization || input.authorization.confirmed !== true) {
    errors.push('authorization.confirmed must be true for owned or licensed content');
  }
  if (!input.authorization?.owner || !input.authorization?.licenseRef) {
    errors.push('authorization.owner and authorization.licenseRef are required');
  }
  if (!Array.isArray(input.sources) || input.sources.length === 0) {
    errors.push('at least one source is required');
  } else {
    input.sources.forEach((source, index) => {
      if (!source.url || !isAllowedMediaUrl(source.url)) {
        errors.push(`sources[${index}].url must be a local file path or http(s) media URL`);
      }
      if (source.authorized !== true) {
        errors.push(`sources[${index}].authorized must be true`);
      }
    });
  }
  if (!input.target || !isAllowedTarget(input.target.ingestUrl)) {
    errors.push('target.ingestUrl must be an official RTMP or SRT ingest URL');
  }
  if (input.alerting?.webhookUrl) {
    const webhookError = validateWebhookUrl(input.alerting.webhookUrl);
    if (webhookError) errors.push(webhookError);
  }
  const maxRetries = Number(input.retryPolicy?.maxRetries ?? 3);
  if (!Number.isInteger(maxRetries) || maxRetries < 0 || maxRetries > 20) {
    errors.push('retryPolicy.maxRetries must be an integer between 0 and 20');
  }
  return errors;
}

function isAllowedMediaUrl(value) {
  try {
    const parsed = new URL(value);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return path.isAbsolute(String(value));
  }
}

function isAllowedTarget(value) {
  try {
    const parsed = new URL(value);
    return ['rtmp:', 'rtmps:', 'srt:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function normalizeStream(input, existing = {}) {
  const now = new Date().toISOString();
  return {
    id: existing.id || crypto.randomUUID(),
    name: String(input.name || existing.name || '').trim(),
    platform: String(input.platform || existing.platform || '').toLowerCase(),
    enabled: Boolean(input.enabled),
    status: existing.status || 'stopped',
    currentSourceIndex: Number(existing.currentSourceIndex || 0),
    retryCount: Number(existing.retryCount || 0),
    lastError: existing.lastError || null,
    createdAt: existing.createdAt || now,
    updatedAt: now,
    authorization: {
      confirmed: input.authorization?.confirmed === true,
      owner: String(input.authorization?.owner || ''),
      licenseRef: String(input.authorization?.licenseRef || ''),
      notes: String(input.authorization?.notes || ''),
    },
    target: {
      ingestUrl: String(input.target?.ingestUrl || ''),
      officialConsoleUrl: String(input.target?.officialConsoleUrl || ''),
    },
    schedule: {
      timezone: String(input.schedule?.timezone || 'UTC'),
      startAt: input.schedule?.startAt || '',
      endAt: input.schedule?.endAt || '',
    },
    retryPolicy: {
      maxRetries: Number(input.retryPolicy?.maxRetries ?? 3),
      backoffSeconds: Number(input.retryPolicy?.backoffSeconds ?? 30),
    },
    alerting: {
      webhookUrl: String(input.alerting?.webhookUrl || ''),
      email: String(input.alerting?.email || ''),
      im: String(input.alerting?.im || ''),
    },
    sources: input.sources.map(source => ({
      id: source.id || crypto.randomUUID(),
      title: String(source.title || ''),
      url: String(source.url || ''),
      authorized: source.authorized === true,
      fallback: source.fallback === true,
    })),
  };
}

function publicStream(stream) {
  return {
    ...stream,
    target: { ...stream.target, ingestUrl: redactUrl(stream.target.ingestUrl) },
    sources: stream.sources.map(source => ({ ...source, url: redactUrl(source.url) })),
  };
}

function redactUrl(value) {
  if (!value) return '';
  try {
    const parsed = new URL(value);
    if (parsed.password) parsed.password = '***';
    if (parsed.username) parsed.username = '***';
    if (parsed.search) parsed.search = '?redacted=true';
    const text = parsed.toString();
    return text.length > 120 ? `${text.slice(0, 117)}...` : text;
  } catch {
    return path.isAbsolute(value) ? value : '[redacted]';
  }
}

function getStream(id) {
  return state.streams.find(stream => stream.id === id);
}

function startStream(id, reason = 'manual') {
  const stream = getStream(id);
  if (!stream) return { error: 'Stream not found' };
  if (processes.has(id)) return { stream };
  const source = stream.sources[stream.currentSourceIndex % stream.sources.length];
  if (!source?.authorized) {
    const message = 'Selected source is not authorized';
    stream.status = 'error';
    stream.lastError = message;
    alert(id, 'error', message);
    saveState();
    return { error: message };
  }

  const args = buildFfmpegArgs(source.url, stream.target.ingestUrl);
  const child = spawn('ffmpeg', args, { stdio: ['ignore', 'ignore', 'pipe'] });
  const startedAt = new Date().toISOString();
  processes.set(id, { child, startedAt, stderr: '' });
  stream.status = 'running';
  stream.lastError = null;
  stream.updatedAt = startedAt;
  audit('stream.start', { streamId: id, reason, sourceId: source.id, platform: stream.platform });
  saveState();

  child.stderr.on('data', chunk => {
    const proc = processes.get(id);
    if (proc) {
      proc.stderr = `${proc.stderr}${chunk}`.slice(-4000);
    }
  });
  child.on('error', error => handleProcessFailure(stream, error.message));
  child.on('exit', (code, signal) => {
    processes.delete(id);
    if (stream.status === 'stopping') {
      stream.status = 'stopped';
      stream.retryCount = 0;
      stream.updatedAt = new Date().toISOString();
      audit('stream.stop', { streamId: id, code, signal });
      saveState();
      return;
    }
    handleProcessFailure(stream, `ffmpeg exited with code ${code ?? 'n/a'} signal ${signal ?? 'n/a'}`);
  });
  return { stream };
}

function buildFfmpegArgs(inputUrl, targetUrl) {
  const target = new URL(targetUrl);
  const format = target.protocol.startsWith('rtmp') ? 'flv' : 'mpegts';
  return ['-hide_banner', '-nostdin', '-re', '-stream_loop', '-1', '-i', inputUrl, '-c', 'copy', '-f', format, targetUrl];
}

function stopStream(id, reason = 'manual') {
  const stream = getStream(id);
  if (!stream) return { error: 'Stream not found' };
  stream.status = 'stopping';
  stream.updatedAt = new Date().toISOString();
  audit('stream.stop.requested', { streamId: id, reason });
  const proc = processes.get(id);
  if (!proc) {
    stream.status = 'stopped';
    saveState();
    return { stream };
  }
  proc.child.kill('SIGTERM');
  setTimeout(() => {
    if (processes.has(id)) {
      proc.child.kill('SIGKILL');
    }
  }, 5000).unref();
  saveState();
  return { stream };
}

function handleProcessFailure(stream, message) {
  stream.lastError = message;
  stream.status = 'error';
  stream.updatedAt = new Date().toISOString();
  alert(stream.id, 'error', 'Streaming process failed', { message });
  const maxRetries = stream.retryPolicy.maxRetries;
  if (!stream.enabled || stream.retryCount >= maxRetries) {
    audit('stream.failed', { streamId: stream.id, retryCount: stream.retryCount, message });
    saveState();
    return;
  }
  stream.retryCount += 1;
  stream.currentSourceIndex = (stream.currentSourceIndex + 1) % stream.sources.length;
  stream.status = 'retrying';
  const backoff = Math.max(1, Number(stream.retryPolicy.backoffSeconds || 30));
  audit('stream.retry.scheduled', { streamId: stream.id, retryCount: stream.retryCount, backoff });
  saveState();
  setTimeout(() => {
    if (stream.enabled && !processes.has(stream.id)) {
      startStream(stream.id, 'retry');
    }
  }, backoff * 1000).unref();
}

function evaluateSchedules() {
  const now = Date.now();
  state.streams.forEach(stream => {
    if (!stream.enabled) return;
    const start = stream.schedule.startAt ? Date.parse(stream.schedule.startAt) : null;
    const end = stream.schedule.endAt ? Date.parse(stream.schedule.endAt) : null;
    const inWindow = (!start || now >= start) && (!end || now <= end);
    if (inWindow && !processes.has(stream.id) && !['running', 'retrying'].includes(stream.status)) {
      startStream(stream.id, 'schedule');
    }
    if (!inWindow && processes.has(stream.id)) {
      stopStream(stream.id, 'schedule');
    }
  });
}

function collectMetrics() {
  return {
    ...state.metrics,
    uptimeSeconds: Math.round(process.uptime()),
    memory: process.memoryUsage(),
    loadAverage: os.loadavg(),
    cpuCount: os.cpus().length,
    networkInterfaces: Object.fromEntries(
      Object.entries(os.networkInterfaces()).map(([name, items]) => [
        name,
        items.map(item => ({ family: item.family, address: item.address, internal: item.internal })),
      ]),
    ),
    runningStreams: processes.size,
    streams: state.streams.length,
    alerts: state.alerts.length,
  };
}

async function handleApi(req, res, pathname) {
  if (!requireAuth(req, res)) return;

  if (req.method === 'GET' && pathname === '/api/health') {
    send(res, 200, { ok: true, metrics: collectMetrics() });
    return;
  }
  if (req.method === 'GET' && pathname === '/api/metrics') {
    send(res, 200, collectMetrics());
    return;
  }
  if (req.method === 'GET' && pathname === '/api/streams') {
    send(res, 200, state.streams.map(publicStream));
    return;
  }
  if (req.method === 'GET' && pathname === '/api/audit') {
    send(res, 200, state.audit);
    return;
  }
  if (req.method === 'GET' && pathname === '/api/alerts') {
    send(res, 200, state.alerts);
    return;
  }
  if (req.method === 'POST' && pathname === '/api/streams') {
    const body = await readJson(req, res);
    if (!body) return;
    const errors = validateStream(body);
    if (errors.length) {
      send(res, 422, { errors });
      return;
    }
    const stream = normalizeStream(body);
    state.streams.push(stream);
    audit('stream.create', { streamId: stream.id, platform: stream.platform });
    saveState();
    send(res, 201, publicStream(stream));
    return;
  }
  const actionMatch = pathname.match(/^\/api\/streams\/([^/]+)\/(start|stop|retry)$/);
  if (req.method === 'POST' && actionMatch) {
    const [, id, action] = actionMatch;
    const stream = getStream(id);
    if (!stream) {
      send(res, 404, { error: 'Stream not found' });
      return;
    }
    if (action === 'start') stream.enabled = true;
    if (action === 'stop') stream.enabled = false;
    if (action === 'retry') {
      stream.retryCount = 0;
      stream.currentSourceIndex = (stream.currentSourceIndex + 1) % stream.sources.length;
    }
    const result = action === 'stop' ? stopStream(id) : startStream(id, action);
    if (result.error) {
      send(res, 409, { error: result.error });
      return;
    }
    send(res, 200, publicStream(stream));
    return;
  }
  const streamMatch = pathname.match(/^\/api\/streams\/([^/]+)$/);
  if (streamMatch && ['PUT', 'DELETE'].includes(req.method)) {
    const id = streamMatch[1];
    const index = state.streams.findIndex(stream => stream.id === id);
    if (index === -1) {
      send(res, 404, { error: 'Stream not found' });
      return;
    }
    if (req.method === 'DELETE') {
      stopStream(id, 'delete');
      state.streams.splice(index, 1);
      audit('stream.delete', { streamId: id });
      saveState();
      send(res, 204, '');
      return;
    }
    const body = await readJson(req, res);
    if (!body) return;
    const errors = validateStream(body);
    if (errors.length) {
      send(res, 422, { errors });
      return;
    }
    state.streams[index] = normalizeStream(body, state.streams[index]);
    audit('stream.update', { streamId: id });
    saveState();
    send(res, 200, publicStream(state.streams[index]));
    return;
  }
  send(res, 404, { error: 'Not found' });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (url.pathname.startsWith('/api/')) {
    handleApi(req, res, url.pathname).catch(error => {
      console.error(error);
      send(res, 500, { error: 'Internal server error' });
    });
    return;
  }
  const requested = url.pathname === '/' ? '/index.html' : url.pathname;
  const filePath = path.normalize(path.join(PUBLIC_DIR, requested));
  sendFile(res, filePath);
});

execFile('ffmpeg', ['-version'], error => {
  state.metrics.ffmpegAvailable = !error;
  saveState();
});

setInterval(evaluateSchedules, 30_000).unref();
server.listen(PORT, HOST, () => {
  console.log(`Dashboard listening on http://${HOST}:${PORT}`);
});

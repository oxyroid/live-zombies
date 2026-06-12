const state = {
  token: localStorage.getItem('adminToken') || '',
};

const loginForm = document.querySelector('#login-form');
const streamForm = document.querySelector('#stream-form');
const streamsEl = document.querySelector('#streams');
const metricsEl = document.querySelector('#metrics');
const alertsEl = document.querySelector('#alerts');
const auditEl = document.querySelector('#audit');
const tokenInput = document.querySelector('#token');

tokenInput.value = state.token;

loginForm.addEventListener('submit', event => {
  event.preventDefault();
  state.token = tokenInput.value;
  localStorage.setItem('adminToken', state.token);
  refresh();
});

streamForm.addEventListener('submit', async event => {
  event.preventDefault();
  const form = new FormData(streamForm);
  const payload = {
    name: form.get('name'),
    platform: form.get('platform'),
    enabled: false,
    authorization: {
      confirmed: form.get('authorized') === 'on',
      owner: form.get('owner'),
      licenseRef: form.get('licenseRef'),
    },
    target: {
      ingestUrl: form.get('ingestUrl'),
      officialConsoleUrl: form.get('officialConsoleUrl'),
    },
    schedule: {
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      startAt: toIso(form.get('startAt')),
      endAt: toIso(form.get('endAt')),
    },
    retryPolicy: {
      maxRetries: Number(form.get('maxRetries')),
      backoffSeconds: Number(form.get('backoffSeconds')),
    },
    alerting: {
      webhookUrl: form.get('webhookUrl'),
      email: form.get('email'),
    },
    sources: [{
      title: form.get('sourceTitle'),
      url: form.get('sourceUrl'),
      authorized: form.get('authorized') === 'on',
      fallback: false,
    }],
  };
  await api('/api/streams', { method: 'POST', body: JSON.stringify(payload) });
  streamForm.reset();
  await refresh();
});

function toIso(value) {
  return value ? new Date(value).toISOString() : '';
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      'content-type': 'application/json',
      authorization: 'Bearer ' + state.token,
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || (body.errors || []).join(', ') || response.statusText);
  }
  if (response.status === 204) return null;
  return response.json();
}

async function streamAction(id, action) {
  await api(`/api/streams/${id}/${action}`, { method: 'POST' });
  await refresh();
}

async function deleteStream(id) {
  if (!confirm('确认删除该直播任务？')) return;
  await api(`/api/streams/${id}`, { method: 'DELETE' });
  await refresh();
}

function renderStreams(streams) {
  streamsEl.innerHTML = streams.length ? '' : '<p>暂无直播任务</p>';
  streams.forEach(stream => {
    const item = document.createElement('article');
    item.className = 'stream';
    item.innerHTML = `
      <h3>${escapeHtml(stream.name)} <span class="badge">${escapeHtml(stream.status)}</span></h3>
      <p>平台：${escapeHtml(stream.platform)} | 授权：${escapeHtml(stream.authorization.licenseRef)}</p>
      <p>源：${stream.sources.map(source => escapeHtml(source.title || source.url)).join('、')}</p>
      <p>推流：${escapeHtml(stream.target.ingestUrl)}</p>
      <button data-action="start">启动</button>
      <button class="secondary" data-action="retry">切换源重试</button>
      <button class="danger" data-action="stop">停止</button>
      <button class="danger" data-action="delete">删除</button>
    `;
    item.querySelector('[data-action="start"]').addEventListener('click', () => streamAction(stream.id, 'start'));
    item.querySelector('[data-action="retry"]').addEventListener('click', () => streamAction(stream.id, 'retry'));
    item.querySelector('[data-action="stop"]').addEventListener('click', () => streamAction(stream.id, 'stop'));
    item.querySelector('[data-action="delete"]').addEventListener('click', () => deleteStream(stream.id));
    streamsEl.appendChild(item);
  });
}

function renderList(element, rows, emptyText) {
  element.innerHTML = rows.length ? '' : `<p>${emptyText}</p>`;
  rows.slice(0, 20).forEach(row => {
    const item = document.createElement('p');
    item.textContent = `${row.at} ${row.level || row.action}: ${row.message || JSON.stringify(row.details)}`;
    element.appendChild(item);
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  }[char]));
}

async function refresh() {
  if (!state.token) return;
  try {
    const [streams, metrics, alerts, audit] = await Promise.all([
      api('/api/streams'),
      api('/api/metrics'),
      api('/api/alerts'),
      api('/api/audit'),
    ]);
    renderStreams(streams);
    metricsEl.textContent = JSON.stringify(metrics, null, 2);
    renderList(alertsEl, alerts, '暂无异常告警');
    renderList(auditEl, audit, '暂无审计日志');
  } catch (error) {
    metricsEl.textContent = error.message;
  }
}

refresh();
setInterval(refresh, 10_000);

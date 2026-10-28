const $ = (id) => document.getElementById(id);
const PERIOD_MS = 30000;
let mode = 'TOTP';
let lastCode = null;
let deadline = 0;          // instante local en que vence el código TOTP vigente
let stepsLocked = false;   // true mientras el panel muestra el cálculo de una validación

async function api(path, method = 'GET', body) {
  let res;
  try {
    res = await fetch('/api' + path, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error('No se pudo conectar con el backend. ¿Está corriendo en localhost:8080?');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Error inesperado del servidor (' + res.status + ').');
  return data;
}

const fmt = (code) => code.slice(0, 3) + ' ' + code.slice(3);

function showCode(code) {
  const el = $('code');
  if (code !== lastCode) {
    el.textContent = code ? fmt(code) : '––– –––';
    el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash');
    lastCode = code;
  }
}


function clearTokenDisplay() {
  lastCode = null;

  $('code').textContent = '––– –––';
  $('code').classList.remove('flash', 'urgent');

  $('steps-origin').textContent = mode === 'HOTP'
      ? 'generá un código para ver el cálculo'
      : 'actualizando código vigente';

  $('f-counter').textContent = '';
  $('s-counter').textContent = '';
  $('s-hmac').textContent = '';
  $('s-trunc').textContent = '';
  $('s-mod').textContent = '';

  $('remaining').textContent = '–';
  $('tstep').textContent = '–';
  $('bar-fill').style.width = '0%';
  $('bar-fill').classList.remove('urgent');
}


function showTrace(t, origin) {
  $('steps-origin').textContent = origin;
  const isTotp = mode === 'TOTP';
  $('f-counter').innerHTML = isTotp
    ? 'C = T = ⌊ t / 30 ⌋, con t = tiempo Unix en segundos'
    : 'C = contador de eventos, se incrementa en cada uso';
  $('s-counter').textContent = `C = ${t.counter}  →  0x ${t.counterHex.match(/../g).join(' ')}`;
  const bytes = t.hmacHex.match(/../g);
  $('s-hmac').innerHTML = bytes.map((b, i) => {
    const cls = i >= t.offset && i < t.offset + 4 ? 'sel' : i === 19 ? 'last' : '';
    return `<span class="${cls}">${b}</span>`;
  }).join('');
  $('s-trunc').textContent =
    `offset = 0x${bytes[19]} AND 0x0F = ${t.offset}   →   0x${t.truncatedHex} AND 0x7FFFFFFF = ${t.binary}`;
  $('s-mod').textContent = `${t.binary} mod ${t.modulus} = ${t.code}`;
}

async function refreshTotp() {
  if (mode !== 'TOTP') return;
  try {
    const d = await api('/totp');

    if (mode !== 'TOTP') return;

    deadline = performance.now() + d.remainingMs;
    showCode(d.code);
    $('tstep').textContent = d.trace.counter;
    if (!stepsLocked) showTrace(d.trace, 'token · código vigente');
    setSecretMsg('', '');
  } catch (e) { setSecretMsg(e.message, 'err'); }
}

function tick() {
  if (mode === 'TOTP' && deadline) {
    const left = deadline - performance.now();
    if (left <= 0) { deadline = 0; stepsLocked = false; refreshTotp(); }
    else {
      const urgent = left < 5000;
      $('bar-fill').style.width = (left / PERIOD_MS * 100) + '%';
      $('bar-fill').classList.toggle('urgent', urgent);
      $('code').classList.toggle('urgent', urgent);
      $('remaining').textContent = Math.ceil(left / 1000);
    }
  }
  requestAnimationFrame(tick);
}

function setSecretMsg(text, cls) {
  const el = $('secret-msg'); el.textContent = text; el.className = 'msg ' + cls;
}

function setResult(text, cls) {
  const el = $('result'); el.textContent = text; el.className = 'result ' + cls;
}

function applyState(s) {
  $('secret').value = s.secret.match(/.{1,4}/g).join(' ');
  $('tok-counter').textContent = s.tokenCounter;
  $('srv-counter').textContent = s.serverCounter;
}

function setMode(m) {
  mode = m;
  stepsLocked = false;
  const totp = m === 'TOTP';
  $('tab-totp').classList.toggle('active', totp);
  $('tab-hotp').classList.toggle('active', !totp);
  $('tab-totp').setAttribute('aria-selected', totp);
  $('tab-hotp').setAttribute('aria-selected', !totp);
  $('totp-box').hidden = !totp;
  $('hotp-box').hidden = totp;
  $('hotp-server').hidden = totp;
  $('mode-label').textContent = m;
  $('code').classList.remove('urgent');
  $('server-hint').textContent = totp
    ? 'Recalcula TOTP(K, T) con su propio reloj y lo compara con el código recibido. Solo acepta el intervalo de 30 s vigente.'
    : 'Recalcula HOTP(K, C) con su propio contador. Si el token se adelantó, busca hasta 5 contadores hacia adelante y se resincroniza.';
  setResult('Ingresá el código del token para validarlo.', '');
  $('verify-code').value = '';
  deadline = 0;
  clearTokenDisplay();

  if (totp) refreshTotp();
}

async function changeSecret(call, okMsg) {
  try {
    applyState(await call());
    $('secret').classList.remove('invalid');
    setSecretMsg(okMsg, 'ok');
    setMode(mode);
  } catch (e) {
    $('secret').classList.add('invalid');
    setSecretMsg(e.message, 'err');
  }
}

$('tab-totp').onclick = () => setMode('TOTP');
$('tab-hotp').onclick = () => setMode('HOTP');
$('btn-set').onclick = () => changeSecret(() => api('/secret', 'POST', { secret: $('secret').value }), 'Secreto aplicado. Los contadores se reiniciaron.');
$('btn-random').onclick = () => changeSecret(() => api('/secret/random', 'POST'), 'Nuevo secreto aleatorio de 160 bits.');
$('btn-rfc').onclick = () => changeSecret(() => api('/secret/rfc', 'POST'), 'Secreto de prueba de los RFC 4226 / 6238 (HOTP con C = 0 debe dar 755224).');
$('secret').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('btn-set').click(); });

$('btn-next').onclick = async () => {
  try {
    const d = await api('/hotp/next', 'POST');
    showCode(d.code);
    $('tok-counter').textContent = d.tokenCounter;
    $('srv-counter').textContent = d.serverCounter;
    showTrace(d.trace, 'token · C = ' + d.trace.counter);
  } catch (e) { setResult(e.message, 'bad'); }
};

$('btn-reset').onclick = async () => {
  try { applyState(await api('/hotp/reset', 'POST')); setMode('HOTP'); }
  catch (e) { setResult(e.message, 'bad'); }
};

$('btn-copy').onclick = () => {
  if (!lastCode) { setResult('Todavía no hay un código generado en el token.', 'warn'); return; }
  $('verify-code').value = lastCode; $('verify-code').focus();
};

$('verify-code').addEventListener('input', (e) => {
  e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
  e.target.classList.remove('invalid');
});

$('verify-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('verify-code');
  if (!/^\d{6}$/.test(input.value)) {
    input.classList.add('invalid');
    setResult('El código debe tener exactamente 6 dígitos.', 'warn');
    return;
  }
  try {
    const d = await api('/verify', 'POST', { mode, code: input.value });
    setResult((d.valid ? '✔ ' : '✘ ') + d.message, d.valid ? 'ok' : 'bad');
    $('tok-counter').textContent = d.tokenCounter;
    $('srv-counter').textContent = d.serverCounter;
    stepsLocked = true;
    showTrace(d.trace, d.valid ? 'servidor · cálculo que coincidió' : 'servidor · código esperado');
  } catch (err) { setResult(err.message, 'bad'); }
});

(async function init() {
  try { applyState(await api('/state')); } catch (e) { setSecretMsg(e.message, 'err'); }
  setMode('TOTP');
  setInterval(() => { if (mode === 'TOTP' && !deadline) refreshTotp(); }, 3000); // reintento si se cayó el backend
  requestAnimationFrame(tick);
})();

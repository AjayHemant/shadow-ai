/**
 * SentinelGate DLP — Universal Content Script (v5 Final)
 * Injected at document_start. Hooks into every page before its JS loads.
 */

console.log('[SentinelGate] v5 LOADED on', location.hostname);

const SOURCE_APP = 'SentinelGate Browser';
const DESTINATION = location.hostname;

/* ─────────────────── TRUSTED DOMAINS (never scan) ─────────────────── */
const TRUSTED_DOMAINS = [
  // Authentication & Login
  'accounts.google.com', 'login.microsoftonline.com', 'login.live.com',
  'login.microsoft.com', 'auth0.com', 'login.yahoo.com',
  'appleid.apple.com', 'idmsa.apple.com',
  'github.com/login', 'github.com/session',
  'gitlab.com/users/sign_in',
  'login.salesforce.com', 'login.xero.com',
  'sso.', 'auth.', 'signin.', 'login.',
  // Password managers
  'vault.bitwarden.com', 'my.1password.com', 'lastpass.com',
  // Banking & Finance (login pages)
  'secure.', 'online.', 'banking.',
  // OS & System
  'windowsupdate.com', 'update.microsoft.com',
  // Certificate
  'ocsp.', 'crl.',
];

function isTrustedDomain() {
  const host = location.hostname.toLowerCase();
  const href = location.href.toLowerCase();
  for (const domain of TRUSTED_DOMAINS) {
    if (host === domain || host.endsWith('.' + domain) || host.startsWith(domain) || href.includes(domain)) {
      return true;
    }
  }
  // Also skip pages that look like login/auth flows
  if (/\/(login|signin|sign-in|auth|sso|oauth|saml|signup|sign-up|register|forgot|reset|verify|mfa|2fa|otp)\b/i.test(location.pathname)) {
    return true;
  }
  return false;
}

/* ─────────────────── LOGIN FIELD DETECTION ─────────────────── */
function isLoginField(el) {
  if (!el) return false;
  const type = (el.getAttribute('type') || '').toLowerCase();
  const name = (el.getAttribute('name') || '').toLowerCase();
  const id = (el.id || '').toLowerCase();
  const auto = (el.getAttribute('autocomplete') || '').toLowerCase();
  const placeholder = (el.getAttribute('placeholder') || '').toLowerCase();

  // Password fields are ALWAYS login fields
  if (type === 'password') return true;

  // Email/username input fields on login pages
  const loginPatterns = /^(email|username|user|login|identifier|phone|mobile|account|userid|user_id|user-id|signin|sign-in)$/i;
  if (loginPatterns.test(name) || loginPatterns.test(id) || loginPatterns.test(type)) return true;

  // Autocomplete hints
  if (['username', 'email', 'current-password', 'new-password', 'tel', 'one-time-code'].includes(auto)) return true;

  // Placeholder text hints
  if (/email|phone|username|password|sign.?in|log.?in/i.test(placeholder)) return true;

  return false;
}

/* ─────────────────── CSS ─────────────────── */
function injectCSS() {
  if (document.getElementById('sg-css')) return;
  const s = document.createElement('style');
  s.id = 'sg-css';
  s.textContent = `
        #sg-overlay{position:fixed;inset:0;z-index:2147483647;background:rgba(4,5,8,.88);backdrop-filter:blur(16px);display:flex;align-items:center;justify-content:center;animation:sg-in .2s ease;font-family:-apple-system,BlinkMacSystemFont,'Inter',sans-serif}
        @keyframes sg-in{from{opacity:0}to{opacity:1}}
        #sg-modal{background:#0f1117;border:1px solid rgba(108,99,255,.25);border-radius:24px;padding:32px;max-width:520px;width:94vw;box-shadow:0 40px 100px rgba(0,0,0,1);animation:sg-pop .3s cubic-bezier(.34,1.56,.64,1);color:#e8eaf0}
        @keyframes sg-pop{from{transform:scale(.92) translateY(30px);opacity:0}to{transform:none;opacity:1}}
        .sg-head{display:flex;align-items:center;gap:16px;margin-bottom:20px}
        .sg-icon{width:56px;height:56px;border-radius:18px;display:flex;align-items:center;justify-content:center;font-size:28px;flex-shrink:0}
        .sg-icon.block{background:rgba(255,77,109,.12);border:1px solid rgba(255,77,109,.3)}
        .sg-icon.warn{background:rgba(255,209,102,.1);border:1px solid rgba(255,209,102,.3)}
        .sg-title{font-size:22px;font-weight:900;letter-spacing:-.02em}
        .sg-sub{font-size:11px;color:#5c637a;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-top:4px}
        .sg-reason{background:#161925;border:1px solid #252a3a;border-radius:14px;padding:16px 20px;color:#a0a8be;font-size:13px;line-height:1.6;margin-bottom:16px}
        .sg-dets{display:flex;flex-direction:column;gap:10px;margin-bottom:24px;max-height:260px;overflow-y:auto}
        .sg-det{background:#0a0c12;border:1px solid #1e2230;border-radius:14px;padding:14px 18px;display:flex;align-items:flex-start;gap:12px}
        .sg-badge{padding:4px 10px;border-radius:30px;font-size:10px;font-weight:900;text-transform:uppercase;white-space:nowrap}
        .sg-badge.CRITICAL{background:rgba(255,77,109,.2);color:#ff4d6d}
        .sg-badge.HIGH{background:rgba(255,140,66,.18);color:#ff8c42}
        .sg-badge.MEDIUM{background:rgba(255,209,102,.15);color:#ffd166}
        .sg-badge.LOW{background:rgba(6,214,160,.12);color:#06d6a0}
        .sg-det-body{flex:1}
        .sg-det-name{font-size:14px;font-weight:800;margin-bottom:3px}
        .sg-det-val{font-family:monospace;font-size:11px;color:rgba(255,255,255,.35);word-break:break-all}
        .sg-act{display:flex;gap:12px}
        .sg-btn{flex:1;padding:14px;border-radius:14px;font-size:14px;font-weight:800;border:none;cursor:pointer;font-family:inherit;transition:all .15s}
        .sg-btn-edit{background:#1e2230;color:#fff;border:1px solid #2d334a}
        .sg-btn-edit:hover{background:#252a3a}
        .sg-btn-send{background:linear-gradient(135deg,#ff9966,#ff5e62);color:#fff;box-shadow:0 8px 20px rgba(255,94,98,.3)}
        #sg-toast{position:fixed;right:24px;bottom:24px;z-index:2147483647;background:#0f1117;border:2px solid #6c63ff;color:#fff;border-radius:14px;padding:14px 20px;min-width:220px;box-shadow:0 16px 40px rgba(0,0,0,.6);display:flex;flex-direction:column;gap:10px;animation:sg-tin .35s ease}
        @keyframes sg-tin{from{transform:translateX(40px);opacity:0}to{transform:none;opacity:1}}
        .sg-row{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:800}
        .sg-spinner{width:14px;height:14px;border:2.5px solid #6c63ff;border-top-color:transparent;border-radius:50%;animation:sg-spin .5s linear infinite}
        @keyframes sg-spin{to{transform:rotate(360deg)}}
        #sg-banner{position:fixed;top:0;left:0;right:0;z-index:2147483647;background:linear-gradient(135deg,#ff4d6d,#ff6b6b);color:#fff;padding:10px 20px;font-family:-apple-system,sans-serif;font-size:13px;font-weight:800;text-align:center;box-shadow:0 4px 20px rgba(255,77,109,.4);animation:sg-bin .3s ease}
        @keyframes sg-bin{from{transform:translateY(-100%)}to{transform:none}}
    `;
  document.head.appendChild(s);
}

/* ─────────────────── BACKEND CALL via Background Worker ─────────────────── */
function scan(payload) {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage(
        { type: 'SCAN_PAYLOAD', data: { payload, source_app: SOURCE_APP, destination: DESTINATION } },
        resp => {
          if (chrome.runtime.lastError || !resp?.success) {
            console.warn('[SentinelGate] Scan error:', chrome.runtime.lastError?.message);
            resolve({ action: 'ALLOW', detections: [], reason: 'Backend unreachable' });
          } else {
            resolve(resp.data);
          }
        }
      );
    } catch (e) {
      if (e.message && e.message.includes('Extension context invalidated')) {
        alert('🛡️ SentinelGate DLP was updated. Please refresh your browser tab (F5) to resume protection.');
      } else {
        console.warn('[SentinelGate] sendMessage failed:', e);
      }
      resolve({ action: 'ALLOW', detections: [], reason: 'Error' });
    }
  });
}

function scanFile(fileData, filename) {
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage(
        { type: 'SCAN_FILE', data: { file_data: fileData, filename, source_app: SOURCE_APP, destination: DESTINATION } },
        resp => {
          if (chrome.runtime.lastError || !resp?.success) {
            console.warn('[SentinelGate] File scan error:', chrome.runtime.lastError?.message);
            resolve({ action: 'ALLOW', detections: [], reason: 'Backend unreachable' });
          } else {
            resolve(resp.data);
          }
        }
      );
    } catch (e) {
      resolve({ action: 'ALLOW', detections: [], reason: 'Error' });
    }
  });
}

/* ─────────────────── UI ─────────────────── */
function esc(s) { return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function showToast(state) {
  injectCSS();
  let el = document.getElementById('sg-toast');
  if (!el) { el = document.createElement('div'); el.id = 'sg-toast'; document.body.appendChild(el); }
  el.innerHTML = state === 'scan'
    ? `<div class="sg-row"><div class="sg-spinner"></div><span>SENTINELGATE SCANNING...</span></div>`
    : `<div class="sg-row" style="color:#06d6a0">🛡️ CONTENT VERIFIED — CLEAN</div>`;
  if (state !== 'scan') setTimeout(() => el?.remove(), 1500);
}

function showBanner(msg, action = 'BLOCK') {
  injectCSS();
  let b = document.getElementById('sg-banner');
  if (!b) { b = document.createElement('div'); b.id = 'sg-banner'; document.body.prepend(b); }

  const isWarn = action === 'WARN';
  const bg = isWarn ? 'linear-gradient(135deg, #ffd166, #ffb703)' : 'linear-gradient(135deg, #ff4d6d, #ff6b6b)';
  const color = isWarn ? '#000' : '#fff';
  const prefix = isWarn ? '⚠️ SENTINELGATE WARNING:' : '🚨 SENTINELGATE BLOCKED:';

  b.style.background = bg;
  b.style.color = color;
  b.innerHTML = `${prefix} ${esc(msg)} &nbsp;<button id="sg-banner-dismiss" style="background:rgba(0,0,0,.15);border:none;color:inherit;padding:3px 10px;border-radius:6px;cursor:pointer;font-weight:800">✕ Dismiss</button>`;
  document.getElementById('sg-banner-dismiss').addEventListener('click', () => b.remove());
}

function showModal(data, onEdit) {
  document.getElementById('sg-overlay')?.remove();
  injectCSS();
  const o = document.createElement('div');
  o.id = 'sg-overlay';
  o.innerHTML = `<div id="sg-modal">
        <div class="sg-head">
            <div class="sg-icon block">🚫</div>
            <div><div class="sg-title">Access Blocked</div>
            <div class="sg-sub">SentinelGate DLP · ${esc(DESTINATION)}</div></div>
        </div>
        <div class="sg-reason">${esc(data.reason)}</div>
        <div class="sg-dets">${(data.detections || []).map(d => `
            <div class="sg-det">
                <span class="sg-badge ${d.severity}">${esc(d.severity)}</span>
                <div class="sg-det-body">
                    <div class="sg-det-name">${esc(d.data_type)}</div>
                    <div class="sg-det-val">${esc(d.redacted_value)}</div>
                </div>
            </div>`).join('')}</div>
        <div class="sg-act">
            <button class="sg-btn sg-btn-edit" id="sg-edit" style="flex:1">✏️ Edit Message</button>
        </div>
    </div>`;
  document.body.appendChild(o);
  document.getElementById('sg-edit').addEventListener('click', () => { o.remove(); onEdit(); });
}

/* ─────────────────── PAYLOAD GETTER ─────────────────── */
function getPayload() {
  // ChatGPT #prompt-textarea is a contenteditable div
  const el = document.getElementById('prompt-textarea')
    || document.querySelector('[contenteditable="true"]')
    || document.querySelector('textarea')
    || document.querySelector('input[type="text"]')
    || document.querySelector('input[type="search"]');

  if (!el) return '';
  const v = el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' ? el.value : (el.innerText || el.textContent);
  return (v || '').trim();
}

/* ─────────────────── CORE INTERCEPTOR ─────────────────── */
let _busy = false;
let _allowed = false;

async function intercept(payload, retrigger) {
  if (!payload || payload.trim().length < 2) {
    retrigger();
    return;
  }
  if (_busy) return;
  _busy = true;
  showToast('scan');
  console.log('[SentinelGate] Scanning:', payload.slice(0, 60) + (payload.length > 60 ? '...' : ''));

  const result = await scan(payload);
  _busy = false;
  document.getElementById('sg-toast')?.remove();

  console.log('[SentinelGate] Result:', result.action);

  if (result.action === 'ALLOW') {
    showToast('ok');
    document.getElementById('sg-banner')?.remove();
    _allowed = true;
    retrigger();
    setTimeout(() => { _allowed = false; }, 600);
  } else {
    showModal(result, () => { /* user chose edit — message stays in input */ });
  }
}

const SCANNABLE_EXTENSIONS = ['txt', 'doc', 'docx', 'pdf'];

function getFileExt(filename) {
  return (filename || '').split('.').pop().toLowerCase();
}

function isScannableFile(file) {
  if (!file || !file.name) return false;
  return SCANNABLE_EXTENSIONS.includes(getFileExt(file.name));
}

async function interceptFile(file, retrigger) {
  if (_busy || !file || !isScannableFile(file)) {
    retrigger();
    return;
  }

  _busy = true;
  showToast('scan');
  console.log('[SentinelGate] Scanning File:', file.name, '(' + (file.size / 1024).toFixed(1) + ' KB)');

  const reader = new FileReader();
  reader.onload = async (e) => {
    const base64 = e.target.result;
    const result = await scanFile(base64, file.name);
    _busy = false;
    document.getElementById('sg-toast')?.remove();

    console.log('[SentinelGate] File Scan Result:', result.action);

    if (result.action === 'ALLOW') {
      showToast('ok');
      document.getElementById('sg-banner')?.remove();
      _allowed = true;
      retrigger();
      setTimeout(() => { _allowed = false; }, 600);
    } else {
      showModal(result, () => { console.log('File blocked edit clicked'); });
    }
  };
  reader.readAsDataURL(file);
}

/* ─────────────────── LIVE SCANNING (as you type) ─────────────────── */
let _debounce = null;
let _lastText = '';

function setupLiveScanner() {
  document.addEventListener('input', e => {
    const t = e.target;
    if (!(t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;

    // Skip login/auth fields — typing your email to sign in is NOT a data leak
    if (isLoginField(t)) return;

    const text = (t.value || t.innerText || '').trim();
    if (!text || text === _lastText || text.length < 5) return;
    _lastText = text;

    clearTimeout(_debounce);
    _debounce = setTimeout(async () => {
      const r = await scan(text);
      if (r.action !== 'ALLOW') {
        const types = (r.detections || []).map(d => d.data_type).join(', ');
        showBanner(`${r.action}: ${types} detected — remove before sending`, r.action);
      } else {
        document.getElementById('sg-banner')?.remove();
      }
    }, 700);
  }, true);
}

/* ─────────────────── EVENT HOOKS ─────────────────── */
// ==========================================
// SPA Network Hooks (fetch & XHR overrides)
// ==========================================
function setupNetworkHooks() {
  // Inject script to override window.fetch and XMLHttpRequest in the main page context
  const injectScript = document.createElement('script');
  injectScript.textContent = `
  (function() {
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
      let payload = "";
      if (args[1] && args[1].body && typeof args[1].body === 'string') {
        payload = args[1].body;
      }

      if (payload && payload.length > 5) {
        return new Promise((resolve, reject) => {
          const id = Math.random().toString(36).substring(7);
          
          const listener = (event) => {
            if (event.source !== window || event.data.type !== 'FROM_CONTENT_SCRIPT' || event.data.id !== id) return;
            window.removeEventListener('message', listener);
            
            if (event.data.action === 'BLOCK') {
              console.error('[SentinelGate] Blocked outgoing fetch request containing sensitive data.');
              reject(new Error('SentinelGate DLP Block: Sensitive data detected.'));
            } else {
              resolve(originalFetch.apply(this, args));
            }
          };
          
          window.addEventListener('message', listener);
          window.postMessage({ type: 'FROM_PAGE_SCRIPT', payload: payload, id: id }, '*');
        });
      }

      return originalFetch.apply(this, args);
    };

    const originalXHR = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
      if (body && typeof body === 'string' && body.length > 5) {
        const xhrSource = this;
        const args = arguments;
        const id = Math.random().toString(36).substring(7);
          
        const listener = (event) => {
          if (event.source !== window || event.data.type !== 'FROM_CONTENT_SCRIPT' || event.data.id !== id) return;
          window.removeEventListener('message', listener);
          
          if (event.data.action === 'BLOCK') {
              console.error('[SentinelGate] Blocked outgoing XHR request containing sensitive data.');
              // Abort silently from the app's perspective
          } else {
              originalXHR.apply(xhrSource, args);
          }
        };
        
        window.addEventListener('message', listener);
        window.postMessage({ type: 'FROM_PAGE_SCRIPT', payload: body, id: id }, '*');
        return; 
      }
      return originalXHR.apply(this, arguments);
    };
  })();
  `;
  (document.head || document.documentElement).appendChild(injectScript);
  injectScript.remove();

  // Bridge between the injected script (page world) and background worker
  window.addEventListener('message', (event) => {
    if (event.source !== window || event.data.type !== 'FROM_PAGE_SCRIPT') return;

    chrome.runtime.sendMessage(
      { type: 'SCAN_PAYLOAD', data: { payload: event.data.payload, source_app: 'Background Network', destination: window.location.hostname } },
      (result) => {
        if (chrome.runtime.lastError || !result || !result.success) {
          window.postMessage({ type: 'FROM_CONTENT_SCRIPT', action: 'ALLOW', id: event.data.id }, '*');
          return;
        }

        const data = result.data;
        if (data.action === 'BLOCK') {
          showModal(data, () => { });
        } else if (data.action === 'WARN') {
          showBanner(data.action + ': Sensitive data detected in background request.');
        }

        window.postMessage({ type: 'FROM_CONTENT_SCRIPT', action: data.action, id: event.data.id }, '*');
      }
    );
  });
}

function setupHooks() {
  // HOOK 1: Enter key on any text input
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' || e.shiftKey || _allowed) return;

    if (_busy) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }

    const t = e.target;
    if (!(t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;

    const text = (t.value || t.innerText || t.textContent || '').trim();
    if (!text || text.length < 3) return;

    console.log('[SentinelGate] Enter intercepted on', t.tagName, t.id || '');
    e.preventDefault();
    e.stopImmediatePropagation();

    intercept(text, () => {
      t.dispatchEvent(new KeyboardEvent('keydown', {
        key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true
      }));
      if (t.form) {
        try { t.form.submit(); } catch (_) { }
      }
    });
  }, true);

  // HOOK 2: Click on send/submit buttons
  document.addEventListener('click', e => {
    if (_allowed) return;

    if (_busy) {
      // Don't allow clicks to bypass while already scanning
      const btnCheck = e.target.closest('button, input[type="submit"], [role="button"]');
      if (btnCheck) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
      return;
    }

    const btn = e.target.closest('button, input[type="submit"], [role="button"]');
    if (!btn) return;

    const label = (btn.innerText || btn.value || btn.getAttribute('aria-label') || '').toLowerCase();
    const testId = btn.getAttribute('data-testid') || '';
    const isSend = /^(send|submit|post|search|go|login|sign\s*in|tweet|confirm)$/i.test(label.trim())
      || /send|submit/i.test(label)
      || testId.includes('send')
      || (!!btn.querySelector('svg') && !label.includes('cancel') && !label.includes('close') && !label.includes('menu'));

    if (!isSend) return;

    const payload = getPayload();
    if (!payload || payload.length < 3) return;

    console.log('[SentinelGate] Button intercepted:', label || testId, '| Payload:', payload.slice(0, 50));
    e.preventDefault();
    e.stopImmediatePropagation();

    intercept(payload, () => {
      btn.click(); // _allowed=true prevents re-interception
    });
  }, true);

  // HOOK 3: Traditional form submit
  document.addEventListener('submit', e => {
    if (_allowed) return;

    if (_busy) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }

    let text = '';
    e.target.querySelectorAll('input:not([type=hidden]), textarea').forEach(el => { text += (el.value || '') + ' '; });
    text = text.trim();
    if (!text || text.length < 3) return;

    console.log('[SentinelGate] Form submit intercepted');
    e.preventDefault();
    e.stopImmediatePropagation();
    intercept(text, () => { try { e.target.submit(); } catch (_) { } });
  }, true);

  // HOOK 4: Paste interception (text + files)
  // Scans ALL paste events on ALL sites (auth domains already excluded at init)
  document.addEventListener('paste', e => {
    if (_allowed || _busy) return;

    const clipboardData = e.clipboardData || e.originalEvent?.clipboardData;
    if (!clipboardData) return;

    // Check for file pastes first (existing behavior)
    const items = clipboardData.items;
    for (let index in items) {
      const item = items[index];
      if (item.kind === 'file') {
        const file = item.getAsFile();
        if (file && isScannableFile(file)) {
          e.preventDefault();
          e.stopImmediatePropagation();
          interceptFile(file, () => {
            alert('SentinelGate: File scanned and approved. Please paste it again to upload.');
          });
          return;
        }
      }
    }

    // Scan ALL text pastes for sensitive data (system-wide protection)
    const pastedText = clipboardData.getData('text/plain');
    if (pastedText && pastedText.trim().length >= 5) {
      // Skip if target is a login field
      const target = e.target;
      if (target && isLoginField(target)) return;

      e.preventDefault();
      e.stopImmediatePropagation();
      console.log('[SentinelGate] Paste intercepted on', DESTINATION, '| Length:', pastedText.length);

      intercept(pastedText, () => {
        // Paste approved — insert the text manually since we prevented the default
        const active = document.activeElement;
        if (active) {
          if (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA') {
            // Insert at cursor position in input/textarea
            const start = active.selectionStart;
            const end = active.selectionEnd;
            const before = active.value.substring(0, start);
            const after = active.value.substring(end);
            active.value = before + pastedText + after;
            active.selectionStart = active.selectionEnd = start + pastedText.length;
            active.dispatchEvent(new Event('input', { bubbles: true }));
          } else if (active.isContentEditable) {
            // Insert into contenteditable (WhatsApp, ChatGPT, etc.)
            document.execCommand('insertText', false, pastedText);
          }
        }
      });
    }
  }, true);

  // HOOK 5: Drop files (Drag and Drop)
  document.addEventListener('drop', e => {
    if (_allowed || _busy) return;
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (isScannableFile(file)) {
        e.preventDefault();
        e.stopImmediatePropagation();
        interceptFile(file, () => {
          alert('SentinelGate: File scanned and approved. Please drop it again to upload.');
        });
      }
    }
  }, true);

  // HOOK 6: File inputs
  document.addEventListener('change', e => {
    if (_allowed || _busy) return;
    const t = e.target;
    if (t.tagName === 'INPUT' && t.type === 'file' && t.files && t.files.length > 0) {
      const file = t.files[0];
      if (isScannableFile(file)) {
        e.preventDefault();
        e.stopImmediatePropagation();
        interceptFile(file, () => {
          // Note: for file inputs, if it's approved, we can't easily re-set the 
          // value to the same file without the user picking it again for security.
          // But since we didn't clear it yet, we just allow it to proceed.
          _allowed = true;
          // Trigger the change event again if needed, but usually just allow.
        });
      }
    }
  }, true);
}

/* ─────────────────── INIT ─────────────────── */
function init() {
  // Skip entirely on trusted auth/login domains
  if (isTrustedDomain()) {
    console.log('[SentinelGate] ✅ Trusted auth domain — skipping DLP hooks on', DESTINATION);
    return;
  }

  console.log('[SentinelGate] DOM ready — initializing hooks on', DESTINATION);
  setupLiveScanner();
  setupHooks();
  setupNetworkHooks();
}

// document_start: DOM might not exist yet
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init(); // DOM already ready (e.g. document_idle fallback)
}

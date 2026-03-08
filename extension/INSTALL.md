# SentinelGate Chrome Extension — Installation Guide

## How to Load in Chrome / Edge

1. Open Chrome and go to:
   ```
   chrome://extensions/
   ```

2. Enable **Developer mode** (toggle in the top-right corner)

3. Click **"Load unpacked"**

4. Select this folder:
   ```
   C:\Users\Ajay\Desktop\KLLLLLLLL\sentinelgate\extension\
   ```

5. The SentinelGate shield icon will appear in your browser toolbar.

---

## Before Using

Make sure the SentinelGate backend is running:
```bash
cd C:\Users\Ajay\Desktop\KLLLLLLLL\sentinelgate
python dashboard.py
```

Dashboard: http://127.0.0.1:5000

---

## How It Works on ChatGPT

1. Go to **https://chatgpt.com** or **https://chat.openai.com**
2. Type a message containing sensitive data (e.g. an API key, password, credit card number)
3. Press **Enter** or click **Send**
4. SentinelGate intercepts the message **before** it's sent
5. A modal popup appears showing what was detected and the action (BLOCK / WARN)
6. You can **Edit Message** (recommended) or **Send Anyway**

---

## What Gets Detected

| Type | Severity | Action |
|------|----------|--------|
| API Keys, AWS Keys, GitHub Tokens | CRITICAL | BLOCK |
| JWT Tokens, Bearer Tokens, Passwords, Credit Cards, SSNs | HIGH | BLOCK |
| Email Addresses, Phone Numbers | MEDIUM | WARN |
| Internal IP Addresses | LOW | WARN |
| Normal Text | — | ALLOW ✅ |

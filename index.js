const express = require('express');
const { createHmac } = require('crypto');
const app = express();
app.use(express.json());

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', [
    'Content-Type',
    'x-bitget-key', 'x-bitget-secret', 'x-bitget-passphrase',
    'x-bybit-key',  'x-bybit-secret',
    'x-bingx-key',  'x-bingx-secret',
    'x-blofin-key', 'x-blofin-secret', 'x-blofin-passphrase',
  ].join(', '));
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── BITGET ────────────────────────────────────────────────────────────────────
// Frontend punta a: https://bitget-proxy-mze2.onrender.com?endpoint=/api/v2/...
app.all('/', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint || !endpoint.startsWith('/api/v2/')) {
    return res.json({ error: 'Endpoint non valido' });
  }
  const apiKey     = req.headers['x-bitget-key']        || '';
  const secret     = req.headers['x-bitget-secret']     || '';
  const passphrase = req.headers['x-bitget-passphrase'] || '';
  if (!apiKey || !secret) return res.json({ error: 'Chiavi mancanti' });

  const method = req.method === 'POST' ? 'POST' : 'GET';
  const ts = String(Date.now());
  let requestPath, bodyStr = '';

  if (method === 'GET') {
    const params = { ...req.query };
    delete params.endpoint;
    const qstr = Object.keys(params).length ? '?' + new URLSearchParams(params).toString() : '';
    requestPath = endpoint + qstr;
  } else {
    bodyStr     = req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : '{}';
    requestPath = endpoint;
  }

  const preSign   = ts + method + requestPath + bodyStr;
  const signature = createHmac('sha256', secret).update(preSign).digest('base64');

  try {
    const response = await fetch(`https://api.bitget.com${requestPath}`, {
      method,
      headers: {
        'ACCESS-KEY':        apiKey,
        'ACCESS-SIGN':       signature,
        'ACCESS-TIMESTAMP':  ts,
        'ACCESS-PASSPHRASE': passphrase,
        'Content-Type':      'application/json',
        'locale':            'en-US',
      },
      ...(method === 'POST' ? { body: bodyStr } : {}),
    });
    res.json(await response.json());
  } catch (e) {
    res.json({ error: e.message });
  }
});

// ── BYBIT ─────────────────────────────────────────────────────────────────────
// Frontend punta a: .../bybit?endpoint=/v5/...
// Firma: HMAC-SHA256(timestamp + apiKey + recvWindow + queryString|body)
app.all('/bybit', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint) return res.json({ error: 'Endpoint mancante' });

  const apiKey = req.headers['x-bybit-key']    || '';
  const secret = req.headers['x-bybit-secret'] || '';
  if (!apiKey || !secret) return res.json({ error: 'Chiavi mancanti' });

  const method     = req.method === 'POST' ? 'POST' : 'GET';
  const ts         = String(Date.now());
  const recvWindow = '5000';
  let   url, bodyStr = '', signPayload;

  if (method === 'GET') {
    const params = { ...req.query };
    delete params.endpoint;
    const qstr = Object.keys(params).length ? new URLSearchParams(params).toString() : '';
    url         = `https://api.bybit.com${endpoint}${qstr ? '?' + qstr : ''}`;
    signPayload = ts + apiKey + recvWindow + qstr;
  } else {
    bodyStr     = req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : '{}';
    url         = `https://api.bybit.com${endpoint}`;
    signPayload = ts + apiKey + recvWindow + bodyStr;
  }

  const signature = createHmac('sha256', secret).update(signPayload).digest('hex');

  try {
    const response = await fetch(url, {
      method,
      headers: {
        'X-BAPI-API-KEY':   apiKey,
        'X-BAPI-SIGN':      signature,
        'X-BAPI-TIMESTAMP': ts,
        'X-BAPI-RECV-WINDOW': recvWindow,
        'Content-Type':     'application/json',
      },
      ...(method === 'POST' ? { body: bodyStr } : {}),
    });
    res.json(await response.json());
  } catch (e) {
    res.json({ error: e.message });
  }
});

// ── BINGX ─────────────────────────────────────────────────────────────────────
// Frontend punta a: .../bingx?endpoint=/openApi/swap/...&param1=x&param2=y
// Firma: HMAC-SHA256 in hex su stringa parametri ordinati alfabeticamente + timestamp
// IMPORTANTE: BingX usa SEMPRE query string (anche per POST), mai body JSON
app.all('/bingx', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint) return res.json({ error: 'Endpoint mancante' });

  const apiKey = req.headers['x-bingx-key']    || '';
  const secret = req.headers['x-bingx-secret'] || '';
  if (!apiKey || !secret) return res.json({ error: 'Chiavi mancanti' });

  const method = req.method === 'POST' ? 'POST' : 'GET';
  const ts     = String(Date.now());

  // Raccogli tutti i parametri: query string + body (se POST)
  const params = { ...req.query };
  delete params.endpoint;

  // Se POST, merge anche il body
  if (method === 'POST' && req.body && Object.keys(req.body).length) {
    Object.assign(params, req.body);
  }

  // Aggiungi timestamp
  params.timestamp = ts;

  // Firma: tutti i parametri ordinati alfabeticamente come "key=value&key=value"
  const sortedStr = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  const signature = createHmac('sha256', secret).update(sortedStr).digest('hex');

  // BingX vuole SEMPRE i parametri in query string, anche per POST
  const url = `https://open-api.bingx.com${endpoint}?${sortedStr}&signature=${signature}`;

  try {
    const response = await fetch(url, {
      method,
      headers: {
        'X-BX-APIKEY':  apiKey,
        'Content-Type': 'application/json',
      },
      // POST senza body — i parametri sono già nella query string
    });
    res.json(await response.json());
  } catch (e) {
    res.json({ error: e.message });
  }
});

// ── BLOFIN ────────────────────────────────────────────────────────────────────
// Frontend punta a: .../blofin?endpoint=/api/v1/...
// Firma: HMAC-SHA256(timestamp + method + requestPath + body)  → base64
// Header extra: x-blofin-passphrase (MD5 della passphrase, già gestito lato client di solito)
app.all('/blofin', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint) return res.json({ error: 'Endpoint mancante' });

  const apiKey     = req.headers['x-blofin-key']        || '';
  const secret     = req.headers['x-blofin-secret']     || '';
  const passphrase = req.headers['x-blofin-passphrase'] || '';
  if (!apiKey || !secret) return res.json({ error: 'Chiavi mancanti' });

  const method = req.method === 'POST' ? 'POST' : 'GET';
  const ts     = String(Date.now());
  let   url, bodyStr = '', requestPath;

  if (method === 'GET') {
    const params = { ...req.query };
    delete params.endpoint;
    const qstr  = Object.keys(params).length ? '?' + new URLSearchParams(params).toString() : '';
    requestPath = endpoint + qstr;
    url         = `https://openapi.blofin.com${requestPath}`;
  } else {
    bodyStr     = req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : '{}';
    requestPath = endpoint;
    url         = `https://openapi.blofin.com${endpoint}`;
  }

  const preSign   = ts + method + requestPath + (method === 'POST' ? bodyStr : '');
  const signature = createHmac('sha256', secret).update(preSign).digest('base64');

  try {
    const response = await fetch(url, {
      method,
      headers: {
        'ACCESS-KEY':        apiKey,
        'ACCESS-SIGN':       signature,
        'ACCESS-TIMESTAMP':  ts,
        'ACCESS-PASSPHRASE': passphrase,
        'Content-Type':      'application/json',
      },
      ...(method === 'POST' ? { body: bodyStr } : {}),
    });
    res.json(await response.json());
  } catch (e) {
    res.json({ error: e.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Proxy running'))

const express = require('express');
const { createHmac } = require('crypto');
const app = express();
app.use(express.json());

// ── CORS ──
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

// ══════════════════════════════════════════════
// BITGET  —  route: /  (legacy, invariato)
// ══════════════════════════════════════════════
app.all('/', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint || !endpoint.startsWith('/api/v2/mix/')) {
    return res.json({ error: 'Endpoint non valido' });
  }

  const apiKey     = req.headers['x-bitget-key']        || '';
  const secret     = req.headers['x-bitget-secret']     || '';
  const passphrase = req.headers['x-bitget-passphrase'] || '';
  if (!apiKey || !secret) return res.json({ error: 'Chiavi mancanti' });

  const method = req.method === 'POST' ? 'POST' : 'GET';
  const ts     = String(Date.now());
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
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// ══════════════════════════════════════════════
// BYBIT  —  route: /bybit
// Firma: HMAC-SHA256( ts + apiKey + recvWindow + queryString )
// Headers: X-BAPI-API-KEY, X-BAPI-SIGN, X-BAPI-TIMESTAMP, X-BAPI-RECV-WINDOW
// Nessuna passphrase.
// ══════════════════════════════════════════════
app.all('/bybit', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint) return res.json({ error: 'Endpoint mancante' });

  const apiKey    = req.headers['x-bybit-key']    || '';
  const secret    = req.headers['x-bybit-secret'] || '';
  if (!apiKey || !secret) return res.json({ error: 'Chiavi Bybit mancanti' });

  const method     = req.method === 'POST' ? 'POST' : 'GET';
  const ts         = String(Date.now());
  const recvWindow = '5000';
  let requestPath, bodyStr = '', signPayload = '';

  if (method === 'GET') {
    const params = { ...req.query };
    delete params.endpoint;
    const qstr = Object.keys(params).length ? new URLSearchParams(params).toString() : '';
    requestPath  = endpoint + (qstr ? '?' + qstr : '');
    signPayload  = ts + apiKey + recvWindow + qstr;
  } else {
    bodyStr      = req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : '';
    requestPath  = endpoint;
    signPayload  = ts + apiKey + recvWindow + bodyStr;
  }

  const signature = createHmac('sha256', secret).update(signPayload).digest('hex');

  try {
    const response = await fetch(`https://api.bybit.com${requestPath}`, {
      method,
      headers: {
        'X-BAPI-API-KEY':      apiKey,
        'X-BAPI-SIGN':         signature,
        'X-BAPI-TIMESTAMP':    ts,
        'X-BAPI-RECV-WINDOW':  recvWindow,
        'Content-Type':        'application/json',
      },
      ...(method === 'POST' ? { body: bodyStr } : {}),
    });
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// ══════════════════════════════════════════════
// BINGX  —  route: /bingx
// Firma: HMAC-SHA256( queryString + body ) — signature va nella query
// Header: X-BX-APIKEY
// Nessuna passphrase.
// ══════════════════════════════════════════════
app.all('/bingx', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint) return res.json({ error: 'Endpoint mancante' });

  const apiKey = req.headers['x-bingx-key']    || '';
  const secret = req.headers['x-bingx-secret'] || '';
  if (!apiKey || !secret) return res.json({ error: 'Chiavi BingX mancanti' });

  const method = req.method === 'POST' ? 'POST' : 'GET';
  const ts     = String(Date.now());

  // Costruisci parametri query (escludi 'endpoint', aggiungi timestamp)
  const queryParams = { ...req.query };
  delete queryParams.endpoint;
  queryParams.timestamp = ts;

  let bodyStr = '';
  let signStr = '';

  if (method === 'GET') {
    signStr = new URLSearchParams(queryParams).toString();
  } else {
    // Per POST: body JSON, firma = queryString + rawBody
    bodyStr = req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : '';
    signStr = new URLSearchParams(queryParams).toString() + bodyStr;
  }

  const signature  = createHmac('sha256', secret).update(signStr).digest('hex');
  queryParams.signature = signature;

  const qstr       = new URLSearchParams(queryParams).toString();
  const requestUrl = `https://open-api.bingx.com${endpoint}?${qstr}`;

  try {
    const response = await fetch(requestUrl, {
      method,
      headers: {
        'X-BX-APIKEY':   apiKey,
        'Content-Type':  'application/json',
      },
      ...(method === 'POST' ? { body: bodyStr } : {}),
    });
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// ══════════════════════════════════════════════
// BLOFIN  —  route: /blofin
// Firma: HMAC-SHA256( ts + method + path + body ) → base64
// Headers: ACCESS-KEY, ACCESS-SIGN, ACCESS-TIMESTAMP, ACCESS-PASSPHRASE
// Passphrase obbligatoria.
// ══════════════════════════════════════════════
app.all('/blofin', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint) return res.json({ error: 'Endpoint mancante' });

  const apiKey     = req.headers['x-blofin-key']        || '';
  const secret     = req.headers['x-blofin-secret']     || '';
  const passphrase = req.headers['x-blofin-passphrase'] || '';
  if (!apiKey || !secret || !passphrase) return res.json({ error: 'Chiavi Blofin mancanti (key + secret + passphrase)' });

  const method = req.method === 'POST' ? 'POST' : 'GET';
  const ts     = String(Date.now());
  let requestPath, bodyStr = '';

  if (method === 'GET') {
    const params = { ...req.query };
    delete params.endpoint;
    const qstr  = Object.keys(params).length ? '?' + new URLSearchParams(params).toString() : '';
    requestPath = endpoint + qstr;
    bodyStr     = '';
  } else {
    bodyStr     = req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : '';
    requestPath = endpoint;
  }

  const preSign   = ts + method + requestPath + bodyStr;
  const signature = createHmac('sha256', secret).update(preSign).digest('base64');

  try {
    const response = await fetch(`https://openapi.blofin.com${requestPath}`, {
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
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.json({ error: e.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Proxy running on port ' + (process.env.PORT || 3000)));

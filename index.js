const express = require('express');
const { createHmac } = require('crypto');
const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-bitget-key, x-bitget-secret, x-bitget-passphrase, x-bybit-key, x-bybit-secret, x-bybit-demo');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.all('/', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint) return res.json({ error: 'Endpoint mancante' });

  // ─── BYBIT (live + demo) ───────────────────────────────────────
  const bybitKey    = req.headers['x-bybit-key']    || '';
  const bybitSecret = req.headers['x-bybit-secret'] || '';
  const bybitDemo   = req.headers['x-bybit-demo']   === 'true';

  if (bybitKey && bybitSecret) {
    if (!endpoint.startsWith('/v5/')) return res.json({ error: 'Endpoint Bybit non valido' });

    const method = req.method === 'POST' ? 'POST' : 'GET';
    const ts     = String(Date.now());
    const recvWindow = '5000';

    let bodyStr = '';
    let queryStr = '';

    if (method === 'GET') {
      const params = { ...req.query };
      delete params.endpoint;
      queryStr = Object.keys(params).length ? new URLSearchParams(params).toString() : '';
    } else {
      bodyStr = req.body && Object.keys(req.body).length ? JSON.stringify(req.body) : '';
    }

    // Bybit V5 signature: timestamp + apiKey + recvWindow + (queryString | body)
    const signPayload = ts + bybitKey + recvWindow + (method === 'GET' ? queryStr : bodyStr);
    const signature   = createHmac('sha256', bybitSecret).update(signPayload).digest('hex');

    const baseUrl = bybitDemo ? 'https://api-demo.bybit.com' : 'https://api.bybit.com';
    const fullUrl = queryStr ? `${baseUrl}${endpoint}?${queryStr}` : `${baseUrl}${endpoint}`;

    try {
      const response = await fetch(fullUrl, {
        method,
        headers: {
          'X-BAPI-API-KEY':     bybitKey,
          'X-BAPI-SIGN':        signature,
          'X-BAPI-TIMESTAMP':   ts,
          'X-BAPI-RECV-WINDOW': recvWindow,
          'Content-Type':       'application/json',
        },
        ...(method === 'POST' ? { body: bodyStr || '{}' } : {}),
      });
      const data = await response.json();
      return res.json(data);
    } catch(e) {
      return res.json({ error: e.message });
    }
  }

  // ─── BITGET ───────────────────────────────────────────────────
  const apiKey     = req.headers['x-bitget-key']        || '';
  const secret     = req.headers['x-bitget-secret']     || '';
  const passphrase = req.headers['x-bitget-passphrase'] || '';

  if (!endpoint.startsWith('/api/v2/mix/')) return res.json({ error: 'Endpoint non valido' });
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
    const data = await response.json();
    res.json(data);
  } catch(e) {
    res.json({ error: e.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Proxy running'));

const express = require('express');
const { createHmac } = require('crypto');
const app = express();

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-bitget-key, x-bitget-secret, x-bitget-passphrase');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint || !endpoint.startsWith('/api/v2/mix/')) {
    return res.json({ error: 'Endpoint non valido' });
  }

  const apiKey     = req.headers['x-bitget-key'] || '';
  const secret     = req.headers['x-bitget-secret'] || '';
  const passphrase = req.headers['x-bitget-passphrase'] || '';

  if (!apiKey || !secret) return res.json({ error: 'Chiavi mancanti' });

  const params = { ...req.query };
  delete params.endpoint;
  const qstr = Object.keys(params).length ? '?' + new URLSearchParams(params).toString() : '';
  const requestPath = endpoint + qstr;

  const ts = String(Date.now());
  const preSign = ts + 'GET' + requestPath;
  const signature = createHmac('sha256', secret).update(preSign).digest('base64');

  try {
    const response = await fetch(`https://api.bitget.com${requestPath}`, {
      headers: {
        'ACCESS-KEY':        apiKey,
        'ACCESS-SIGN':       signature,
        'ACCESS-TIMESTAMP':  ts,
        'ACCESS-PASSPHRASE': passphrase,
        'Content-Type':      'application/json',
      }
    });
    const data = await response.json();
    res.json(data);
  } catch(e) {
    res.json({ error: e.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Proxy running'));

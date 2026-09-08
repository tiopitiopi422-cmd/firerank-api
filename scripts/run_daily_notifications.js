'use strict';

const baseUrl = String(process.env.FIRERANK_API_BASE_URL || 'https://firerank-api-oxy1.onrender.com').replace(/\/$/, '');
const secret = String(process.env.FIRERANK_CRON_SECRET || '').trim();

if (!secret) {
  console.error('FIRERANK_CRON=INTERNAL_SECRET_MISSING');
  process.exitCode = 2;
} else {
  fetch(`${baseUrl}/api/internal/daily-notifications`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'x-firerank-cron-secret': secret,
    },
    body: '{}',
  })
    .then(async (response) => {
      const text = await response.text();
      if (!response.ok) throw new Error(`HTTP_${response.status}:${text.slice(0, 300)}`);
      console.log(`FIRERANK_DAILY_NOTIFICATIONS=SUCCESS ${text.slice(0, 600)}`);
    })
    .catch((error) => {
      console.error(`FIRERANK_DAILY_NOTIFICATIONS=ERROR ${error.message}`);
      process.exitCode = 1;
    });
}

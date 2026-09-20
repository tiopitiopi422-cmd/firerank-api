'use strict';

const baseUrl = String(process.env.FIRERANK_API_BASE_URL || 'https://firerank-api-oxy1.onrender.com').replace(/\/$/, '');
const secret = String(process.env.FIRERANK_CRON_SECRET || '').trim();

if (!secret) {
  console.error('FIRERANK_NOTIFICATION_OUTBOX=CRON_SECRET_MISSING');
  process.exitCode = 2;
} else {
  fetch(`${baseUrl}/api/internal/notification-outbox`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'x-firerank-cron-secret': secret,
    },
    body: JSON.stringify({ limit: 50 }),
  })
    .then(async (response) => {
      const text = await response.text();
      if (!response.ok) throw new Error(`HTTP_${response.status}:${text.slice(0, 300)}`);
      console.log(`FIRERANK_NOTIFICATION_OUTBOX=SUCCESS ${text.slice(0, 800)}`);
    })
    .catch((error) => {
      console.error(`FIRERANK_NOTIFICATION_OUTBOX=ERROR ${error.message}`);
      process.exitCode = 1;
    });
}

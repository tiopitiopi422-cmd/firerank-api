'use strict';
const baseUrl=String(process.env.FIRERANK_API_BASE_URL||'https://firerank-api-oxy1.onrender.com').replace(/\/$/,'');
const secret=String(process.env.FIRERANK_CRON_SECRET||'').trim();
if(!secret){console.error('FIRERANK_DB17_MAINTENANCE=CRON_SECRET_MISSING');process.exitCode=2;}else{fetch(`${baseUrl}/api/internal/db17-maintenance`,{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json','x-firerank-cron-secret':secret},body:JSON.stringify({limit:100})}).then(async r=>{const t=await r.text();if(!r.ok)throw new Error(`HTTP_${r.status}:${t.slice(0,300)}`);console.log(`FIRERANK_DB17_MAINTENANCE=SUCCESS ${t.slice(0,800)}`)}).catch(e=>{console.error(`FIRERANK_DB17_MAINTENANCE=ERROR ${e.message}`);process.exitCode=1;});}

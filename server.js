require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

const app = express();

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

const PORT = Number(process.env.PORT || 10000);

const APP_BASE_URL =
  process.env.APP_BASE_URL ||
  "https://firerank-api-production.up.railway.app";

const MP_PUBLIC_KEY = process.env.MERCADO_PAGO_PUBLIC_KEY || "";
const MP_ACCESS_TOKEN = process.env.MERCADO_PAGO_ACCESS_TOKEN || "";

const FIREBASE_DATABASE_URL = process.env.FIREBASE_DATABASE_URL || "";
const FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 =
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 || "";
const FIREBASE_SERVICE_ACCOUNT_JSON =
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON || "";
const FIREBASE_WEB_API_KEY = process.env.FIREBASE_WEB_API_KEY || "";

const PAYMENT_SUCCESS_URL =
  process.env.PAYMENT_SUCCESS_URL || `${APP_BASE_URL}/success`;
const PAYMENT_PENDING_URL =
  process.env.PAYMENT_PENDING_URL || `${APP_BASE_URL}/pending`;
const PAYMENT_FAILURE_URL =
  process.env.PAYMENT_FAILURE_URL || `${APP_BASE_URL}/failure`;

const MP_WEBHOOK_URL =
  process.env.MP_WEBHOOK_URL ||
  process.env.MERCADO_PAGO_WEBHOOK_URL ||
  `${APP_BASE_URL}/api/mercadopago/webhook`;

const PASSWORD_RESET_URL =
  process.env.PASSWORD_RESET_URL || `${APP_BASE_URL}/reset-password`;

const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_SECURE = String(process.env.SMTP_SECURE || "true").toLowerCase() === "true";
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || "FireRank";
const MAIL_FROM_EMAIL = process.env.MAIL_FROM_EMAIL || SMTP_USER || "";
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || MAIL_FROM_EMAIL || "";

const DAY_MS = 24 * 60 * 60 * 1000;

const passwordResetThrottle = new Map();

function safe(v) {
  return String(v ?? "").trim();
}

function toNumber(v) {
  const n = Number(String(v ?? "").replace(",", ".").trim());
  return Number.isFinite(n) ? n : 0;
}

function nowMs() {
  return Date.now();
}

function isValidEmail(email) {
  const e = safe(email).toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function maskEmail(email) {
  const e = safe(email);
  const parts = e.split("@");
  if (parts.length !== 2) return e;
  const name = parts[0];
  const domain = parts[1];
  const visible = name.length <= 2 ? name[0] || "*" : `${name[0]}${name[1]}`;
  return `${visible}***@${domain}`;
}

function mpHeaders() {
  return {
    Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
    "Content-Type": "application/json",
  };
}

function ensureMP() {
  if (!MP_ACCESS_TOKEN) {
    throw new Error("MERCADO_PAGO_ACCESS_TOKEN não configurado");
  }
}

function ensureEmailConfig() {
  const missing = [];

  if (!SMTP_HOST) missing.push("SMTP_HOST");
  if (!SMTP_PORT) missing.push("SMTP_PORT");
  if (!SMTP_USER) missing.push("SMTP_USER");
  if (!SMTP_PASS) missing.push("SMTP_PASS");
  if (!MAIL_FROM_EMAIL) missing.push("MAIL_FROM_EMAIL");
  if (!FIREBASE_WEB_API_KEY) missing.push("FIREBASE_WEB_API_KEY");

  if (missing.length > 0) {
    throw new Error(`Configuração de e-mail incompleta: ${missing.join(", ")}`);
  }
}

function htmlPage(title, message) {
  return `
  <!DOCTYPE html>
  <html lang="pt-BR">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>${escapeHtml(title)}</title>
      <style>
        * { box-sizing: border-box; }
        body {
          margin: 0;
          font-family: Arial, sans-serif;
          background: #0b0b0b;
          color: #fff;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          padding: 24px;
        }
        .card {
          width: 100%;
          max-width: 540px;
          background: rgba(255,255,255,0.06);
          border: 1px solid rgba(255,255,255,0.08);
          border-radius: 20px;
          padding: 24px;
          box-shadow: 0 18px 60px rgba(0,0,0,.35);
        }
        .logo {
          width: 54px;
          height: 54px;
          border-radius: 18px;
          background: rgba(30,136,229,.16);
          color: #1E88E5;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 28px;
          font-weight: 900;
          margin-bottom: 16px;
        }
        h1 {
          margin: 0 0 12px;
          font-size: 28px;
        }
        p {
          margin: 0;
          line-height: 1.5;
          color: rgba(255,255,255,0.78);
        }
        a {
          color: #1E88E5;
          font-weight: 800;
        }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="logo">🔥</div>
        <h1>${escapeHtml(title)}</h1>
        <p>${escapeHtml(message)}</p>
      </div>
    </body>
  </html>
  `;
}

function resetPasswordPage() {
  return `
  <!DOCTYPE html>
  <html lang="pt-BR">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Redefinir senha - FireRank</title>
      <style>
        * { box-sizing: border-box; }
        body {
          margin: 0;
          min-height: 100vh;
          font-family: Arial, sans-serif;
          background:
            radial-gradient(circle at top, rgba(30,136,229,.22), transparent 34%),
            linear-gradient(180deg, #050505 0%, #0d0d0d 100%);
          color: #fff;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 24px;
        }
        .card {
          width: 100%;
          max-width: 460px;
          background: rgba(255,255,255,.07);
          border: 1px solid rgba(255,255,255,.10);
          border-radius: 26px;
          padding: 26px;
          box-shadow: 0 24px 90px rgba(0,0,0,.45);
          backdrop-filter: blur(12px);
        }
        .brand {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 18px;
        }
        .brand-icon {
          width: 52px;
          height: 52px;
          border-radius: 18px;
          background: rgba(30,136,229,.16);
          display: flex;
          align-items: center;
          justify-content: center;
          color: #1E88E5;
          font-size: 28px;
        }
        .brand-name {
          font-size: 21px;
          font-weight: 900;
          letter-spacing: -.3px;
        }
        h1 {
          margin: 0;
          font-size: 28px;
          line-height: 1.1;
          letter-spacing: -.8px;
        }
        .subtitle {
          margin: 10px 0 20px;
          color: rgba(255,255,255,.68);
          font-size: 14px;
          line-height: 1.45;
          font-weight: 600;
        }
        label {
          display: block;
          margin-bottom: 8px;
          color: rgba(255,255,255,.72);
          font-size: 13px;
          font-weight: 800;
        }
        input {
          width: 100%;
          height: 52px;
          border: 1px solid rgba(255,255,255,.12);
          background: rgba(255,255,255,.08);
          color: white;
          border-radius: 16px;
          padding: 0 15px;
          font-size: 15px;
          outline: none;
        }
        input:focus {
          border-color: #1E88E5;
          box-shadow: 0 0 0 3px rgba(30,136,229,.18);
        }
        button {
          width: 100%;
          height: 52px;
          margin-top: 16px;
          border: 0;
          border-radius: 16px;
          background: #1E88E5;
          color: white;
          font-weight: 900;
          font-size: 15px;
          cursor: pointer;
        }
        button:disabled {
          opacity: .6;
          cursor: not-allowed;
        }
        .msg {
          margin-top: 14px;
          padding: 12px;
          border-radius: 14px;
          background: rgba(255,255,255,.07);
          color: rgba(255,255,255,.78);
          font-size: 13px;
          line-height: 1.4;
          display: none;
        }
        .msg.ok {
          display: block;
          border: 1px solid rgba(67, 255, 143, .20);
          background: rgba(67, 255, 143, .08);
        }
        .msg.err {
          display: block;
          border: 1px solid rgba(255, 84, 84, .22);
          background: rgba(255, 84, 84, .09);
        }
        .footer {
          margin-top: 18px;
          color: rgba(255,255,255,.42);
          font-size: 12px;
          text-align: center;
          line-height: 1.4;
        }
      </style>
    </head>
    <body>
      <main class="card">
        <div class="brand">
          <div class="brand-icon">🔥</div>
          <div class="brand-name">FireRank</div>
        </div>

        <h1>Crie uma nova senha</h1>
        <p class="subtitle">
          Digite sua nova senha abaixo. Depois disso, você já poderá voltar para o app e entrar normalmente.
        </p>

        <form id="form">
          <label for="password">Nova senha</label>
          <input id="password" type="password" minlength="6" autocomplete="new-password" placeholder="Mínimo de 6 caracteres" required />

          <label for="confirm" style="margin-top: 12px;">Confirmar senha</label>
          <input id="confirm" type="password" minlength="6" autocomplete="new-password" placeholder="Digite novamente" required />

          <button id="btn" type="submit">Salvar nova senha</button>
          <div id="msg" class="msg"></div>
        </form>

        <div class="footer">
          Se o link estiver expirado, solicite uma nova recuperação de senha no app FireRank.
        </div>
      </main>

      <script>
        const form = document.getElementById("form");
        const btn = document.getElementById("btn");
        const msg = document.getElementById("msg");
        const params = new URLSearchParams(window.location.search);
        const oobCode = params.get("oobCode") || params.get("oobcode") || "";

        function show(type, text) {
          msg.className = "msg " + type;
          msg.textContent = text;
        }

        if (!oobCode) {
          show("err", "Link inválido. Peça uma nova recuperação de senha no app FireRank.");
          btn.disabled = true;
        }

        form.addEventListener("submit", async (e) => {
          e.preventDefault();

          const password = document.getElementById("password").value.trim();
          const confirm = document.getElementById("confirm").value.trim();

          if (!password || password.length < 6) {
            show("err", "A senha precisa ter pelo menos 6 caracteres.");
            return;
          }

          if (password !== confirm) {
            show("err", "As senhas não conferem.");
            return;
          }

          btn.disabled = true;
          btn.textContent = "Salvando...";

          try {
            const response = await fetch("/api/auth/confirm-password-reset", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ oobCode, newPassword: password })
            });

            const data = await response.json().catch(() => ({}));

            if (!response.ok || !data.ok) {
              throw new Error(data.error || "Não foi possível redefinir sua senha.");
            }

            show("ok", "Senha redefinida com sucesso. Agora você já pode voltar ao app FireRank e entrar com sua nova senha.");
            btn.textContent = "Senha salva";
          } catch (err) {
            show("err", err.message || "Link expirado ou inválido. Solicite uma nova recuperação no app.");
            btn.disabled = false;
            btn.textContent = "Salvar nova senha";
          }
        });
      </script>
    </body>
  </html>
  `;
}

function buildResetEmailHtml({ resetUrl, email }) {
  const cleanResetUrl = escapeHtml(resetUrl);
  const cleanEmail = escapeHtml(email);

  return `
  <!DOCTYPE html>
  <html lang="pt-BR">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Redefina sua senha do FireRank</title>
    </head>
    <body style="margin:0;padding:0;background:#f4f6f8;font-family:Arial,sans-serif;color:#111827;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:28px 14px;">
        <tr>
          <td align="center">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:22px;overflow:hidden;border:1px solid #e5e7eb;">
              <tr>
                <td style="background:#0b0b0b;padding:26px 26px 22px;">
                  <div style="display:inline-block;background:rgba(30,136,229,.16);color:#1E88E5;border-radius:16px;width:50px;height:50px;line-height:50px;text-align:center;font-size:26px;font-weight:900;">🔥</div>
                  <h1 style="margin:16px 0 0;color:#ffffff;font-size:26px;line-height:1.15;">Redefina sua senha</h1>
                  <p style="margin:8px 0 0;color:rgba(255,255,255,.72);font-size:14px;line-height:1.45;">Solicitação de recuperação da sua conta FireRank.</p>
                </td>
              </tr>
              <tr>
                <td style="padding:26px;">
                  <p style="margin:0 0 14px;font-size:15px;line-height:1.55;color:#374151;">Olá,</p>
                  <p style="margin:0 0 14px;font-size:15px;line-height:1.55;color:#374151;">
                    Recebemos uma solicitação para redefinir a senha da conta FireRank vinculada a:
                  </p>
                  <p style="margin:0 0 20px;font-size:15px;line-height:1.55;color:#111827;font-weight:700;">${cleanEmail}</p>
                  <p style="margin:0 0 22px;font-size:15px;line-height:1.55;color:#374151;">
                    Clique no botão abaixo para criar uma nova senha:
                  </p>

                  <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 22px;">
                    <tr>
                      <td style="background:#1E88E5;border-radius:14px;">
                        <a href="${cleanResetUrl}" style="display:inline-block;padding:14px 22px;color:#ffffff;text-decoration:none;font-weight:900;font-size:15px;">
                          Redefinir minha senha
                        </a>
                      </td>
                    </tr>
                  </table>

                  <p style="margin:0 0 14px;font-size:13px;line-height:1.55;color:#6b7280;">
                    Se o botão não funcionar, copie e cole este link no navegador:
                  </p>
                  <p style="margin:0 0 20px;font-size:12px;line-height:1.55;color:#1E88E5;word-break:break-all;">
                    <a href="${cleanResetUrl}" style="color:#1E88E5;">${cleanResetUrl}</a>
                  </p>

                  <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:16px;padding:14px;margin:0 0 20px;">
                    <p style="margin:0;font-size:13px;line-height:1.5;color:#6b7280;">
                      Se você não solicitou essa alteração, ignore este e-mail. Sua senha atual continuará a mesma.
                    </p>
                  </div>

                  <p style="margin:0;font-size:15px;line-height:1.55;color:#374151;">Obrigado,</p>
                  <p style="margin:4px 0 0;font-size:15px;line-height:1.55;color:#111827;font-weight:900;">Equipe FireRank</p>
                </td>
              </tr>
            </table>

            <p style="max-width:560px;margin:14px auto 0;font-size:11px;line-height:1.45;color:#9ca3af;text-align:center;">
              Este e-mail foi enviado automaticamente pelo FireRank.
            </p>
          </td>
        </tr>
      </table>
    </body>
  </html>
  `;
}

function buildResetEmailText({ resetUrl, email }) {
  return [
    "Olá,",
    "",
    `Recebemos uma solicitação para redefinir a senha da conta FireRank vinculada a ${email}.`,
    "",
    "Para criar uma nova senha, acesse o link abaixo:",
    resetUrl,
    "",
    "Se você não solicitou essa alteração, ignore este e-mail.",
    "",
    "Equipe FireRank",
  ].join("\n");
}

function getMailTransporter() {
  ensureEmailConfig();

  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });
}

async function sendPasswordResetEmail({ email, resetUrl }) {
  const transporter = getMailTransporter();

  await transporter.sendMail({
    from: `"${MAIL_FROM_NAME}" <${MAIL_FROM_EMAIL}>`,
    to: email,
    subject: "Redefina sua senha do FireRank",
    text: buildResetEmailText({ resetUrl, email }),
    html: buildResetEmailHtml({ resetUrl, email }),
  });
}

function canRequestPasswordReset(email) {
  const key = safe(email).toLowerCase();
  const last = Number(passwordResetThrottle.get(key) || 0);
  const t = nowMs();

  if (last && t - last < 60 * 1000) {
    return false;
  }

  passwordResetThrottle.set(key, t);
  return true;
}

function extractOobCodeFromFirebaseLink(link) {
  try {
    const url = new URL(link);
    const directCode = url.searchParams.get("oobCode");

    if (directCode) return directCode;

    const continueUrl = url.searchParams.get("continueUrl");
    if (continueUrl) {
      const nested = new URL(continueUrl);
      return nested.searchParams.get("oobCode") || "";
    }

    return "";
  } catch (_) {
    return "";
  }
}

function normalizePrivateKey(privateKey) {
  return String(privateKey || "")
    .replace(/\r/g, "")
    .replace(/\\n/g, "\n")
    .trim();
}

function parseServiceAccount() {
  let raw = "";

  if (FIREBASE_SERVICE_ACCOUNT_JSON_BASE64) {
    try {
      raw = Buffer.from(
        FIREBASE_SERVICE_ACCOUNT_JSON_BASE64.trim(),
        "base64"
      ).toString("utf8");
    } catch (_) {
      throw new Error(
        "FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 inválido ou malformado"
      );
    }
  } else if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    raw = FIREBASE_SERVICE_ACCOUNT_JSON.trim();
  } else {
    throw new Error(
      "Firebase não configurado. Defina FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 ou FIREBASE_SERVICE_ACCOUNT_JSON"
    );
  }

  let serviceAccount;

  try {
    serviceAccount = JSON.parse(raw);
  } catch (_) {
    throw new Error("JSON da service account inválido");
  }

  if (!serviceAccount.private_key) {
    throw new Error("private_key ausente na service account");
  }

  serviceAccount.private_key = normalizePrivateKey(serviceAccount.private_key);

  if (
    !serviceAccount.private_key.includes("-----BEGIN PRIVATE KEY-----") ||
    !serviceAccount.private_key.includes("-----END PRIVATE KEY-----")
  ) {
    throw new Error("private_key inválida: cabeçalho PEM ausente");
  }

  return serviceAccount;
}

function initFirebase() {
  if (admin.apps.length > 0) {
    return admin.database();
  }

  if (!FIREBASE_DATABASE_URL) {
    throw new Error("FIREBASE_DATABASE_URL não configurado");
  }

  const serviceAccount = parseServiceAccount();

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: FIREBASE_DATABASE_URL,
  });

  return admin.database();
}

const db = initFirebase();

function firebaseSafeKey(value) {
  const s = safe(value);
  if (!s) return "";
  return s.replace(/[.#$/[\]]/g, "_");
}

function normalizePaymentStatus(status) {
  const s = safe(status).toLowerCase();

  if (s === "approved") return "approved";
  if (s === "paid") return "approved";
  if (s === "confirmed") return "approved";
  if (s === "active") return "approved";
  if (s === "pending") return "pending";
  if (s === "in_process") return "in_process";
  if (s === "rejected") return "rejected";
  if (s === "cancelled") return "cancelled";
  if (s === "canceled") return "cancelled";
  if (s === "refunded") return "refunded";
  if (s === "charged_back") return "charged_back";

  return s || "pending";
}

function isPaymentApproved(status) {
  return normalizePaymentStatus(status) === "approved";
}

function isPaymentPending(status) {
  const s = normalizePaymentStatus(status);
  return s === "pending" || s === "in_process";
}

function planToDays(plan, fallbackDays = 1) {
  const p = safe(plan).toLowerCase();

  if (p === "one_day" || p === "1_day" || p === "day_1") return 1;
  if (p === "two_days" || p === "2_days" || p === "day_2") return 2;
  if (p === "three_days" || p === "3_days" || p === "day_3") return 3;
  if (p === "seven_days" || p === "7_days" || p === "week") return 7;
  if (p === "monthly" || p === "month" || p === "30_days") return 30;
  if (p === "yearly" || p === "year" || p === "365_days") return 365;

  const n = Number(fallbackDays);
  return Number.isFinite(n) && n > 0 ? Math.round(n) : 1;
}

function planFromDays(days) {
  const d = Number(days);

  if (d === 1) return "one_day";
  if (d === 2) return "two_days";
  if (d === 3) return "three_days";
  if (d === 7) return "seven_days";
  if (d === 30) return "monthly";
  if (d === 365) return "yearly";

  return `${d}_days`;
}

function extractUidFromVerificationExternalReference(externalReference) {
  const ref = safe(externalReference);

  if (!ref.startsWith("verification_")) return "";

  const parts = ref.split("_");

  if (parts.length < 2) return "";

  return safe(parts[1]);
}

function getPaymentPreferenceId(paymentDetail) {
  return safe(
    paymentDetail.metadata?.preference_id ||
      paymentDetail.metadata?.preferenceId ||
      paymentDetail.order?.id ||
      paymentDetail.additional_info?.items?.[0]?.id
  );
}

function getPaymentExternalReference(paymentDetail) {
  return safe(paymentDetail.external_reference);
}

function detectRequestTypeFromBody(body) {
  const raw = safe(
    body.type ||
      body.paymentType ||
      body.payment_type ||
      body.requestType ||
      body.request_type ||
      body.kind ||
      body.metadata?.type ||
      body.metadata?.payment_type
  ).toLowerCase();

  if (
    raw === "verification" ||
    raw === "verified" ||
    raw === "selo" ||
    raw === "selo_verificado"
  ) {
    return "verification";
  }

  if (
    raw === "boost" ||
    raw === "ad" ||
    raw === "ads" ||
    raw === "advertisement" ||
    raw === "turbinado" ||
    raw === "impulsionamento"
  ) {
    return "boost";
  }

  const externalReference = safe(
    body.externalReference || body.external_reference
  );

  if (externalReference.startsWith("verification_")) return "verification";
  if (
    externalReference.startsWith("boost_") ||
    externalReference.startsWith("ad_") ||
    externalReference.startsWith("ads_")
  ) {
    return "boost";
  }

  if (body.productId || body.product_id || body.adId || body.ad_id) {
    return "boost";
  }

  return "verification";
}

function detectRequestTypeFromPayment(paymentDetail) {
  const metadata = paymentDetail.metadata || {};
  const raw = safe(
    metadata.type ||
      metadata.payment_type ||
      metadata.request_type ||
      metadata.kind
  ).toLowerCase();

  const externalReference = getPaymentExternalReference(paymentDetail);

  if (
    raw === "verification" ||
    raw === "verified" ||
    raw === "selo" ||
    raw === "selo_verificado"
  ) {
    return "verification";
  }

  if (
    raw === "boost" ||
    raw === "ad" ||
    raw === "ads" ||
    raw === "advertisement" ||
    raw === "turbinado" ||
    raw === "impulsionamento"
  ) {
    return "boost";
  }

  if (externalReference.startsWith("verification_")) return "verification";

  if (
    externalReference.startsWith("boost_") ||
    externalReference.startsWith("ad_") ||
    externalReference.startsWith("ads_")
  ) {
    return "boost";
  }

  if (
    metadata.product_id ||
    metadata.productId ||
    metadata.ad_id ||
    metadata.adId ||
    metadata.seller_uid ||
    metadata.sellerUid
  ) {
    return "boost";
  }

  return "unknown";
}

async function fetchMercadoPagoPayment(paymentId) {
  const response = await axios.get(
    `https://api.mercadopago.com/v1/payments/${paymentId}`,
    { headers: mpHeaders() }
  );

  return response.data || {};
}

async function findFirstByChild(path, child, value) {
  const v = safe(value);
  if (!v) return null;

  const snap = await db.ref(path).orderByChild(child).equalTo(v).get();

  if (!snap.exists()) return null;

  let found = null;

  snap.forEach((childSnap) => {
    if (!found) {
      found = {
        key: childSnap.key,
        value: childSnap.val() || {},
      };
    }
  });

  return found;
}

async function logPaymentWebhook(paymentDetail, requestType) {
  const paymentId = safe(paymentDetail.id);
  const key = firebaseSafeKey(paymentId || `webhook_${nowMs()}`);
  const t = nowMs();

  await db.ref(`payment_webhooks/${key}`).set({
    paymentId,
    requestType,
    provider: "mercado_pago",
    status: normalizePaymentStatus(paymentDetail.status),
    externalReference: getPaymentExternalReference(paymentDetail),
    gatewayPreferenceId: getPaymentPreferenceId(paymentDetail),
    createdAtMs: t,
    updatedAtMs: t,
    processed: true,
  });
}

async function updateVerificationPaymentRecords({
  uid,
  requestId,
  gatewayPaymentId,
  gatewayPreferenceId,
  paymentStatus,
  updatedAtMs,
  rawStatusDetail,
}) {
  const updates = {};

  const paymentKey = firebaseSafeKey(
    gatewayPaymentId || requestId || gatewayPreferenceId || `verification_${uid}`
  );

  if (paymentKey) {
    updates[`verification_payments/${paymentKey}/uid`] = uid;
    updates[`verification_payments/${paymentKey}/requestId`] = requestId;
    updates[`verification_payments/${paymentKey}/status`] = paymentStatus;
    updates[`verification_payments/${paymentKey}/provider`] = "mercado_pago";
    updates[`verification_payments/${paymentKey}/updatedAtMs`] = updatedAtMs;

    if (gatewayPaymentId) {
      updates[`verification_payments/${paymentKey}/gatewayPaymentId`] =
        gatewayPaymentId;
    }

    if (gatewayPreferenceId) {
      updates[`verification_payments/${paymentKey}/gatewayPreferenceId`] =
        gatewayPreferenceId;
    }

    if (rawStatusDetail) {
      updates[`verification_payments/${paymentKey}/rawStatusDetail`] =
        rawStatusDetail;
    }
  }

  if (requestId) {
    const byRequestId = await db
      .ref("verification_payments")
      .orderByChild("requestId")
      .equalTo(requestId)
      .get();

    if (byRequestId.exists()) {
      byRequestId.forEach((child) => {
        updates[`verification_payments/${child.key}/uid`] = uid;
        updates[`verification_payments/${child.key}/status`] = paymentStatus;
        updates[`verification_payments/${child.key}/updatedAtMs`] = updatedAtMs;

        if (gatewayPaymentId) {
          updates[`verification_payments/${child.key}/gatewayPaymentId`] =
            gatewayPaymentId;
        }

        if (gatewayPreferenceId) {
          updates[`verification_payments/${child.key}/gatewayPreferenceId`] =
            gatewayPreferenceId;
        }

        if (rawStatusDetail) {
          updates[`verification_payments/${child.key}/rawStatusDetail`] =
            rawStatusDetail;
        }
      });
    }
  }

  if (gatewayPreferenceId) {
    const byPreference = await db
      .ref("verification_payments")
      .orderByChild("gatewayPreferenceId")
      .equalTo(gatewayPreferenceId)
      .get();

    if (byPreference.exists()) {
      byPreference.forEach((child) => {
        updates[`verification_payments/${child.key}/uid`] = uid;
        updates[`verification_payments/${child.key}/status`] = paymentStatus;
        updates[`verification_payments/${child.key}/updatedAtMs`] = updatedAtMs;

        if (gatewayPaymentId) {
          updates[`verification_payments/${child.key}/gatewayPaymentId`] =
            gatewayPaymentId;
        }

        if (rawStatusDetail) {
          updates[`verification_payments/${child.key}/rawStatusDetail`] =
            rawStatusDetail;
        }
      });
    }
  }

  if (Object.keys(updates).length > 0) {
    await db.ref().update(updates);
  }
}

async function handleVerificationPayment(paymentDetail) {
  const t = nowMs();

  const paymentId = safe(paymentDetail.id);
  const paymentStatus = normalizePaymentStatus(paymentDetail.status);
  const statusDetail = safe(paymentDetail.status_detail);
  const externalReference = getPaymentExternalReference(paymentDetail);
  const preferenceId = getPaymentPreferenceId(paymentDetail);
  const metadata = paymentDetail.metadata || {};

  let uid = safe(
    metadata.uid ||
      metadata.user_uid ||
      metadata.userUid ||
      metadata.seller_uid ||
      metadata.sellerUid
  );

  if (!uid) {
    uid = extractUidFromVerificationExternalReference(externalReference);
  }

  if (!uid) {
    console.log("Webhook de verificação ignorado: uid ausente", {
      externalReference,
      paymentId,
      paymentStatus,
    });
    return;
  }

  const requestRef = db.ref(`verification_requests/${uid}`);
  const requestSnap = await requestRef.get();
  const requestData = requestSnap.exists() ? requestSnap.val() || {} : {};

  const requestId = safe(
    requestData.requestId ||
      requestData.externalReference ||
      metadata.request_id ||
      metadata.requestId ||
      externalReference ||
      `verification_${uid}_${t}`
  );

  const plan = safe(
    requestData.plan ||
      metadata.plan ||
      metadata.verification_plan ||
      "monthly"
  );

  const days = planToDays(plan, requestData.days || metadata.days || 30);

  const oldExpiresAt = Number(requestData.expiresAtMs || 0);
  const startsAtMs = t;
  const expiresAtMs =
    oldExpiresAt > t && isPaymentApproved(paymentStatus)
      ? oldExpiresAt
      : t + days * DAY_MS;

  const updates = {
    [`verification_requests/${uid}/uid`]: uid,
    [`verification_requests/${uid}/requestId`]: requestId,
    [`verification_requests/${uid}/paymentStatus`]: paymentStatus,
    [`verification_requests/${uid}/gatewayPaymentId`]: paymentId,
    [`verification_requests/${uid}/gatewayPreferenceId`]: preferenceId,
    [`verification_requests/${uid}/paymentProvider`]: "mercado_pago",
    [`verification_requests/${uid}/updatedAtMs`]: t,

    [`users/${uid}/verificationPaymentStatus`]: paymentStatus,
    [`users/${uid}/updatedAtMs`]: t,
  };

  if (statusDetail) {
    updates[`verification_requests/${uid}/rawStatusDetail`] = statusDetail;
  }

  if (isPaymentApproved(paymentStatus)) {
    updates[`verification_requests/${uid}/status`] = "active";
    updates[`verification_requests/${uid}/verifiedStatus`] = "active";
    updates[`verification_requests/${uid}/adminStatus`] = "auto_approved";
    updates[`verification_requests/${uid}/approvedAtMs`] = t;
    updates[`verification_requests/${uid}/startsAtMs`] = startsAtMs;
    updates[`verification_requests/${uid}/expiresAtMs`] = expiresAtMs;
    updates[`verification_requests/${uid}/autoActivated`] = true;
    updates[`verification_requests/${uid}/requiresAdminApproval`] = false;

    updates[`users/${uid}/verified`] = true;
    updates[`users/${uid}/verificationStatus`] = "active";
    updates[`users/${uid}/verifiedAtMs`] = t;
    updates[`users/${uid}/verificationExpiresAtMs`] = expiresAtMs;
    updates[`users/${uid}/verificationSubscription/status`] = "active";
    updates[`users/${uid}/verificationSubscription/active`] = true;
    updates[`users/${uid}/verificationSubscription/plan`] = plan;
    updates[`users/${uid}/verificationSubscription/startsAtMs`] = startsAtMs;
    updates[`users/${uid}/verificationSubscription/expiresAtMs`] = expiresAtMs;
    updates[`users/${uid}/verificationSubscription/paymentProvider`] =
      "mercado_pago";
    updates[`users/${uid}/verificationSubscription/gatewayPaymentId`] =
      paymentId;
    updates[`users/${uid}/verificationSubscription/gatewayPreferenceId`] =
      preferenceId;
    updates[`users/${uid}/verificationSubscription/autoActivated`] = true;
    updates[`users/${uid}/verificationSubscription/updatedAtMs`] = t;

    updates[`verified_users/${uid}/uid`] = uid;
    updates[`verified_users/${uid}/active`] = true;
    updates[`verified_users/${uid}/status`] = "active";
    updates[`verified_users/${uid}/source`] = "payment_auto_activation";
    updates[`verified_users/${uid}/paymentProvider`] = "mercado_pago";
    updates[`verified_users/${uid}/gatewayPaymentId`] = paymentId;
    updates[`verified_users/${uid}/startsAtMs`] = startsAtMs;
    updates[`verified_users/${uid}/expiresAtMs`] = expiresAtMs;
    updates[`verified_users/${uid}/updatedAtMs`] = t;

    updates[`admin_actions/AUTO_VERIFICATION_${uid}_${t}/actionId`] =
      `AUTO_VERIFICATION_${uid}_${t}`;
    updates[`admin_actions/AUTO_VERIFICATION_${uid}_${t}/actor`] =
      "payment_webhook";
    updates[`admin_actions/AUTO_VERIFICATION_${uid}_${t}/type`] =
      "auto_approved_verification";
    updates[`admin_actions/AUTO_VERIFICATION_${uid}_${t}/targetUid`] = uid;
    updates[`admin_actions/AUTO_VERIFICATION_${uid}_${t}/createdAtMs`] = t;
    updates[`admin_actions/AUTO_VERIFICATION_${uid}_${t}/message`] =
      "Selo verificado ativado automaticamente após pagamento aprovado.";

    updates[`notifications/${uid}/verification-payment-${t}/title`] =
      "Selo verificado ativado";
    updates[`notifications/${uid}/verification-payment-${t}/body`] =
      "Seu pagamento foi aprovado e seu selo verificado já está ativo automaticamente.";
    updates[`notifications/${uid}/verification-payment-${t}/type`] =
      "verification_auto_activated";
    updates[`notifications/${uid}/verification-payment-${t}/read`] = false;
    updates[`notifications/${uid}/verification-payment-${t}/createdAtMs`] = t;
  } else if (isPaymentPending(paymentStatus)) {
    updates[`verification_requests/${uid}/status`] = "pending_payment";
    updates[`verification_requests/${uid}/verifiedStatus`] = "payment_pending";
    updates[`verification_requests/${uid}/adminStatus`] = "none";
    updates[`verification_requests/${uid}/autoActivated`] = false;
    updates[`verification_requests/${uid}/requiresAdminApproval`] = false;

    updates[`users/${uid}/verificationStatus`] = "payment_pending";
    updates[`users/${uid}/verified`] = false;
  } else {
    updates[`verification_requests/${uid}/status`] = "payment_failed";
    updates[`verification_requests/${uid}/verifiedStatus`] = "payment_failed";
    updates[`verification_requests/${uid}/adminStatus`] = "none";
    updates[`verification_requests/${uid}/autoActivated`] = false;
    updates[`verification_requests/${uid}/requiresAdminApproval`] = false;

    updates[`users/${uid}/verificationStatus`] = "payment_failed";
    updates[`users/${uid}/verified`] = false;

    updates[`notifications/${uid}/verification-payment-${t}/title`] =
      "Pagamento do selo não aprovado";
    updates[`notifications/${uid}/verification-payment-${t}/body`] =
      "O pagamento do selo não foi aprovado. Você pode tentar novamente no app.";
    updates[`notifications/${uid}/verification-payment-${t}/type`] =
      "verification_payment_failed";
    updates[`notifications/${uid}/verification-payment-${t}/read`] = false;
    updates[`notifications/${uid}/verification-payment-${t}/createdAtMs`] = t;
  }

  await db.ref().update(updates);

  await updateVerificationPaymentRecords({
    uid,
    requestId,
    gatewayPaymentId: paymentId,
    gatewayPreferenceId: preferenceId,
    paymentStatus,
    updatedAtMs: t,
    rawStatusDetail: statusDetail,
  });

  console.log("Webhook de verificação processado:", {
    uid,
    externalReference,
    paymentId,
    paymentStatus,
    preferenceId,
  });
}

async function findBoostRequest({
  externalReference,
  gatewayPreferenceId,
  gatewayPaymentId,
}) {
  const directKey = firebaseSafeKey(externalReference);

  if (directKey) {
    const directSnap = await db.ref(`boost_requests/${directKey}`).get();
    if (directSnap.exists()) {
      return {
        key: directKey,
        value: directSnap.val() || {},
      };
    }
  }

  const byRequestId = await findFirstByChild(
    "boost_requests",
    "requestId",
    externalReference
  );

  if (byRequestId) return byRequestId;

  const byExternal = await findFirstByChild(
    "boost_requests",
    "externalReference",
    externalReference
  );

  if (byExternal) return byExternal;

  const byPref = await findFirstByChild(
    "boost_requests",
    "gatewayPreferenceId",
    gatewayPreferenceId
  );

  if (byPref) return byPref;

  const byPayment = await findFirstByChild(
    "boost_payments",
    "gatewayPaymentId",
    gatewayPaymentId
  );

  if (byPayment) {
    const requestId = safe(byPayment.value.requestId);
    if (requestId) {
      const requestSnap = await db.ref(`boost_requests/${requestId}`).get();
      if (requestSnap.exists()) {
        return {
          key: requestId,
          value: requestSnap.val() || {},
        };
      }
    }
  }

  return null;
}

async function handleBoostPayment(paymentDetail) {
  const t = nowMs();

  const paymentId = safe(paymentDetail.id);
  const paymentStatus = normalizePaymentStatus(paymentDetail.status);
  const statusDetail = safe(paymentDetail.status_detail);
  const externalReference = getPaymentExternalReference(paymentDetail);
  const preferenceId = getPaymentPreferenceId(paymentDetail);
  const metadata = paymentDetail.metadata || {};

  const foundRequest = await findBoostRequest({
    externalReference,
    gatewayPreferenceId: preferenceId,
    gatewayPaymentId: paymentId,
  });

  const requestData = foundRequest?.value || {};
  const requestKey = safe(foundRequest?.key);

  const requestId = safe(
    requestData.requestId ||
      metadata.request_id ||
      metadata.requestId ||
      externalReference ||
      requestKey ||
      `boost_${t}`
  );

  const sellerUid = safe(
    requestData.sellerUid ||
      requestData.seller_uid ||
      metadata.seller_uid ||
      metadata.sellerUid ||
      metadata.uid
  );

  const productId = safe(
    requestData.productId ||
      requestData.product_id ||
      metadata.product_id ||
      metadata.productId
  );

  const adId = safe(
    requestData.adId ||
      requestData.ad_id ||
      metadata.ad_id ||
      metadata.adId ||
      requestId
  );

  const boostId = safe(
    requestData.boostId ||
      requestData.boost_id ||
      metadata.boost_id ||
      metadata.boostId ||
      requestId
  );

  const productTitle = safe(
    requestData.productTitle ||
      requestData.product_title ||
      metadata.product_title ||
      metadata.productTitle
  );

  const productImage = safe(
    requestData.productImage ||
      requestData.product_image ||
      metadata.product_image ||
      metadata.productImage
  );

  const placement = safe(
    requestData.placement ||
      metadata.placement ||
      "home_hero_horizontal"
  );

  const plan = safe(
    requestData.plan ||
      metadata.plan ||
      planFromDays(requestData.days || metadata.days || 1)
  );

  const days = planToDays(plan, requestData.days || metadata.days || 1);

  const price = toNumber(
    requestData.price ||
      metadata.price ||
      paymentDetail.transaction_amount ||
      paymentDetail.total_paid_amount
  );

  const startsAtMs = t;
  const expiresAtMs =
    Number(requestData.expiresAtMs || 0) > t
      ? Number(requestData.expiresAtMs)
      : startsAtMs + days * DAY_MS;

  if (!sellerUid || !productId) {
    const key = firebaseSafeKey(paymentId || requestId);

    const missingUpdates = {
      [`payment_integrity_audit/boost_${key}/type`]:
        "boost_missing_required_fields",
      [`payment_integrity_audit/boost_${key}/paymentId`]: paymentId,
      [`payment_integrity_audit/boost_${key}/externalReference`]:
        externalReference,
      [`payment_integrity_audit/boost_${key}/gatewayPreferenceId`]:
        preferenceId,
      [`payment_integrity_audit/boost_${key}/paymentStatus`]: paymentStatus,
      [`payment_integrity_audit/boost_${key}/sellerUid`]: sellerUid,
      [`payment_integrity_audit/boost_${key}/productId`]: productId,
      [`payment_integrity_audit/boost_${key}/createdAtMs`]: t,
    };

    await db.ref().update(missingUpdates);

    console.log("Boost ignorado: sellerUid/productId ausente", {
      paymentId,
      externalReference,
      preferenceId,
      sellerUid,
      productId,
    });

    return;
  }

  const paymentKey = firebaseSafeKey(paymentId || requestId);

  const updates = {
    [`boost_requests/${requestId}/requestId`]: requestId,
    [`boost_requests/${requestId}/adId`]: adId,
    [`boost_requests/${requestId}/boostId`]: boostId,
    [`boost_requests/${requestId}/sellerUid`]: sellerUid,
    [`boost_requests/${requestId}/productId`]: productId,
    [`boost_requests/${requestId}/productTitle`]: productTitle,
    [`boost_requests/${requestId}/productImage`]: productImage,
    [`boost_requests/${requestId}/placement`]: placement,
    [`boost_requests/${requestId}/plan`]: plan,
    [`boost_requests/${requestId}/days`]: days,
    [`boost_requests/${requestId}/price`]: price,
    [`boost_requests/${requestId}/currency`]: "BRL",
    [`boost_requests/${requestId}/paymentStatus`]: paymentStatus,
    [`boost_requests/${requestId}/paymentProvider`]: "mercado_pago",
    [`boost_requests/${requestId}/gatewayPaymentId`]: paymentId,
    [`boost_requests/${requestId}/gatewayPreferenceId`]: preferenceId,
    [`boost_requests/${requestId}/updatedAtMs`]: t,

    [`boost_payments/${paymentKey}/paymentId`]: paymentKey,
    [`boost_payments/${paymentKey}/gatewayPaymentId`]: paymentId,
    [`boost_payments/${paymentKey}/gatewayPreferenceId`]: preferenceId,
    [`boost_payments/${paymentKey}/externalReference`]: externalReference,
    [`boost_payments/${paymentKey}/provider`]: "mercado_pago",
    [`boost_payments/${paymentKey}/status`]: paymentStatus,
    [`boost_payments/${paymentKey}/amount`]: price,
    [`boost_payments/${paymentKey}/currency`]: "BRL",
    [`boost_payments/${paymentKey}/requestId`]: requestId,
    [`boost_payments/${paymentKey}/adId`]: adId,
    [`boost_payments/${paymentKey}/boostId`]: boostId,
    [`boost_payments/${paymentKey}/sellerUid`]: sellerUid,
    [`boost_payments/${paymentKey}/productId`]: productId,
    [`boost_payments/${paymentKey}/updatedAtMs`]: t,
  };

  if (statusDetail) {
    updates[`boost_payments/${paymentKey}/rawStatusDetail`] = statusDetail;
    updates[`boost_requests/${requestId}/rawStatusDetail`] = statusDetail;
  }

  if (isPaymentApproved(paymentStatus)) {
    updates[`boost_requests/${requestId}/status`] = "active";
    updates[`boost_requests/${requestId}/startsAtMs`] = startsAtMs;
    updates[`boost_requests/${requestId}/expiresAtMs`] = expiresAtMs;
    updates[`boost_requests/${requestId}/activatedAtMs`] = t;
    updates[`boost_requests/${requestId}/autoActivated`] = true;
    updates[`boost_requests/${requestId}/requiresAdminApproval`] = false;

    updates[`ads/${adId}/adId`] = adId;
    updates[`ads/${adId}/boostId`] = boostId;
    updates[`ads/${adId}/requestId`] = requestId;
    updates[`ads/${adId}/sellerUid`] = sellerUid;
    updates[`ads/${adId}/productId`] = productId;
    updates[`ads/${adId}/productTitle`] = productTitle;
    updates[`ads/${adId}/productImage`] = productImage;
    updates[`ads/${adId}/placement`] = placement;
    updates[`ads/${adId}/plan`] = plan;
    updates[`ads/${adId}/days`] = days;
    updates[`ads/${adId}/price`] = price;
    updates[`ads/${adId}/currency`] = "BRL";
    updates[`ads/${adId}/status`] = "active";
    updates[`ads/${adId}/paymentStatus`] = "approved";
    updates[`ads/${adId}/paymentProvider`] = "mercado_pago";
    updates[`ads/${adId}/paymentId`] = paymentId;
    updates[`ads/${adId}/gatewayPaymentId`] = paymentId;
    updates[`ads/${adId}/gatewayPreferenceId`] = preferenceId;
    updates[`ads/${adId}/startsAtMs`] = startsAtMs;
    updates[`ads/${adId}/endsAtMs`] = expiresAtMs;
    updates[`ads/${adId}/expiresAtMs`] = expiresAtMs;
    updates[`ads/${adId}/views`] = requestData.views || 0;
    updates[`ads/${adId}/clicks`] = requestData.clicks || 0;
    updates[`ads/${adId}/createdAtMs`] = requestData.createdAtMs || t;
    updates[`ads/${adId}/updatedAtMs`] = t;
    updates[`ads/${adId}/autoActivated`] = true;

    updates[`products/${productId}/isBoosted`] = true;
    updates[`products/${productId}/boosted`] = true;
    updates[`products/${productId}/boost/isBoosted`] = true;
    updates[`products/${productId}/boost/active`] = true;
    updates[`products/${productId}/boost/status`] = "active";
    updates[`products/${productId}/boost/paymentStatus`] = "approved";
    updates[`products/${productId}/boost/paymentProvider`] = "mercado_pago";
    updates[`products/${productId}/boost/paymentId`] = paymentId;
    updates[`products/${productId}/boost/gatewayPaymentId`] = paymentId;
    updates[`products/${productId}/boost/gatewayPreferenceId`] = preferenceId;
    updates[`products/${productId}/boost/requestId`] = requestId;
    updates[`products/${productId}/boost/adId`] = adId;
    updates[`products/${productId}/boost/boostId`] = boostId;
    updates[`products/${productId}/boost/sellerUid`] = sellerUid;
    updates[`products/${productId}/boost/placement`] = placement;
    updates[`products/${productId}/boost/plan`] = plan;
    updates[`products/${productId}/boost/days`] = days;
    updates[`products/${productId}/boost/price`] = price;
    updates[`products/${productId}/boost/startAtMs`] = startsAtMs;
    updates[`products/${productId}/boost/startsAtMs`] = startsAtMs;
    updates[`products/${productId}/boost/activatedAtMs`] = t;
    updates[`products/${productId}/boost/expiresAtMs`] = expiresAtMs;
    updates[`products/${productId}/boost/endsAtMs`] = expiresAtMs;
    updates[`products/${productId}/boost/updatedAtMs`] = t;

    updates[`products/${productId}/boostStatus`] = "active";
    updates[`products/${productId}/boostPaymentStatus`] = "approved";
    updates[`products/${productId}/boostStartAtMs`] = startsAtMs;
    updates[`products/${productId}/boostExpiresAtMs`] = expiresAtMs;
    updates[`products/${productId}/boostEndAtMs`] = expiresAtMs;
    updates[`products/${productId}/updatedAtMs`] = t;

    updates[`active_boosts/${adId}`] = true;
    updates[`active_boosts_by_product/${productId}/${adId}`] = true;
    updates[`active_boosts_by_seller/${sellerUid}/${adId}`] = true;

    updates[`boost_events/${requestId}_${t}/eventId`] = `${requestId}_${t}`;
    updates[`boost_events/${requestId}_${t}/type`] = "payment_approved";
    updates[`boost_events/${requestId}_${t}/requestId`] = requestId;
    updates[`boost_events/${requestId}_${t}/adId`] = adId;
    updates[`boost_events/${requestId}_${t}/boostId`] = boostId;
    updates[`boost_events/${requestId}_${t}/sellerUid`] = sellerUid;
    updates[`boost_events/${requestId}_${t}/productId`] = productId;
    updates[`boost_events/${requestId}_${t}/createdAtMs`] = t;

    updates[`notifications/${sellerUid}/boost-payment-${t}/title`] =
      "Anúncio ativado";
    updates[`notifications/${sellerUid}/boost-payment-${t}/body`] =
      "Seu pagamento foi aprovado e o anúncio do produto já está ativo automaticamente.";
    updates[`notifications/${sellerUid}/boost-payment-${t}/type`] =
      "boost_auto_activated";
    updates[`notifications/${sellerUid}/boost-payment-${t}/read`] = false;
    updates[`notifications/${sellerUid}/boost-payment-${t}/createdAtMs`] = t;
    updates[`notifications/${sellerUid}/boost-payment-${t}/data/productId`] =
      productId;
    updates[`notifications/${sellerUid}/boost-payment-${t}/data/adId`] = adId;
  } else if (isPaymentPending(paymentStatus)) {
    updates[`boost_requests/${requestId}/status`] = "pending_payment";
    updates[`ads/${adId}/status`] = "pending_payment";
    updates[`ads/${adId}/paymentStatus`] = paymentStatus;
    updates[`ads/${adId}/updatedAtMs`] = t;
  } else {
    updates[`boost_requests/${requestId}/status`] = "cancelled";
    updates[`ads/${adId}/status`] = "cancelled";
    updates[`ads/${adId}/paymentStatus`] = paymentStatus;
    updates[`ads/${adId}/updatedAtMs`] = t;

    updates[`products/${productId}/boost/paymentStatus`] = paymentStatus;

    updates[`notifications/${sellerUid}/boost-payment-${t}/title`] =
      "Pagamento do anúncio não aprovado";
    updates[`notifications/${sellerUid}/boost-payment-${t}/body`] =
      "O pagamento do anúncio/turbinamento não foi aprovado. Você pode tentar novamente no app.";
    updates[`notifications/${sellerUid}/boost-payment-${t}/type`] =
      "boost_payment_failed";
    updates[`notifications/${sellerUid}/boost-payment-${t}/read`] = false;
    updates[`notifications/${sellerUid}/boost-payment-${t}/createdAtMs`] = t;
  }

  await db.ref().update(updates);

  console.log("Webhook de boost/anúncio processado:", {
    sellerUid,
    productId,
    requestId,
    adId,
    paymentId,
    paymentStatus,
    preferenceId,
  });
}

async function savePendingVerificationPreference({
  externalReference,
  preferenceId,
  checkoutUrl,
  sandboxInitPoint,
  body,
}) {
  const t = nowMs();

  let uid = safe(
    body.uid ||
      body.userUid ||
      body.user_uid ||
      body.sellerUid ||
      body.seller_uid
  );

  if (!uid) {
    uid = extractUidFromVerificationExternalReference(externalReference);
  }

  if (!uid) return;

  const plan = safe(body.plan || body.verificationPlan || "monthly");
  const days = planToDays(plan, body.days || 30);
  const price = toNumber(
    body.price || body.amount || body.items?.[0]?.unit_price
  );

  const updates = {
    [`verification_requests/${uid}/uid`]: uid,
    [`verification_requests/${uid}/requestId`]: externalReference,
    [`verification_requests/${uid}/externalReference`]: externalReference,
    [`verification_requests/${uid}/plan`]: plan,
    [`verification_requests/${uid}/days`]: days,
    [`verification_requests/${uid}/price`]: price,
    [`verification_requests/${uid}/currency`]: "BRL",
    [`verification_requests/${uid}/checkoutUrl`]: checkoutUrl,
    [`verification_requests/${uid}/sandboxCheckoutUrl`]: sandboxInitPoint,
    [`verification_requests/${uid}/gatewayPreferenceId`]: preferenceId,
    [`verification_requests/${uid}/paymentProvider`]: "mercado_pago",
    [`verification_requests/${uid}/paymentStatus`]: "pending",
    [`verification_requests/${uid}/status`]: "pending_payment",
    [`verification_requests/${uid}/verifiedStatus`]: "payment_pending",
    [`verification_requests/${uid}/adminStatus`]: "none",
    [`verification_requests/${uid}/requiresAdminApproval`]: false,
    [`verification_requests/${uid}/autoActivationEnabled`]: true,
    [`verification_requests/${uid}/createdAtMs`]: t,
    [`verification_requests/${uid}/updatedAtMs`]: t,

    [`users/${uid}/verificationStatus`]: "payment_pending",
    [`users/${uid}/verificationPaymentStatus`]: "pending",
    [`users/${uid}/verified`]: false,
    [`users/${uid}/updatedAtMs`]: t,
  };

  await db.ref().update(updates);
}

async function savePendingBoostPreference({
  externalReference,
  preferenceId,
  checkoutUrl,
  sandboxInitPoint,
  body,
}) {
  const t = nowMs();

  const requestId = safe(body.requestId || body.request_id || externalReference);
  const adId = safe(body.adId || body.ad_id || requestId);
  const boostId = safe(body.boostId || body.boost_id || requestId);

  const sellerUid = safe(
    body.sellerUid || body.seller_uid || body.uid || body.userUid
  );

  const productId = safe(body.productId || body.product_id);

  const productTitle = safe(body.productTitle || body.product_title);
  const productImage = safe(body.productImage || body.product_image);
  const placement = safe(body.placement || "home_hero_horizontal");

  const price = toNumber(
    body.price || body.amount || body.items?.[0]?.unit_price
  );
  const days = planToDays(body.plan, body.days || 1);
  const plan = safe(body.plan || planFromDays(days));

  if (!sellerUid || !productId || !requestId) {
    await db.ref(`payment_integrity_audit/pending_boost_${t}`).set({
      type: "pending_boost_missing_required_fields",
      externalReference,
      preferenceId,
      checkoutUrl,
      sellerUid,
      productId,
      requestId,
      createdAtMs: t,
    });

    return;
  }

  const common = {
    requestId,
    adId,
    boostId,
    sellerUid,
    productId,
    productTitle,
    productImage,
    placement,
    plan,
    days,
    price,
    currency: "BRL",
    checkoutUrl,
    sandboxCheckoutUrl: sandboxInitPoint,
    gatewayPreferenceId: preferenceId,
    paymentProvider: "mercado_pago",
    paymentStatus: "pending",
    status: "pending_payment",
    requiresAdminApproval: false,
    autoActivationEnabled: true,
    createdAtMs: t,
    updatedAtMs: t,
  };

  const updates = {
    [`boost_requests/${requestId}`]: common,

    [`ads/${adId}/adId`]: adId,
    [`ads/${adId}/requestId`]: requestId,
    [`ads/${adId}/boostId`]: boostId,
    [`ads/${adId}/sellerUid`]: sellerUid,
    [`ads/${adId}/productId`]: productId,
    [`ads/${adId}/productTitle`]: productTitle,
    [`ads/${adId}/productImage`]: productImage,
    [`ads/${adId}/placement`]: placement,
    [`ads/${adId}/plan`]: plan,
    [`ads/${adId}/days`]: days,
    [`ads/${adId}/price`]: price,
    [`ads/${adId}/currency`]: "BRL",
    [`ads/${adId}/checkoutUrl`]: checkoutUrl,
    [`ads/${adId}/sandboxCheckoutUrl`]: sandboxInitPoint,
    [`ads/${adId}/gatewayPreferenceId`]: preferenceId,
    [`ads/${adId}/paymentProvider`]: "mercado_pago",
    [`ads/${adId}/paymentStatus`]: "pending",
    [`ads/${adId}/status`]: "pending_payment",
    [`ads/${adId}/requiresAdminApproval`]: false,
    [`ads/${adId}/autoActivationEnabled`]: true,
    [`ads/${adId}/views`]: 0,
    [`ads/${adId}/clicks`]: 0,
    [`ads/${adId}/createdAtMs`]: t,
    [`ads/${adId}/updatedAtMs`]: t,

    [`boost_payments/${requestId}/paymentId`]: requestId,
    [`boost_payments/${requestId}/requestId`]: requestId,
    [`boost_payments/${requestId}/adId`]: adId,
    [`boost_payments/${requestId}/boostId`]: boostId,
    [`boost_payments/${requestId}/sellerUid`]: sellerUid,
    [`boost_payments/${requestId}/productId`]: productId,
    [`boost_payments/${requestId}/amount`]: price,
    [`boost_payments/${requestId}/currency`]: "BRL",
    [`boost_payments/${requestId}/provider`]: "mercado_pago",
    [`boost_payments/${requestId}/status`]: "pending",
    [`boost_payments/${requestId}/externalReference`]: externalReference,
    [`boost_payments/${requestId}/gatewayPreferenceId`]: preferenceId,
    [`boost_payments/${requestId}/checkoutUrl`]: checkoutUrl,
    [`boost_payments/${requestId}/createdAtMs`]: t,
    [`boost_payments/${requestId}/updatedAtMs`]: t,

    [`boost_events/${requestId}_${t}/eventId`]: `${requestId}_${t}`,
    [`boost_events/${requestId}_${t}/type`]: "created",
    [`boost_events/${requestId}_${t}/requestId`]: requestId,
    [`boost_events/${requestId}_${t}/adId`]: adId,
    [`boost_events/${requestId}_${t}/boostId`]: boostId,
    [`boost_events/${requestId}_${t}/sellerUid`]: sellerUid,
    [`boost_events/${requestId}_${t}/productId`]: productId,
    [`boost_events/${requestId}_${t}/createdAtMs`]: t,
  };

  await db.ref().update(updates);
}

async function buildExpireBoostUpdates(t) {
  const adsSnap = await db
    .ref("ads")
    .orderByChild("status")
    .equalTo("active")
    .get();

  const updates = {};
  let expiredBoosts = 0;

  if (adsSnap.exists()) {
    adsSnap.forEach((child) => {
      const adId = child.key;
      const ad = child.val() || {};
      const productId = safe(ad.productId);
      const sellerUid = safe(ad.sellerUid);
      const expiresAtMs = Number(ad.endsAtMs || ad.expiresAtMs || 0);

      if (expiresAtMs > 0 && expiresAtMs <= t) {
        expiredBoosts++;

        updates[`ads/${adId}/status`] = "expired";
        updates[`ads/${adId}/expiredAtMs`] = t;
        updates[`ads/${adId}/updatedAtMs`] = t;

        if (productId) {
          updates[`products/${productId}/isBoosted`] = false;
          updates[`products/${productId}/boosted`] = false;
          updates[`products/${productId}/boost/isBoosted`] = false;
          updates[`products/${productId}/boost/active`] = false;
          updates[`products/${productId}/boost/status`] = "expired";
          updates[`products/${productId}/boost/expiredAtMs`] = t;
          updates[`products/${productId}/boost/updatedAtMs`] = t;
          updates[`products/${productId}/boostStatus`] = "expired";
          updates[`products/${productId}/updatedAtMs`] = t;
          updates[`active_boosts_by_product/${productId}/${adId}`] = null;
        }

        if (sellerUid) {
          updates[`active_boosts_by_seller/${sellerUid}/${adId}`] = null;

          updates[`notifications/${sellerUid}/boost-expired-${adId}-${t}/title`] =
            "Anúncio expirado";
          updates[`notifications/${sellerUid}/boost-expired-${adId}-${t}/body`] =
            "O período do seu anúncio terminou.";
          updates[`notifications/${sellerUid}/boost-expired-${adId}-${t}/type`] =
            "boost_expired";
          updates[`notifications/${sellerUid}/boost-expired-${adId}-${t}/read`] =
            false;
          updates[
            `notifications/${sellerUid}/boost-expired-${adId}-${t}/createdAtMs`
          ] = t;
        }

        updates[`active_boosts/${adId}`] = null;
      }
    });
  }

  return { updates, expiredBoosts };
}

async function buildExpireVerificationUpdates(t) {
  const verifiedSnap = await db
    .ref("verified_users")
    .orderByChild("active")
    .equalTo(true)
    .get();

  const updates = {};
  let expiredVerifications = 0;

  if (verifiedSnap.exists()) {
    verifiedSnap.forEach((child) => {
      const uid = child.key;
      const data = child.val() || {};
      const expiresAtMs = Number(data.expiresAtMs || 0);

      if (!uid || !expiresAtMs) return;

      if (expiresAtMs <= t) {
        expiredVerifications++;

        updates[`verified_users/${uid}/active`] = false;
        updates[`verified_users/${uid}/status`] = "expired";
        updates[`verified_users/${uid}/expiredAtMs`] = t;
        updates[`verified_users/${uid}/updatedAtMs`] = t;

        updates[`users/${uid}/verified`] = false;
        updates[`users/${uid}/verificationStatus`] = "expired";
        updates[`users/${uid}/verificationPaymentStatus`] = "expired";
        updates[`users/${uid}/verificationExpiredAtMs`] = t;
        updates[`users/${uid}/updatedAtMs`] = t;

        updates[`users/${uid}/verificationSubscription/status`] = "expired";
        updates[`users/${uid}/verificationSubscription/active`] = false;
        updates[`users/${uid}/verificationSubscription/expiredAtMs`] = t;
        updates[`users/${uid}/verificationSubscription/updatedAtMs`] = t;

        updates[`verification_requests/${uid}/status`] = "expired";
        updates[`verification_requests/${uid}/verifiedStatus`] = "expired";
        updates[`verification_requests/${uid}/expiredAtMs`] = t;
        updates[`verification_requests/${uid}/updatedAtMs`] = t;

        updates[`notifications/${uid}/verification-expired-${t}/title`] =
          "Selo verificado expirado";
        updates[`notifications/${uid}/verification-expired-${t}/body`] =
          "Seu selo verificado expirou. Renove para ativar novamente.";
        updates[`notifications/${uid}/verification-expired-${t}/type`] =
          "verification_expired";
        updates[`notifications/${uid}/verification-expired-${t}/read`] = false;
        updates[`notifications/${uid}/verification-expired-${t}/createdAtMs`] =
          t;
      }
    });
  }

  return { updates, expiredVerifications };
}

app.get("/", (_, res) => {
  res.send(
    htmlPage(
      "FireRank API",
      "Backend online do FireRank: pagamentos, selo verificado, anúncios automáticos e recuperação de senha."
    )
  );
});

app.get("/health", (_, res) => {
  res.json({
    ok: true,
    mercadoPagoConfigured: !!MP_ACCESS_TOKEN,
    firebaseConfigured: !!FIREBASE_DATABASE_URL,
    firebaseWebApiKeyConfigured: !!FIREBASE_WEB_API_KEY,
    emailConfigured: !!SMTP_HOST && !!SMTP_USER && !!SMTP_PASS && !!MAIL_FROM_EMAIL,
    baseUrl: APP_BASE_URL,
    webhookUrl: MP_WEBHOOK_URL,
    passwordResetUrl: PASSWORD_RESET_URL,
    autoVerificationActivation: true,
    autoBoostActivation: true,
    expireBoostsEnabled: true,
    expireVerificationsEnabled: true,
    maintenanceEnabled: true,
  });
});

app.get("/success", (_, res) => {
  res.send(
    htmlPage(
      "Pagamento aprovado",
      "Pagamento concluído. Você já pode voltar ao app."
    )
  );
});

app.get("/pending", (_, res) => {
  res.send(
    htmlPage(
      "Pagamento pendente",
      "Seu pagamento está pendente. Você já pode voltar ao app e acompanhar o status."
    )
  );
});

app.get("/failure", (_, res) => {
  res.send(
    htmlPage(
      "Pagamento não concluído",
      "O pagamento não foi concluído. Você pode tentar novamente no app."
    )
  );
});

app.get("/reset-password", (_, res) => {
  res.send(resetPasswordPage());
});

app.post("/api/auth/request-password-reset", async (req, res) => {
  const email = safe(req.body?.email).toLowerCase();
  const t = nowMs();

  try {
    if (!isValidEmail(email)) {
      return res.status(400).json({
        ok: false,
        error: "Digite um e-mail válido.",
      });
    }

    if (!canRequestPasswordReset(email)) {
      return res.status(429).json({
        ok: false,
        error: "Aguarde um pouco antes de pedir outro link.",
      });
    }

    ensureEmailConfig();

    let userRecord = null;

    try {
      userRecord = await admin.auth().getUserByEmail(email);
    } catch (e) {
      console.log("Recuperação solicitada para e-mail não encontrado:", maskEmail(email));

      await db.ref(`password_reset_requests/${firebaseSafeKey(email)}_${t}`).set({
        emailMasked: maskEmail(email),
        status: "email_not_found",
        createdAtMs: t,
      });

      return res.json({
        ok: true,
        message:
          "Se existir uma conta com esse e-mail, enviaremos um link de recuperação.",
      });
    }

    const firebaseResetLink = await admin.auth().generatePasswordResetLink(email);
    const oobCode = extractOobCodeFromFirebaseLink(firebaseResetLink);

    if (!oobCode) {
      throw new Error("Não foi possível gerar o código de redefinição.");
    }

    const resetUrl = `${PASSWORD_RESET_URL}?mode=resetPassword&oobCode=${encodeURIComponent(
      oobCode
    )}&email=${encodeURIComponent(email)}`;

    await sendPasswordResetEmail({
      email,
      resetUrl,
    });

    await db.ref(`password_reset_requests/${firebaseSafeKey(userRecord.uid)}_${t}`).set({
      uid: userRecord.uid,
      emailMasked: maskEmail(email),
      status: "sent",
      provider: "railway_smtp",
      createdAtMs: t,
    });

    return res.json({
      ok: true,
      message:
        "Se existir uma conta com esse e-mail, enviaremos um link de recuperação.",
    });
  } catch (e) {
    console.error("Erro ao enviar recuperação de senha:", e.message);

    await db.ref(`password_reset_errors/${firebaseSafeKey(email || "unknown")}_${t}`).set({
      emailMasked: email ? maskEmail(email) : "",
      error: e.message || "Erro desconhecido",
      createdAtMs: t,
    });

    return res.status(500).json({
      ok: false,
      error:
        "Não foi possível enviar o e-mail de recuperação agora. Tente novamente em alguns minutos.",
    });
  }
});

app.post("/api/auth/confirm-password-reset", async (req, res) => {
  try {
    const oobCode = safe(req.body?.oobCode || req.body?.code);
    const newPassword = safe(req.body?.newPassword || req.body?.password);

    if (!FIREBASE_WEB_API_KEY) {
      return res.status(500).json({
        ok: false,
        error: "FIREBASE_WEB_API_KEY não configurada.",
      });
    }

    if (!oobCode) {
      return res.status(400).json({
        ok: false,
        error: "Link inválido. Solicite uma nova recuperação no app.",
      });
    }

    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({
        ok: false,
        error: "A senha precisa ter pelo menos 6 caracteres.",
      });
    }

    const response = await axios.post(
      `https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=${encodeURIComponent(
        FIREBASE_WEB_API_KEY
      )}`,
      {
        oobCode,
        newPassword,
      },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    const email = safe(response.data?.email);

    await db.ref(`password_reset_confirmations/${firebaseSafeKey(email || nowMs())}`).set({
      emailMasked: email ? maskEmail(email) : "",
      status: "completed",
      completedAtMs: nowMs(),
    });

    return res.json({
      ok: true,
      message: "Senha redefinida com sucesso.",
    });
  } catch (e) {
    const apiError =
      e.response?.data?.error?.message ||
      e.response?.data?.message ||
      e.message ||
      "";

    console.error("Erro ao confirmar nova senha:", apiError);

    let friendly =
      "Link expirado ou inválido. Solicite uma nova recuperação de senha no app.";

    if (apiError.includes("WEAK_PASSWORD")) {
      friendly = "A senha é muito fraca. Use pelo menos 6 caracteres.";
    }

    if (apiError.includes("EXPIRED_OOB_CODE")) {
      friendly = "Esse link expirou. Solicite uma nova recuperação de senha no app.";
    }

    if (apiError.includes("INVALID_OOB_CODE")) {
      friendly = "Esse link é inválido ou já foi usado. Solicite uma nova recuperação.";
    }

    return res.status(400).json({
      ok: false,
      error: friendly,
    });
  }
});

app.post("/api/mercadopago/create-preference", async (req, res) => {
  try {
    ensureMP();

    const body = req.body || {};
    const requestType = detectRequestTypeFromBody(body);

    const externalReference =
      safe(body.externalReference) ||
      safe(body.external_reference) ||
      safe(body.orderId) ||
      safe(body.requestId) ||
      safe(body.request_id) ||
      `${requestType}_${safe(body.uid || body.sellerUid || "unknown")}_${nowMs()}`;

    if (!externalReference) {
      return res.status(400).json({
        ok: false,
        error: "externalReference obrigatório",
      });
    }

    const rawItems = Array.isArray(body.items) ? body.items : [];

    if (rawItems.length === 0) {
      return res.status(400).json({
        ok: false,
        error: "items obrigatório",
      });
    }

    const items = rawItems.map((item, i) => {
      const unitPrice = toNumber(item.unit_price || item.unitPrice);

      if (unitPrice <= 0) {
        throw new Error(`unit_price inválido no item ${i + 1}`);
      }

      return {
        id: safe(item.id) || `${requestType}_item_${i + 1}`,
        title: safe(item.title) || `Item ${i + 1}`,
        quantity: Math.max(1, Number(item.quantity) || 1),
        currency_id: "BRL",
        unit_price: unitPrice,
      };
    });

    const metadata = {
      type: requestType,
      payment_type: requestType,
      request_type: requestType,
      request_id: externalReference,
      uid: safe(body.uid || body.userUid || body.user_uid || body.sellerUid),
      seller_uid: safe(body.sellerUid || body.seller_uid || body.uid),
      product_id: safe(body.productId || body.product_id),
      ad_id: safe(body.adId || body.ad_id || externalReference),
      boost_id: safe(body.boostId || body.boost_id || externalReference),
      plan: safe(body.plan),
      days: safe(body.days),
      placement: safe(body.placement),
      product_title: safe(body.productTitle || body.product_title),
      product_image: safe(body.productImage || body.product_image),
    };

    const payload = {
      items,
      external_reference: externalReference,
      back_urls: {
        success: PAYMENT_SUCCESS_URL,
        pending: PAYMENT_PENDING_URL,
        failure: PAYMENT_FAILURE_URL,
      },
      auto_return: "approved",
      notification_url: MP_WEBHOOK_URL,
      metadata,
    };

    const response = await axios.post(
      "https://api.mercadopago.com/checkout/preferences",
      payload,
      { headers: mpHeaders() }
    );

    const data = response.data || {};

    const preferenceId = safe(data.id);
    const checkoutUrl = safe(data.init_point);
    const sandboxInitPoint = safe(data.sandbox_init_point);

    if (requestType === "verification") {
      await savePendingVerificationPreference({
        externalReference,
        preferenceId,
        checkoutUrl,
        sandboxInitPoint,
        body,
      });
    }

    if (requestType === "boost") {
      await savePendingBoostPreference({
        externalReference,
        preferenceId,
        checkoutUrl,
        sandboxInitPoint,
        body,
      });
    }

    return res.json({
      ok: true,
      type: requestType,
      publicKey: MP_PUBLIC_KEY,
      preferenceId,
      initPoint: checkoutUrl,
      checkoutUrl,
      sandboxInitPoint,
      webhookUrl: MP_WEBHOOK_URL,
      externalReference,
    });
  } catch (error) {
    console.error("ERRO MP:", error.response?.data || error.message);

    return res.status(error.response?.status || 500).json({
      ok: false,
      error:
        error.response?.data?.message ||
        error.response?.data ||
        error.message ||
        "Erro ao criar preferência",
    });
  }
});

async function processMercadoPagoWebhookPayment(paymentId) {
  ensureMP();

  const paymentDetail = await fetchMercadoPagoPayment(paymentId);
  let requestType = detectRequestTypeFromPayment(paymentDetail);

  const externalReference = getPaymentExternalReference(paymentDetail);

  if (requestType === "unknown") {
    const uid = extractUidFromVerificationExternalReference(externalReference);

    if (uid) {
      requestType = "verification";
    } else {
      const foundBoost = await findBoostRequest({
        externalReference,
        gatewayPreferenceId: getPaymentPreferenceId(paymentDetail),
        gatewayPaymentId: safe(paymentDetail.id),
      });

      requestType = foundBoost ? "boost" : "verification";
    }
  }

  await logPaymentWebhook(paymentDetail, requestType);

  if (requestType === "boost") {
    await handleBoostPayment(paymentDetail);
    return;
  }

  await handleVerificationPayment(paymentDetail);
}

app.get("/api/mercadopago/webhook", async (req, res) => {
  try {
    const type = safe(req.query.type || req.query.topic);
    const id = safe(req.query["data.id"] || req.query.id);

    if (type === "payment" && id) {
      await processMercadoPagoWebhookPayment(id);
    }

    return res.status(200).send("ok");
  } catch (e) {
    console.error("Erro no webhook GET:", e.response?.data || e.message);
    return res.status(500).send("webhook error");
  }
});

app.post("/api/mercadopago/webhook", async (req, res) => {
  try {
    const body = req.body || {};
    const type = safe(
      body.type || body.topic || req.query.type || req.query.topic
    );
    const id = safe(
      body.data?.id ||
        body["data.id"] ||
        req.query["data.id"] ||
        req.query.id
    );

    if (type === "payment" && id) {
      await processMercadoPagoWebhookPayment(id);
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("Erro no webhook POST:", e.response?.data || e.message);
    return res.status(500).json({
      ok: false,
      error: e.message || "webhook error",
    });
  }
});

app.post("/api/internal/expire-boosts", async (_, res) => {
  try {
    const t = nowMs();

    const { updates, expiredBoosts } = await buildExpireBoostUpdates(t);

    if (Object.keys(updates).length > 0) {
      await db.ref().update(updates);
    }

    return res.json({
      ok: true,
      expiredBoosts,
      checkedAtMs: t,
    });
  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: e.message || "Erro ao expirar anúncios",
    });
  }
});

app.post("/api/internal/expire-verifications", async (_, res) => {
  try {
    const t = nowMs();

    const { updates, expiredVerifications } =
      await buildExpireVerificationUpdates(t);

    if (Object.keys(updates).length > 0) {
      await db.ref().update(updates);
    }

    return res.json({
      ok: true,
      expiredVerifications,
      checkedAtMs: t,
    });
  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: e.message || "Erro ao expirar selos verificados",
    });
  }
});

app.post("/api/internal/run-maintenance", async (_, res) => {
  try {
    const t = nowMs();

    const boostResult = await buildExpireBoostUpdates(t);
    const verificationResult = await buildExpireVerificationUpdates(t);

    const updates = {
      ...boostResult.updates,
      ...verificationResult.updates,
    };

    if (Object.keys(updates).length > 0) {
      await db.ref().update(updates);
    }

    return res.json({
      ok: true,
      expiredBoosts: boostResult.expiredBoosts,
      expiredVerifications: verificationResult.expiredVerifications,
      checkedAtMs: t,
    });
  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: e.message || "Erro ao rodar manutenção",
    });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor FireRank rodando na porta ${PORT}`);
  console.log(`Webhook Mercado Pago: ${MP_WEBHOOK_URL}`);
  console.log(`Reset de senha FireRank: ${PASSWORD_RESET_URL}`);
});

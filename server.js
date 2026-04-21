require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const admin = require("firebase-admin");

const app = express();

app.use(cors());
app.use(express.json({ limit: "2mb" }));

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

function safe(v) {
  return String(v ?? "").trim();
}

function toNumber(v) {
  const n = Number(String(v ?? "").replace(",", ".").trim());
  return Number.isFinite(n) ? n : 0;
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

function htmlPage(title, message) {
  return `
  <!DOCTYPE html>
  <html lang="pt-BR">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>${title}</title>
      <style>
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
      </style>
    </head>
    <body>
      <div class="card">
        <h1>${title}</h1>
        <p>${message}</p>
      </div>
    </body>
  </html>
  `;
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
    } catch (e) {
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
  } catch (e) {
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

function extractUidFromExternalReference(externalReference) {
  const ref = safe(externalReference);
  if (!ref.startsWith("verification_")) return "";
  const parts = ref.split("_");
  if (parts.length < 3) return "";
  return safe(parts[1]);
}

async function fetchMercadoPagoPayment(paymentId) {
  const response = await axios.get(
    `https://api.mercadopago.com/v1/payments/${paymentId}`,
    { headers: mpHeaders() }
  );
  return response.data || {};
}

function normalizePaymentStatus(status) {
  const s = safe(status).toLowerCase();

  if (s === "approved") return "approved";
  if (s === "pending") return "pending";
  if (s === "in_process") return "in_process";
  if (s === "rejected") return "rejected";
  if (s === "cancelled") return "cancelled";
  if (s === "refunded") return "refunded";
  if (s === "charged_back") return "charged_back";

  return s || "pending";
}

/**
 * Para o fluxo do selo:
 * approved -> waiting_admin_confirmation
 * pending/in_process -> payment_pending
 * rejected/cancelled/refunded/charged_back -> rejected_by_admin
 *
 * Mantive a compatibilidade com o seu painel atual.
 */
function verificationStatusFromPaymentStatus(paymentStatus) {
  const s = normalizePaymentStatus(paymentStatus);

  if (s === "approved") return "waiting_admin_confirmation";
  if (s === "pending" || s === "in_process") return "payment_pending";
  if (
    s === "rejected" ||
    s === "cancelled" ||
    s === "refunded" ||
    s === "charged_back"
  ) {
    return "rejected_by_admin";
  }

  return "payment_pending";
}

/**
 * Atualiza verification_payments procurando:
 * 1) requestId
 * 2) gatewayPreferenceId
 *
 * Isso resolve o caso em que o webhook chega, mas o update não encontra
 * o registro só pelo requestId.
 */
async function updateVerificationPaymentRecords({
  requestId,
  gatewayPaymentId,
  gatewayPreferenceId,
  paymentStatus,
  updatedAtMs,
  rawStatusDetail,
}) {
  const updates = {};

  if (requestId) {
    const byRequestId = await db
      .ref("verification_payments")
      .orderByChild("requestId")
      .equalTo(requestId)
      .get();

    if (byRequestId.exists()) {
      byRequestId.forEach((child) => {
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

  if (Object.keys(updates).length === 0 && gatewayPreferenceId) {
    const byPreference = await db
      .ref("verification_payments")
      .orderByChild("gatewayPreferenceId")
      .equalTo(gatewayPreferenceId)
      .get();

    if (byPreference.exists()) {
      byPreference.forEach((child) => {
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

  if (Object.keys(updates).length > 0) {
    await db.ref().update(updates);
  } else {
    console.log("Nenhum verification_payment encontrado para atualizar", {
      requestId,
      gatewayPaymentId,
      gatewayPreferenceId,
      paymentStatus,
    });
  }
}

async function handleVerificationPayment(paymentDetail) {
  const now = Date.now();

  const paymentId = safe(paymentDetail.id);
  const paymentStatus = normalizePaymentStatus(paymentDetail.status);
  const statusDetail = safe(paymentDetail.status_detail);
  const externalReference = safe(paymentDetail.external_reference);

  /**
   * preferenceId:
   * - tentamos primeiro metadata.preference_id
   * - depois order.id
   * - e por fim additional_info.items[0].id se existir
   */
  const preferenceId = safe(
    paymentDetail.metadata?.preference_id ||
      paymentDetail.order?.id ||
      paymentDetail.additional_info?.items?.[0]?.id
  );

  const uid = extractUidFromExternalReference(externalReference);

  if (!externalReference || !uid) {
    console.log("Webhook ignorado por external_reference inválido:", {
      externalReference,
      paymentId,
      paymentStatus,
    });
    return;
  }

  const requestRef = db.ref(`verification_requests/${uid}`);
  const requestSnap = await requestRef.get();

  if (!requestSnap.exists()) {
    console.log("verification_request não encontrado para uid", uid, {
      externalReference,
      paymentId,
      paymentStatus,
    });
    return;
  }

  const verifiedStatus = verificationStatusFromPaymentStatus(paymentStatus);

  const rootUpdates = {
    [`verification_requests/${uid}/paymentStatus`]: paymentStatus,
    [`verification_requests/${uid}/verifiedStatus`]: verifiedStatus,
    [`verification_requests/${uid}/updatedAtMs`]: now,
    [`users/${uid}/verificationPaymentStatus`]: paymentStatus,
    [`users/${uid}/updatedAtMs`]: now,
  };

  if (paymentStatus === "approved") {
    rootUpdates[`verification_requests/${uid}/adminStatus`] = "pending";
    rootUpdates[`users/${uid}/verificationStatus`] =
      "waiting_admin_confirmation";
    rootUpdates[`users/${uid}/verified`] = false;

    rootUpdates[`notifications/${uid}/verification-payment-${now}/title`] =
      "Pagamento aprovado";
    rootUpdates[`notifications/${uid}/verification-payment-${now}/body`] =
      "Seu pagamento do selo foi aprovado. Agora aguarde a confirmação do ADM.";
    rootUpdates[`notifications/${uid}/verification-payment-${now}/type`] =
      "verification_payment_approved";
    rootUpdates[`notifications/${uid}/verification-payment-${now}/read`] = false;
    rootUpdates[
      `notifications/${uid}/verification-payment-${now}/createdAtMs`
    ] = now;
  } else if (paymentStatus === "pending" || paymentStatus === "in_process") {
    rootUpdates[`verification_requests/${uid}/adminStatus`] = "pending";
    rootUpdates[`users/${uid}/verificationStatus`] = "payment_pending";
    rootUpdates[`users/${uid}/verified`] = false;
  } else {
    rootUpdates[`verification_requests/${uid}/adminStatus`] = "pending";
    rootUpdates[`users/${uid}/verificationStatus`] = "payment_pending";
    rootUpdates[`users/${uid}/verified`] = false;

    rootUpdates[`notifications/${uid}/verification-payment-${now}/title`] =
      "Pagamento não aprovado";
    rootUpdates[`notifications/${uid}/verification-payment-${now}/body`] =
      "O pagamento do selo não foi aprovado. Você pode tentar novamente no app.";
    rootUpdates[`notifications/${uid}/verification-payment-${now}/type`] =
      "verification_payment_failed";
    rootUpdates[`notifications/${uid}/verification-payment-${now}/read`] = false;
    rootUpdates[
      `notifications/${uid}/verification-payment-${now}/createdAtMs`
    ] = now;
  }

  if (paymentId) {
    rootUpdates[`verification_requests/${uid}/gatewayPaymentId`] = paymentId;
  }

  if (preferenceId) {
    rootUpdates[`verification_requests/${uid}/gatewayPreferenceId`] =
      preferenceId;
  }

  if (statusDetail) {
    rootUpdates[`verification_requests/${uid}/rawStatusDetail`] = statusDetail;
  }

  await db.ref().update(rootUpdates);

  await updateVerificationPaymentRecords({
    requestId: externalReference,
    paymentStatus,
    updatedAtMs: now,
    gatewayPaymentId: paymentId,
    gatewayPreferenceId: preferenceId,
    rawStatusDetail: statusDetail,
  });

  console.log("Webhook processado:", {
    uid,
    externalReference,
    paymentId,
    paymentStatus,
    statusDetail,
    preferenceId,
  });
}

app.get("/", (_, res) => {
  res.send(
    htmlPage("FireRank API", "Backend online do checkout do selo verificado.")
  );
});

app.get("/health", (_, res) => {
  res.json({
    ok: true,
    mercadoPagoConfigured: !!MP_ACCESS_TOKEN,
    firebaseConfigured: !!FIREBASE_DATABASE_URL,
    baseUrl: APP_BASE_URL,
    webhookUrl: MP_WEBHOOK_URL,
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

app.post("/api/mercadopago/create-preference", async (req, res) => {
  try {
    ensureMP();

    const body = req.body || {};
    const externalReference =
      safe(body.externalReference) || safe(body.orderId);

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
      const unitPrice = toNumber(item.unit_price);

      if (unitPrice <= 0) {
        throw new Error(`unit_price inválido no item ${i + 1}`);
      }

      return {
        id: safe(item.id) || `verification_item_${i + 1}`,
        title: safe(item.title) || `Item ${i + 1}`,
        quantity: Math.max(1, Number(item.quantity) || 1),
        currency_id: "BRL",
        unit_price: unitPrice,
      };
    });

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
      metadata: {
        request_id: externalReference,
      },
    };

    const response = await axios.post(
      "https://api.mercadopago.com/checkout/preferences",
      payload,
      { headers: mpHeaders() }
    );

    const data = response.data || {};

    return res.json({
      ok: true,
      publicKey: MP_PUBLIC_KEY,
      preferenceId: safe(data.id),
      initPoint: safe(data.init_point),
      checkoutUrl: safe(data.init_point),
      sandboxInitPoint: safe(data.sandbox_init_point),
      webhookUrl: MP_WEBHOOK_URL,
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

app.get("/api/mercadopago/webhook", async (req, res) => {
  try {
    const type = safe(req.query.type || req.query.topic);
    const id = safe(req.query["data.id"] || req.query.id);

    if (type === "payment" && id) {
      const paymentDetail = await fetchMercadoPagoPayment(id);
      await handleVerificationPayment(paymentDetail);
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
      const paymentDetail = await fetchMercadoPagoPayment(id);
      await handleVerificationPayment(paymentDetail);
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

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

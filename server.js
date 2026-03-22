require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const admin = require("firebase-admin");

const app = express();

app.use(cors());
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 10000;
const APP_BASE_URL = process.env.APP_BASE_URL || "http://localhost:10000";

const MP_PUBLIC_KEY = process.env.MERCADO_PAGO_PUBLIC_KEY || "";
const MP_ACCESS_TOKEN = process.env.MERCADO_PAGO_ACCESS_TOKEN || "";
const MP_WEBHOOK_URL =
  process.env.MERCADO_PAGO_WEBHOOK_URL || `${APP_BASE_URL}/webhook`;

const PAYMENT_SUCCESS_URL =
  process.env.PAYMENT_SUCCESS_URL || `${APP_BASE_URL}/success`;
const PAYMENT_PENDING_URL =
  process.env.PAYMENT_PENDING_URL || `${APP_BASE_URL}/pending`;
const PAYMENT_FAILURE_URL =
  process.env.PAYMENT_FAILURE_URL || `${APP_BASE_URL}/failure`;

const FIREBASE_DATABASE_URL = process.env.FIREBASE_DATABASE_URL || "";
const FIREBASE_SERVICE_ACCOUNT_JSON =
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON || "";

let firebaseReady = false;

function initFirebase() {
  try {
    if (!FIREBASE_DATABASE_URL || !FIREBASE_SERVICE_ACCOUNT_JSON) {
      console.log("[firebase] not configured, webhook sync will be skipped");
      return;
    }

    if (admin.apps.length > 0) {
      firebaseReady = true;
      return;
    }

    const serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: FIREBASE_DATABASE_URL,
    });

    firebaseReady = true;
    console.log("[firebase] initialized");
  } catch (error) {
    firebaseReady = false;
    console.error("[firebase] init error:", error.message);
  }
}

initFirebase();

function mpHeaders() {
  return {
    Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
    "Content-Type": "application/json",
  };
}

function ensureMercadoPagoConfigured() {
  if (!MP_ACCESS_TOKEN) {
    throw new Error("MERCADO_PAGO_ACCESS_TOKEN não configurado.");
  }
  if (!MP_PUBLIC_KEY) {
    throw new Error("MERCADO_PAGO_PUBLIC_KEY não configurado.");
  }
}

function toNumber(value, fallback = 0) {
  if (value === null || value === undefined) return fallback;
  const n =
    typeof value === "number"
      ? value
      : Number(String(value).replace(",", ".").trim());
  return Number.isFinite(n) ? n : fallback;
}

function toInt(value, fallback = 0) {
  return Math.trunc(toNumber(value, fallback));
}

function safeText(value) {
  return String(value ?? "").trim();
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

async function getPayment(paymentId) {
  const url = `https://api.mercadopago.com/v1/payments/${paymentId}`;
  const response = await axios.get(url, { headers: mpHeaders() });
  return response.data;
}

async function updateOrderOrGroupByExternalReference(externalReference, patch) {
  if (!firebaseReady || !externalReference) return false;

  const orderRef = admin.database().ref(`orders/${externalReference}`);
  const orderSnap = await orderRef.get();

  if (orderSnap.exists()) {
    await orderRef.update({
      ...patch,
      updatedAtMs: Date.now(),
    });
    return true;
  }

  const groupRef = admin.database().ref(`checkout_groups/${externalReference}`);
  const groupSnap = await groupRef.get();

  if (!groupSnap.exists()) {
    console.log("[firebase] no order or group found:", externalReference);
    return false;
  }

  const groupData = groupSnap.val() || {};
  const orderIdsMap = groupData.orderIds || {};

  await groupRef.update({
    ...patch,
    updatedAtMs: Date.now(),
  });

  const updates = {};
  for (const orderId of Object.keys(orderIdsMap)) {
    updates[`orders/${orderId}/updatedAtMs`] = Date.now();
    for (const [key, value] of Object.entries(patch)) {
      updates[`orders/${orderId}/${key}`] = value;
    }
  }

  if (Object.keys(updates).length > 0) {
    await admin.database().ref().update(updates);
  }

  return true;
}

function mapPaymentStatusToOrderStatus(paymentStatus, paymentDetail) {
  const status = safeText(paymentStatus).toLowerCase();
  const detail = safeText(paymentDetail).toLowerCase();

  if (status === "approved") {
    return {
      status: "paid",
      paymentStatus: "approved",
      shippingStatus: "not_started",
    };
  }

  if (status === "pending" || status === "in_process") {
    return {
      status: "waiting_payment",
      paymentStatus: "pending",
    };
  }

  if (status === "rejected" || status === "cancelled") {
    return {
      status: "cancelled",
      paymentStatus: status,
      refundStatus: detail === "refunded" ? "refunded" : "none",
    };
  }

  if (status === "refunded" || detail === "refunded") {
    return {
      status: "refunded",
      paymentStatus: "refunded",
      refundStatus: "refunded",
    };
  }

  return {
    paymentStatus: status || "unknown",
  };
}

app.get("/", (_, res) => {
  res.send(
    htmlPage(
      "FireRank API",
      "Backend do FireRank online. Mercado Pago e webhooks prontos."
    )
  );
});

app.get("/health", (_, res) => {
  res.json({
    ok: true,
    service: "firerank-api",
    mercadoPagoConfigured: !!MP_ACCESS_TOKEN && !!MP_PUBLIC_KEY,
    firebaseReady,
    baseUrl: APP_BASE_URL,
  });
});

app.get("/success", (req, res) => {
  res.send(
    htmlPage(
      "Pagamento aprovado",
      `Pagamento concluído. Você já pode voltar ao app. ${
        safeText(req.query.payment_id)
          ? `Payment ID: ${safeText(req.query.payment_id)}.`
          : ""
      }`
    )
  );
});

app.get("/pending", (req, res) => {
  res.send(
    htmlPage(
      "Pagamento pendente",
      `Seu pagamento está pendente. Você já pode voltar ao app e acompanhar o status. ${
        safeText(req.query.payment_id)
          ? `Payment ID: ${safeText(req.query.payment_id)}.`
          : ""
      }`
    )
  );
});

app.get("/failure", (req, res) => {
  res.send(
    htmlPage(
      "Pagamento não concluído",
      `O pagamento não foi concluído. Você pode tentar novamente no app. ${
        safeText(req.query.payment_id)
          ? `Payment ID: ${safeText(req.query.payment_id)}.`
          : ""
      }`
    )
  );
});

app.post("/api/mercadopago/create-preference", async (req, res) => {
  try {
    ensureMercadoPagoConfigured();

    const body = req.body || {};
    const externalReference =
      safeText(body.externalReference) || safeText(body.orderId);
    const title = safeText(body.title) || "Pedido FireRank";

    const rawItems = Array.isArray(body.items) ? body.items : [];

    if (!externalReference) {
      return res.status(400).json({
        ok: false,
        error: "externalReference é obrigatório.",
      });
    }

    if (rawItems.length === 0) {
      return res.status(400).json({
        ok: false,
        error: "items é obrigatório.",
      });
    }

    const items = rawItems.map((item, index) => {
      const itemTitle = safeText(item.title) || `Item ${index + 1}`;
      const quantity = Math.max(1, toInt(item.quantity, 1));
      const unitPrice = toNumber(item.unit_price, 0);

      if (unitPrice <= 0) {
        throw new Error(`unit_price inválido no item ${index + 1}.`);
      }

      return {
        id: safeText(item.id) || `${externalReference}_${index + 1}`,
        title: itemTitle,
        description: safeText(item.description) || itemTitle,
        picture_url: safeText(item.picture_url) || undefined,
        category_id: safeText(item.category_id) || "others",
        quantity,
        currency_id: safeText(item.currency_id) || "BRL",
        unit_price: unitPrice,
      };
    });

    const payer =
      body.payer && typeof body.payer === "object" ? body.payer : {};

    const payload = {
      items,
      payer: {
        email: safeText(payer.email) || undefined,
        name: safeText(payer.name) || undefined,
        surname: safeText(payer.surname) || undefined,
      },
      external_reference: externalReference,
      notification_url: MP_WEBHOOK_URL,
      back_urls: {
        success: PAYMENT_SUCCESS_URL,
        pending: PAYMENT_PENDING_URL,
        failure: PAYMENT_FAILURE_URL,
      },
      auto_return: "approved",
      metadata: {
        externalReference,
        source: "firerank",
        title,
      },
    };

    console.log("[create-preference] payload:", JSON.stringify(payload));

    const response = await axios.post(
      "https://api.mercadopago.com/checkout/preferences",
      payload,
      { headers: mpHeaders() }
    );

    const data = response.data || {};

    if (firebaseReady) {
      await updateOrderOrGroupByExternalReference(externalReference, {
        checkoutPreferenceId: safeText(data.id),
        checkoutUrl: safeText(data.init_point || data.sandbox_init_point),
        paymentProvider: "mercado_pago",
        paymentMethod: "mercado_pago",
        paymentStatus: "awaiting_checkout",
      });
    }

    return res.json({
      ok: true,
      publicKey: MP_PUBLIC_KEY,
      preferenceId: safeText(data.id),
      initPoint: safeText(data.init_point),
      sandboxInitPoint: safeText(data.sandbox_init_point),
      externalReference,
    });
  } catch (error) {
    console.error(
      "[create-preference] error:",
      error.response?.data || error.message
    );

    return res.status(error.response?.status || 500).json({
      ok: false,
      error:
        error.response?.data?.message ||
        error.response?.data ||
        error.message ||
        "Erro ao criar preferência.",
      details: error.response?.data || null,
    });
  }
});

app.post("/webhook", async (req, res) => {
  try {
    ensureMercadoPagoConfigured();

    const queryType = safeText(req.query.type || req.query.topic);
    const bodyType = safeText(req.body?.type || req.body?.topic);
    const topic = queryType || bodyType;

    const queryDataId = safeText(req.query["data.id"]);
    const bodyDataId = safeText(req.body?.data?.id || req.body?.id);
    const resourceId = queryDataId || bodyDataId;

    console.log("[webhook] topic:", topic);
    console.log("[webhook] resourceId:", resourceId);
    console.log("[webhook] body:", JSON.stringify(req.body || {}));

    if (!resourceId) {
      return res
        .status(200)
        .json({ ok: true, received: true, skipped: "no_resource_id" });
    }

    if (topic && topic !== "payment") {
      return res.status(200).json({
        ok: true,
        received: true,
        skipped: `topic_${topic}`,
      });
    }

    const payment = await getPayment(resourceId);
    const externalReference = safeText(payment.external_reference);
    const paymentId = safeText(payment.id);
    const paymentStatus = safeText(payment.status);
    const paymentDetail = safeText(payment.status_detail);

    const patch = {
      paymentId,
      paymentStatus,
      mercadoPagoStatus: paymentStatus,
      mercadoPagoStatusDetail: paymentDetail,
      ...mapPaymentStatusToOrderStatus(paymentStatus, paymentDetail),
    };

    if (paymentStatus === "approved") {
      patch.paidAtMs = Date.now();
    }

    if (firebaseReady && externalReference) {
      await updateOrderOrGroupByExternalReference(externalReference, patch);
    }

    return res.status(200).json({
      ok: true,
      received: true,
      paymentId,
      externalReference,
      paymentStatus,
    });
  } catch (error) {
    console.error("[webhook] error:", error.response?.data || error.message);

    return res.status(error.response?.status || 500).json({
      ok: false,
      error:
        error.response?.data?.message ||
        error.response?.data ||
        error.message ||
        "Erro no webhook.",
    });
  }
});

app.listen(PORT, () => {
  console.log(`FireRank API running on port ${PORT}`);
  console.log(`Base URL: ${APP_BASE_URL}`);
});

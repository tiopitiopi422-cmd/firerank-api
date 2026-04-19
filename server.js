require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();

app.use(cors());
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 10000;
const APP_BASE_URL = process.env.APP_BASE_URL || "http://localhost:10000";

const MP_PUBLIC_KEY = process.env.MERCADO_PAGO_PUBLIC_KEY || "";
const MP_ACCESS_TOKEN = process.env.MERCADO_PAGO_ACCESS_TOKEN || "";

const PAYMENT_SUCCESS_URL =
  process.env.PAYMENT_SUCCESS_URL || `${APP_BASE_URL}/success`;
const PAYMENT_PENDING_URL =
  process.env.PAYMENT_PENDING_URL || `${APP_BASE_URL}/pending`;
const PAYMENT_FAILURE_URL =
  process.env.PAYMENT_FAILURE_URL || `${APP_BASE_URL}/failure`;

function mpHeaders() {
  return {
    Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
    "Content-Type": "application/json",
  };
}

function ensureMP() {
  if (!MP_ACCESS_TOKEN) {
    throw new Error("ACCESS TOKEN não configurado");
  }
}

function toNumber(v) {
  const n = Number(String(v ?? "").replace(",", ".").trim());
  return Number.isFinite(n) ? n : 0;
}

function safe(v) {
  return String(v ?? "").trim();
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

app.get("/", (_, res) => {
  res.send(
    htmlPage(
      "FireRank API",
      "Backend online do checkout do selo verificado."
    )
  );
});

app.get("/health", (_, res) => {
  res.json({
    ok: true,
    mercadoPagoConfigured: !!MP_ACCESS_TOKEN,
    baseUrl: APP_BASE_URL,
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
    };

    console.log("PAYLOAD:", JSON.stringify(payload, null, 2));

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

app.listen(PORT, () => {
  console.log("Servidor rodando na porta", PORT);
});

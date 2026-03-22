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
  return Number(v) || 0;
}

function safe(v) {
  return String(v ?? "").trim();
}

app.get("/health", (_, res) => {
  res.json({
    ok: true,
    mercadoPagoConfigured: !!MP_ACCESS_TOKEN,
    baseUrl: APP_BASE_URL,
  });
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

    const items = rawItems.map((item, i) => ({
      title: safe(item.title) || `Item ${i + 1}`,
      quantity: Math.max(1, Number(item.quantity) || 1),
      currency_id: "BRL",
      unit_price: toNumber(item.unit_price),
    }));

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

    console.log("PAYLOAD:", payload);

    const response = await axios.post(
      "https://api.mercadopago.com/checkout/preferences",
      payload,
      { headers: mpHeaders() }
    );

    const data = response.data;

    return res.json({
      ok: true,
      publicKey: MP_PUBLIC_KEY,
      preferenceId: data.id,
      initPoint: data.init_point,
    });
  } catch (error) {
    console.error("ERRO MP:", error.response?.data || error.message);

    return res.status(500).json({
      ok: false,
      error: error.response?.data || error.message,
    });
  }
});

app.listen(PORT, () => {
  console.log("Servidor rodando na porta", PORT);
});

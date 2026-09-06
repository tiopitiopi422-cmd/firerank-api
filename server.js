require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { initializeApp, getApps, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getDatabase } = require("firebase-admin/database");
const { getAppCheck } = require("firebase-admin/app-check");
const nodemailer = require("nodemailer");
const sharp = require("sharp");
const multer = require("multer");
const { v2: cloudinary } = require("cloudinary");
const {
  WebhookSignatureValidator,
  InvalidWebhookSignatureError,
} = require("mercadopago");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

const PORT = Number(process.env.PORT || 10000);
const NODE_ENV = String(process.env.NODE_ENV || "development")
  .trim()
  .toLowerCase();

const FIRERANK_SCHEMA_VERSION = "4.2.0";
const OFFICIAL_RENDER_BASE_URL = "https://firerank-api-oxy1.onrender.com";

const APP_BASE_URL = String(
  process.env.APP_BASE_URL ||
    (NODE_ENV === "production"
      ? OFFICIAL_RENDER_BASE_URL
      : `http://localhost:${PORT}`)
).replace(/\/+$/, "");

const FIREBASE_DATABASE_URL = String(process.env.FIREBASE_DATABASE_URL || "");
const FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 = String(
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 || ""
);
const FIREBASE_SERVICE_ACCOUNT_JSON = String(
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON || ""
);
const FIREBASE_WEB_API_KEY = String(process.env.FIREBASE_WEB_API_KEY || "");

const MP_PUBLIC_KEY = String(process.env.MERCADO_PAGO_PUBLIC_KEY || "");
const MP_ACCESS_TOKEN = String(process.env.MERCADO_PAGO_ACCESS_TOKEN || "");
const MP_WEBHOOK_SECRET = String(
  process.env.MERCADO_PAGO_WEBHOOK_SECRET || ""
);
const MP_WEBHOOK_URL = String(
  process.env.MP_WEBHOOK_URL ||
    process.env.MERCADO_PAGO_WEBHOOK_URL ||
    `${APP_BASE_URL}/api/mercadopago/webhook`
);

const PAYMENT_SUCCESS_URL = String(
  process.env.PAYMENT_SUCCESS_URL || `${APP_BASE_URL}/success`
);
const PAYMENT_PENDING_URL = String(
  process.env.PAYMENT_PENDING_URL || `${APP_BASE_URL}/pending`
);
const PAYMENT_FAILURE_URL = String(
  process.env.PAYMENT_FAILURE_URL || `${APP_BASE_URL}/failure`
);
const PASSWORD_RESET_URL = String(
  process.env.PASSWORD_RESET_URL || `${APP_BASE_URL}/reset-password`
);

const SMTP_HOST = String(process.env.SMTP_HOST || "");
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_SECURE =
  String(process.env.SMTP_SECURE || "true").toLowerCase() === "true";
const SMTP_USER = String(process.env.SMTP_USER || "");
const SMTP_PASS = String(process.env.SMTP_PASS || "");
const MAIL_FROM_NAME = String(process.env.MAIL_FROM_NAME || "FireRank");
const MAIL_FROM_EMAIL = String(process.env.MAIL_FROM_EMAIL || SMTP_USER || "");

const REQUIRE_APP_CHECK =
  String(process.env.REQUIRE_APP_CHECK || "false").toLowerCase() === "true";
const ENFORCE_GOOGLE_PLAY_BILLING =
  String(process.env.ENFORCE_GOOGLE_PLAY_BILLING || "false").toLowerCase() ===
  "true";
const INTERNAL_MAINTENANCE_SECRET = String(
  process.env.INTERNAL_MAINTENANCE_SECRET || ""
);
const MEDIA_TOKEN_SECRET = String(process.env.MEDIA_TOKEN_SECRET || "");
const BOOST_CATALOG_JSON = String(process.env.BOOST_CATALOG_JSON || "");

const CLOUDINARY_CLOUD_NAME = String(process.env.CLOUDINARY_CLOUD_NAME || "dkrwufqxc").trim();
const CLOUDINARY_API_KEY = String(process.env.CLOUDINARY_API_KEY || "").trim();
const CLOUDINARY_API_SECRET = String(process.env.CLOUDINARY_API_SECRET || "").trim();
const GEMINI_API_KEY = String(process.env.GEMINI_API_KEY || "").trim();
const GEMINI_MODEL = String(process.env.GEMINI_MODEL || "").trim();
const CLOUDINARY_CONFIGURED = !!(CLOUDINARY_CLOUD_NAME && CLOUDINARY_API_KEY && CLOUDINARY_API_SECRET);
cloudinary.config({ cloud_name: CLOUDINARY_CLOUD_NAME, api_key: CLOUDINARY_API_KEY, api_secret: CLOUDINARY_API_SECRET, secure: true });

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const MEDIA_UPLOAD_TOKEN_TTL_MS = 2 * HOUR_MS;
const PAYMENT_PROCESSING_LOCK_TTL_MS = 2 * 60 * 1000;
const MAX_MEDIA_BYTES = 12 * 1024 * 1024;
const MAX_PRODUCT_IMAGES = 8;
const MAX_VARIANT_COMBINATIONS = 60;

function safe(value) {
  return String(value ?? "").trim();
}

function nowMs() {
  return Date.now();
}

function bool(value, fallback = false) {
  if (typeof value === "boolean") return value;
  if (value === 1 || value === "1" || value === "true") return true;
  if (value === 0 || value === "0" || value === "false") return false;
  return fallback;
}

function integer(value, fallback = 0) {
  const n = Number(value);
  return Number.isInteger(n) ? n : fallback;
}

function finiteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function isObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function map(value) {
  return isObject(value) ? value : {};
}

function clip(value, max) {
  return safe(value).slice(0, max);
}

function firebaseSafeKey(value) {
  const text = safe(value);
  if (!text) return "";
  return text.replace(/[.#$/[\]]/g, "_");
}

function stableHash(value) {
  return crypto.createHash("sha256").update(String(value ?? "")).digest("hex");
}

function timingSafeEqualText(a, b) {
  const aBuffer = Buffer.from(String(a ?? ""));
  const bBuffer = Buffer.from(String(b ?? ""));
  if (aBuffer.length !== bBuffer.length) return false;
  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

function isHttpsUrl(value) {
  try {
    return new URL(String(value || "")).protocol === "https:";
  } catch (_) {
    return false;
  }
}

async function bestEffort(label, action) {
  try {
    await action();
  } catch (error) {
    console.error(
      `[best-effort:${label}]`,
      error?.code || error?.message || "error"
    );
  }
}

function validateCriticalRuntimeConfig() {
  if (!Number.isFinite(PORT) || PORT <= 0 || PORT > 65535) {
    throw new Error("PORT_INVALID");
  }

  if (
    NODE_ENV === "production" &&
    !isHttpsUrl(APP_BASE_URL)
  ) {
    console.warn(
      "APP_BASE_URL ainda não é HTTPS. Defina APP_BASE_URL para o domínio público do Render antes de conectar o app."
    );
  }

  if (
    NODE_ENV === "production" &&
    !MEDIA_TOKEN_SECRET
  ) {
    throw new Error(
      "MEDIA_TOKEN_SECRET_REQUIRED_IN_PRODUCTION"
    );
  }

  if (
    NODE_ENV === "production" &&
    MP_ACCESS_TOKEN &&
    !MP_WEBHOOK_SECRET
  ) {
    throw new Error(
      "MERCADO_PAGO_WEBHOOK_SECRET_REQUIRED_WHEN_PAYMENTS_ARE_ENABLED"
    );
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
    raw = Buffer.from(
      FIREBASE_SERVICE_ACCOUNT_JSON_BASE64.trim(),
      "base64"
    ).toString("utf8");
  } else if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    raw = FIREBASE_SERVICE_ACCOUNT_JSON.trim();
  } else {
    throw new Error(
      "Firebase não configurado. Defina FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 ou FIREBASE_SERVICE_ACCOUNT_JSON"
    );
  }

  const serviceAccount = JSON.parse(raw);

  if (!serviceAccount.private_key || !serviceAccount.project_id) {
    throw new Error("Service account Firebase incompleta");
  }

  serviceAccount.private_key = normalizePrivateKey(serviceAccount.private_key);
  return serviceAccount;
}

if (!FIREBASE_DATABASE_URL) {
  throw new Error("FIREBASE_DATABASE_URL não configurado");
}

const serviceAccount = parseServiceAccount();
const firebaseApp =
  getApps().length > 0
    ? getApps()[0]
    : initializeApp({
        credential: cert(serviceAccount),
        databaseURL: FIREBASE_DATABASE_URL,
      });

const db = getDatabase(firebaseApp);
const firebaseAuth = getAuth(firebaseApp);
const firebaseAppCheck = getAppCheck(firebaseApp);

const configuredAllowedOrigins = String(
  process.env.CORS_ALLOWED_ORIGINS || ""
)
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);

const allowedOrigins = new Set(configuredAllowedOrigins);

// FireRank Admin - Hosting oficial
allowedOrigins.add("https://firerank-admin.web.app");
allowedOrigins.add("https://firerank-admin.firebaseapp.com");

if (isHttpsUrl(APP_BASE_URL)) {
  try {
    allowedOrigins.add(new URL(APP_BASE_URL).origin);
  } catch (_) {}
}

app.use(
  cors({
    origin(origin, callback) {
      // Apps nativos, curl e chamadas servidor-servidor normalmente não enviam Origin.
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.has(origin)) {
        return callback(null, true);
      }

      // Em desenvolvimento, manter conveniência local. Em produção, fail closed.
      if (
        NODE_ENV !== "production" &&
        configuredAllowedOrigins.length === 0
      ) {
        return callback(null, true);
      }

      return callback(
        new Error("CORS_ORIGIN_NOT_ALLOWED")
      );
    },
    credentials: false,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: [
      "Authorization",
      "Content-Type",
      "X-Firebase-AppCheck",
      "X-Firebase-AppCheck-Token",
      "X-FireRank-Schema",
      "X-FireRank-Internal-Secret",
      "X-Client-Platform",
      "Idempotency-Key",
      "X-Idempotency-Key",
    ],
    maxAge: 86400,
  })
);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  res.setHeader("X-FireRank-Schema", FIRERANK_SCHEMA_VERSION);
  next();
});

app.use(
  express.json({
    limit: "2mb",
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "2mb",
  })
);

const rateBuckets = new Map();

function rateLimit(
  name,
  max,
  windowMs
) {
  return (req, res, next) => {
    const key =
      `${name}:${req.auth?.uid || req.ip || "unknown"}`;

    const t = nowMs();

    const current =
      rateBuckets.get(key);

    if (
      !current ||
      current.resetAtMs <= t
    ) {
      rateBuckets.set(
        key,
        {
          count: 1,
          resetAtMs: t + windowMs,
        }
      );

      return next();
    }

    current.count += 1;

    if (
      current.count > max
    ) {
      res.setHeader(
        "Retry-After",
        Math.max(
          1,
          Math.ceil(
            (current.resetAtMs - t) / 1000
          )
        ).toString()
      );

      return res.status(429).json({
        ok: false,
        code: "RATE_LIMITED",
        message:
          "Muitas tentativas. Aguarde um pouco.",
      });
    }

    rateBuckets.set(
      key,
      current
    );

    return next();
  };
}

setInterval(() => {
  const t = nowMs();

  for (
    const [key, value]
    of rateBuckets.entries()
  ) {
    if (
      !value ||
      value.resetAtMs <= t
    ) {
      rateBuckets.delete(key);
    }
  }
}, 10 * 60 * 1000).unref();

function bearerToken(req) {
  const header =
    safe(req.headers.authorization);

  if (
    !header
      .toLowerCase()
      .startsWith("bearer ")
  ) {
    return "";
  }

  return header
    .slice(7)
    .trim();
}

async function verifyAppCheckIfRequired(
  req
) {
  if (!REQUIRE_APP_CHECK) {
    return;
  }

  const token = safe(
    req.headers["x-firebase-appcheck"] ||
      req.headers[
        "x-firebase-appcheck-token"
      ]
  );

  if (!token) {
    const error =
      new Error(
        "APP_CHECK_REQUIRED"
      );

    error.statusCode = 401;

    throw error;
  }

  await firebaseAppCheck.verifyToken(token);
}

async function requireUser(
  req,
  res,
  next
) {
  try {
    const token =
      bearerToken(req);

    if (!token) {
      return res
        .status(401)
        .json({
          ok: false,
          code:
            "AUTH_REQUIRED",
          message:
            "Autenticação necessária.",
        });
    }

    await verifyAppCheckIfRequired(
      req
    );

    const decoded =
      await firebaseAuth.verifyIdToken(token, true);

    const provider =
      safe(
        decoded.firebase
          ?.sign_in_provider
      ).toLowerCase();

    if (
      !decoded.uid ||
      provider === "anonymous"
    ) {
      return res
        .status(403)
        .json({
          ok: false,
          code:
            "FULL_ACCOUNT_REQUIRED",
          message:
            "Use uma conta completa para esta ação.",
        });
    }

    req.auth = decoded;

    return next();
  } catch (error) {
    if (
      NODE_ENV !== "production"
    ) {
      console.error(
        "Auth middleware:",
        error.message
      );
    }

    return res
      .status(
        error.statusCode || 401
      )
      .json({
        ok: false,
        code:
          "INVALID_SESSION",
        message:
          "Sessão inválida ou expirada.",
      });
  }
}

function requireInternalSecret(
  req,
  res,
  next
) {
  if (
    !INTERNAL_MAINTENANCE_SECRET
  ) {
    return res
      .status(503)
      .json({
        ok: false,
        code:
          "MAINTENANCE_SECRET_NOT_CONFIGURED",
        message:
          "Manutenção interna não configurada.",
      });
  }

  const supplied =
    safe(
      req.headers[
        "x-firerank-internal-secret"
      ]
    );

  if (
    !supplied ||
    !timingSafeEqualText(
      supplied,
      INTERNAL_MAINTENANCE_SECRET
    )
  ) {
    return res
      .status(401)
      .json({
        ok: false,
        code:
          "INTERNAL_AUTH_REQUIRED",
        message:
          "Não autorizado.",
      });
  }

  return next();
}

async function appendAudit(
  type,
  data = {}
) {
  const ref =
    db.ref(
      "audit_logs"
    ).push();

  const eventId =
    ref.key;

  await ref.set({
    eventId,
    type:
      clip(
        type,
        80
      ),
    actorType:
      clip(
        data.actorType ||
          "backend",
        40
      ),
    actorUid:
      clip(
        data.actorUid || "",
        128
      ),
    targetUid:
      clip(
        data.targetUid || "",
        128
      ),
    referenceId:
      clip(
        data.referenceId || "",
        180
      ),
    status:
      clip(
        data.status || "ok",
        60
      ),
    createdAtMs:
      nowMs(),
    immutable:
      true,
  });

  return eventId;
}

async function pushNotification(
  uid,
  notification
) {
  if (!uid) {
    return;
  }

  const ref =
    db
      .ref(
        `notifications/${uid}`
      )
      .push();

  await ref.set({
    title:
      clip(
        notification.title,
        120
      ),
    body:
      clip(
        notification.body,
        500
      ),
    type:
      clip(
        notification.type ||
          "system",
        80
      ),
    read:
      false,
    createdAtMs:
      nowMs(),
    data:
      map(
        notification.data
      ),
  });
}

async function ensurePublicApiConfig() {
  if (!isHttpsUrl(APP_BASE_URL) && NODE_ENV === "production") {
    console.warn(
      "public_config/api não foi alterado: APP_BASE_URL público HTTPS ainda não está configurado."
    );
    return false;
  }

  const t = nowMs();

  await db.ref("public_config/api").update({
    schemaVersion: FIRERANK_SCHEMA_VERSION,
    baseUrl: APP_BASE_URL,
    gatewayBaseUrl: APP_BASE_URL,
    backendBaseUrl: APP_BASE_URL,
    productCreateEndpoint: `${APP_BASE_URL}/v1/products`,
    createProductEndpoint: `${APP_BASE_URL}/v1/products`,
    productUpdateEndpoint: `${APP_BASE_URL}/v1/products/update`,
    updateProductEndpoint: `${APP_BASE_URL}/v1/products/update`,
    mediaUploadEndpoint: `${APP_BASE_URL}/v1/media/product`,
    productMediaUploadEndpoint: `${APP_BASE_URL}/v1/media/product`,
    mediaSignEndpoint: `${APP_BASE_URL}/v1/media/sign`,
    addressSaveEndpoint: `${APP_BASE_URL}/v1/account/address`,
    saveAddressEndpoint: `${APP_BASE_URL}/v1/account/address`,
    userAddressEndpoint: `${APP_BASE_URL}/v1/account/address`,
    billingMercadoPagoEndpoint:
      `${APP_BASE_URL}/v1/billing/mercadopago/create-preference`,
    sellerApplicationEndpoint: `${APP_BASE_URL}/v1/applications/seller`,
    deliveryApplicationEndpoint: `${APP_BASE_URL}/v1/applications/delivery`,
    accountPrivacyEndpoint: `${APP_BASE_URL}/v1/account/privacy`,
    supportChatEndpoint: `${APP_BASE_URL}/v1/support/chat`,
    aiAssistantEndpoint: `${APP_BASE_URL}/v1/ai/v2/chat`,
    analyticsBannerEndpoint: `${APP_BASE_URL}/v1/analytics/banner`,
    mediaProvider: "cloudinary",
    firebaseStorageUsed: false,
    updatedAtMs: t,
  });

  return true;
}

async function getFeatureFlag(
  name,
  fallback = false
) {
  const snap =
    await db
      .ref(
        `feature_flags/${name}`
      )
      .get();

  return snap.exists()
    ? bool(
        snap.val(),
        fallback
      )
    : fallback;
}

async function getAccountVisibility(
  uid
) {
  const snap =
    await db
      .ref(
        `account_visibility/${uid}`
      )
      .get();

  const visibility =
    safe(
      snap.val()
    ).toLowerCase();

  return visibility ===
    "private"
    ? "private"
    : "public";
}

async function assertSellerCanPublish(
  uid
) {
  const [
    rolesSnap,
    stateSnap,
    eligibilitySnap,
  ] =
    await Promise.all([
      db
        .ref(
          `user_roles/${uid}`
        )
        .get(),

      db
        .ref(
          `role_state/${uid}/seller`
        )
        .get(),

      db
        .ref(
          `eligibility/${uid}`
        )
        .get(),
    ]);

  const roles =
    map(
      rolesSnap.val()
    );

  const state =
    map(
      stateSnap.val()
    );

  const eligibility =
    map(
      eligibilitySnap.val()
    );

  const allowed =
    roles.seller === true &&
    state.active === true &&
    state.accessEnabled === true &&
    eligibility.canSell === true &&
    eligibility.needsAgeReview !== true;

  if (!allowed) {
    const error =
      new Error(
        "SELLER_NOT_ELIGIBLE"
      );

    error.statusCode =
      403;

    error.publicMessage =
      "Sua conta ainda não está liberada para publicar produtos.";

    throw error;
  }

  return {
    roles,
    state,
    eligibility,
  };
}

async function resolveStoreForUser(
  uid,
  requestedStoreId
) {
  const requested =
    safe(
      requestedStoreId
    );

  if (requested) {
    const memberSnap =
      await db
        .ref(
          `store_members/${requested}/${uid}`
        )
        .get();

    const member =
      map(
        memberSnap.val()
      );

    if (
      member.active !== true
    ) {
      const error =
        new Error(
          "STORE_MEMBERSHIP_REQUIRED"
        );

      error.statusCode =
        403;

      error.publicMessage =
        "Você não possui acesso a esta loja.";

      throw error;
    }

    return requested;
  }

  const indexSnap =
    await db
      .ref(
        `stores_by_user/${uid}`
      )
      .get();

  const index =
    map(
      indexSnap.val()
    );

  for (
    const storeId
    of Object
      .keys(index)
      .slice(0, 20)
  ) {
    const memberSnap =
      await db
        .ref(
          `store_members/${storeId}/${uid}`
        )
        .get();

    if (
      map(
        memberSnap.val()
      ).active === true
    ) {
      return storeId;
    }
  }

  const error =
    new Error(
      "STORE_REQUIRED"
    );

  error.statusCode =
    422;

  error.publicMessage =
    "Nenhuma loja válida foi encontrada para esta conta.";

  throw error;
}

function normalizeSearchTerm(
  value
) {
  return safe(value)
    .normalize("NFD")
    .replace(
      /[\u0300-\u036f]/g,
      ""
    )
    .toLowerCase()
    .replace(
      /[^a-z0-9]+/g,
      "_"
    )
    .replace(
      /^_+|_+$/g,
      ""
    )
    .slice(
      0,
      80
    );
}

function searchTermsForProduct(
  title,
  categoryId
) {
  const terms =
    new Set();

  const full =
    normalizeSearchTerm(
      title
    );

  const category =
    normalizeSearchTerm(
      categoryId
    );

  if (full) {
    terms.add(full);
  }

  if (category) {
    terms.add(category);
  }

  for (
    const part
    of safe(title)
      .split(/\s+/)
      .slice(0, 12)
  ) {
    const term =
      normalizeSearchTerm(
        part
      );

    if (
      term.length >= 2
    ) {
      terms.add(term);
    }

    if (
      terms.size >= 12
    ) {
      break;
    }
  }

  return [...terms];
}

function makeSignedToken(
  payload,
  secret
) {
  const body =
    Buffer
      .from(
        JSON.stringify(
          payload
        )
      )
      .toString(
        "base64url"
      );

  const signature =
    crypto
      .createHmac(
        "sha256",
        secret
      )
      .update(body)
      .digest(
        "base64url"
      );

  return `${body}.${signature}`;
}

function verifySignedToken(
  token,
  secret
) {
  const parts =
    safe(token).split(".");

  if (
    parts.length !== 2
  ) {
    throw new Error(
      "INVALID_MEDIA_TOKEN"
    );
  }

  const [
    body,
    signature,
  ] =
    parts;

  const expected =
    crypto
      .createHmac(
        "sha256",
        secret
      )
      .update(body)
      .digest(
        "base64url"
      );

  if (
    !timingSafeEqualText(
      signature,
      expected
    )
  ) {
    throw new Error(
      "INVALID_MEDIA_TOKEN"
    );
  }

  const payload =
    JSON.parse(
      Buffer
        .from(
          body,
          "base64url"
        )
        .toString(
          "utf8"
        )
    );

  if (
    payload.exp &&
    Number(payload.exp) <
      nowMs()
  ) {
    throw new Error(
      "EXPIRED_MEDIA_TOKEN"
    );
  }

  return payload;
}

function resolvedMediaTokenSecret() {
  if (MEDIA_TOKEN_SECRET) {
    return MEDIA_TOKEN_SECRET;
  }

  if (NODE_ENV !== "production") {
    return stableHash(serviceAccount.private_key).slice(0, 64);
  }

  throw new Error(
    "MEDIA_TOKEN_SECRET_REQUIRED_IN_PRODUCTION"
  );
}

function parseMultipartSingleFile(
  req
) {
  if (
    !Buffer.isBuffer(
      req.body
    )
  ) {
    throw new Error(
      "MULTIPART_BODY_REQUIRED"
    );
  }

  const contentType =
    safe(
      req.headers[
        "content-type"
      ]
    );

  const match =
    contentType.match(
      /boundary=(?:"([^"]+)"|([^;]+))/i
    );

  const boundaryText =
    safe(
      match?.[1] ||
        match?.[2]
    );

  if (!boundaryText) {
    throw new Error(
      "MULTIPART_BOUNDARY_REQUIRED"
    );
  }

  const delimiter =
    Buffer.from(
      `--${boundaryText}`
    );

  const endMarker =
    Buffer.from(
      `--${boundaryText}--`
    );

  const fields = {};

  let file = null;

  let cursor =
    req.body.indexOf(
      delimiter
    );

  while (
    cursor >= 0 &&
    cursor < req.body.length
  ) {
    cursor +=
      delimiter.length;

    if (
      req.body
        .slice(
          cursor,
          cursor + 2
        )
        .equals(
          Buffer.from("--")
        )
    ) {
      break;
    }

    if (
      req.body
        .slice(
          cursor,
          cursor + 2
        )
        .equals(
          Buffer.from("\r\n")
        )
    ) {
      cursor += 2;
    }

    const next =
      req.body.indexOf(
        delimiter,
        cursor
      );

    const terminal =
      req.body.indexOf(
        endMarker,
        cursor
      );

    let end =
      next >= 0
        ? next
        : terminal;

    if (end < 0) {
      break;
    }

    let part =
      req.body.slice(
        cursor,
        end
      );

    if (
      part
        .slice(-2)
        .equals(
          Buffer.from("\r\n")
        )
    ) {
      part =
        part.slice(
          0,
          -2
        );
    }

    const headerEnd =
      part.indexOf(
        Buffer.from(
          "\r\n\r\n"
        )
      );

    if (
      headerEnd < 0
    ) {
      cursor = next;
      continue;
    }

    const headerText =
      part
        .slice(
          0,
          headerEnd
        )
        .toString(
          "latin1"
        );

    const content =
      part.slice(
        headerEnd + 4
      );

    const disposition =
      headerText
        .match(
          /content-disposition:[^\r\n]+/i
        )?.[0] || "";

    const name =
      disposition
        .match(
          /name="([^"]+)"/i
        )?.[1] || "";

    const filename =
      disposition
        .match(
          /filename="([^"]*)"/i
        )?.[1] || "";

    const mimeType =
      headerText
        .match(
          /content-type:\s*([^\r\n]+)/i
        )?.[1]
        ?.trim() || "";

    if (filename) {
      if (
        name === "file" &&
        !file
      ) {
        file = {
          filename:
            filename.slice(
              0,
              180
            ),
          mimeType,
          bytes:
            content,
        };
      }
    } else if (name) {
      fields[name] =
        content
          .toString(
            "utf8"
          )
          .slice(
            0,
            10000
          );
    }

    cursor = next;
  }

  if (!file) {
    throw new Error(
      "MEDIA_FILE_REQUIRED"
    );
  }

  return {
    fields,
    file,
  };
}

function detectImageType(
  bytes
) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length < 12
  ) {
    return null;
  }

  if (
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff
  ) {
    return "jpeg";
  }

  if (
    bytes
      .slice(0, 8)
      .equals(
        Buffer.from([
          0x89,
          0x50,
          0x4e,
          0x47,
          0x0d,
          0x0a,
          0x1a,
          0x0a,
        ])
      )
  ) {
    return "png";
  }

  if (
    bytes
      .slice(
        0,
        4
      )
      .toString(
        "ascii"
      ) === "RIFF" &&
    bytes
      .slice(
        8,
        12
      )
      .toString(
        "ascii"
      ) === "WEBP"
  ) {
    return "webp";
  }

  if (
    bytes
      .slice(
        4,
        8
      )
      .toString(
        "ascii"
      ) === "ftyp"
  ) {
    const brand =
      bytes
        .slice(
          8,
          12
        )
        .toString(
          "ascii"
        )
        .toLowerCase();

    if (
      [
        "heic",
        "heix",
        "hevc",
        "hevx",
        "mif1",
        "msf1",
      ].includes(
        brand
      )
    ) {
      return "heic";
    }
  }

  return null;
}

async function processProductImage(
  bytes
) {
  if (!sharp) {
    const error =
      new Error(
        "MEDIA_PROCESSOR_NOT_INSTALLED"
      );

    error.statusCode =
      503;

    error.publicMessage =
      'O processador de imagens do servidor ainda não está instalado. Adicione o pacote "sharp".';

    throw error;
  }

  const image =
    sharp(
      bytes,
      {
        failOn:
          "error",
        limitInputPixels:
          80_000_000,
      }
    ).rotate();

  const metadata =
    await image.metadata();

  if (
    !metadata.width ||
    !metadata.height ||
    metadata.width < 240 ||
    metadata.height < 240
  ) {
    const error =
      new Error(
        "MEDIA_RESOLUTION_TOO_SMALL"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "A imagem precisa ter resolução maior.";

    throw error;
  }

  const detail =
    await sharp(
      bytes,
      {
        failOn:
          "error",
        limitInputPixels:
          80_000_000,
      }
    )
      .rotate()
      .resize(
        1080,
        1080,
        {
          fit:
            "cover",
          position:
            "attention",
        }
      )
      .webp({
        quality:
          84,
      })
      .toBuffer();

  const thumb =
    await sharp(
      bytes,
      {
        failOn:
          "error",
        limitInputPixels:
          80_000_000,
      }
    )
      .rotate()
      .resize(
        480,
        480,
        {
          fit:
            "cover",
          position:
            "attention",
        }
      )
      .webp({
        quality:
          80,
      })
      .toBuffer();

  return {
    detail,
    thumb,
  };
}

function cloudinaryUploadBuffer(bytes, options = {}) {
  if (!CLOUDINARY_CONFIGURED) {
    const error = new Error("CLOUDINARY_NOT_CONFIGURED");
    error.statusCode = 503;
    error.publicMessage = "O serviço de mídia ainda não está configurado.";
    throw error;
  }
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream({
      resource_type: "image",
      type: options.type || "authenticated",
      folder: options.folder || "firerank/private",
      public_id: options.publicId,
      overwrite: false,
      format: "webp",
    }, (error, result) => error ? reject(error) : resolve(result));
    stream.end(bytes);
  });
}

async function createMediaUploadSession(uid, fileBytes) {
  const mediaId = crypto.randomBytes(18).toString("hex");
  const processed = await processProductImage(fileBytes);
  const folder = `firerank/products/${uid}/${mediaId}`;
  const [detail, thumb] = await Promise.all([
    cloudinaryUploadBuffer(processed.detail, {folder, publicId: "detail", type: "authenticated"}),
    cloudinaryUploadBuffer(processed.thumb, {folder, publicId: "thumb", type: "authenticated"}),
  ]);
  const token = makeSignedToken({
    v: 2, type: "upload", uid, mediaId,
    detailPath: detail.public_id, thumbPath: thumb.public_id,
    detailVersion: detail.version, thumbVersion: thumb.version,
    provider: "cloudinary", exp: nowMs() + MEDIA_UPLOAD_TOKEN_TTL_MS,
  }, resolvedMediaTokenSecret());
  return { mediaId: token };
}

function verifyMediaUploadToken(
  token,
  uid
) {
  const payload =
    verifySignedToken(
      token,
      resolvedMediaTokenSecret()
    );

  if (
    payload.type !== "upload" ||
    payload.uid !== uid
  ) {
    throw new Error(
      "MEDIA_TOKEN_OWNER_MISMATCH"
    );
  }

  return payload;
}

function deliveryMediaUrl({
  uid,
  productId,
  path,
  scope,
  kind,
}) {
  const token =
    makeSignedToken(
      {
        v: 1,
        type:
          "delivery",
        uid,
        productId,
        path,
        scope,
        kind,
      },
      resolvedMediaTokenSecret()
    );

  return (
    `${APP_BASE_URL}/v1/media/${scope}/${token}`
  );
}

function parseOwnDeliveryUrl(
  url,
  uid,
  productId
) {
  const prefixPublic =
    `${APP_BASE_URL}/v1/media/public/`;

  const prefixPrivate =
    `${APP_BASE_URL}/v1/media/private/`;

  let token = "";

  if (
    safe(url).startsWith(
      prefixPublic
    )
  ) {
    token =
      safe(url).slice(
        prefixPublic.length
      );
  }

  if (
    safe(url).startsWith(
      prefixPrivate
    )
  ) {
    token =
      safe(url).slice(
        prefixPrivate.length
      );
  }

  if (!token) {
    return null;
  }

  const payload =
    verifySignedToken(
      token,
      resolvedMediaTokenSecret()
    );

  if (
    payload.type !==
      "delivery" ||
    payload.uid !== uid ||
    payload.productId !==
      productId ||
    !payload.path
  ) {
    return null;
  }

  return payload;
}

function rescopeExistingMediaUrl(
  url,
  uid,
  productId,
  scope
) {
  const own =
    parseOwnDeliveryUrl(
      url,
      uid,
      productId
    );

  if (!own) {
    if (
      scope === "private"
    ) {
      const error =
        new Error(
          "LEGACY_MEDIA_NOT_PRIVATE"
        );

      error.statusCode =
        409;

      error.publicMessage =
        "Para manter a conta privada, substitua as imagens antigas por novas imagens protegidas.";

      throw error;
    }

    return safe(url);
  }

  return deliveryMediaUrl({
    uid,
    productId,
    path:
      own.path,
    scope,
    kind:
      own.kind ||
      "detail",
  });
}

async function finalizeUploadedMedia(
  entries,
  uid,
  productId,
  scope
) {
  if (
    !Array.isArray(entries) ||
    entries.length < 1 ||
    entries.length >
      MAX_PRODUCT_IMAGES
  ) {
    const error =
      new Error(
        "INVALID_MEDIA_COUNT"
      );

    error.statusCode =
      422;

    error.publicMessage =
      `Selecione entre 1 e ${MAX_PRODUCT_IMAGES} imagens.`;

    throw error;
  }

  const ordered =
    [...entries].sort(
      (a, b) =>
        integer(a.order) -
        integer(b.order)
    );

  const result = [];

  for (
    let i = 0;
    i < ordered.length;
    i += 1
  ) {
    const payload =
      verifyMediaUploadToken(
        ordered[i].mediaId,
        uid
      );

    result.push({
      detailUrl:
        deliveryMediaUrl({
          uid,
          productId,
          path:
            payload.detailPath,
          scope,
          kind:
            "detail",
        }),

      thumbUrl:
        deliveryMediaUrl({
          uid,
          productId,
          path:
            payload.thumbPath,
          scope,
          kind:
            "thumb",
        }),
    });
  }

  return result;
}

async function canViewPrivateProduct(
  auth,
  product
) {
  if (!auth?.uid) {
    return false;
  }

  if (
    auth.admin === true ||
    product.ownerUid ===
      auth.uid
  ) {
    return true;
  }

  if (
    product.storeId
  ) {
    const memberSnap =
      await db
        .ref(
          `store_members/${product.storeId}/${auth.uid}`
        )
        .get();

    if (
      map(
        memberSnap.val()
      ).active === true
    ) {
      return true;
    }
  }

  const followSnap =
    await db
      .ref(
        `follow_edges/${product.ownerUid}/${auth.uid}`
      )
      .get();

  return (
    safe(
      map(
        followSnap.val()
      ).status
    ).toLowerCase() ===
    "approved"
  );
}

async function streamStoredMedia(
  req,
  res,
  scope
) {
  try {
    const payload =
      verifySignedToken(
        req.params.token,
        resolvedMediaTokenSecret()
      );

    if (
      payload.type !==
        "delivery" ||
      payload.scope !==
        scope ||
      !payload.path
    ) {
      return res
        .status(404)
        .end();
    }

    const productSnap =
      await db
        .ref(
          `products/${payload.productId}`
        )
        .get();

    if (
      !productSnap.exists()
    ) {
      return res
        .status(404)
        .end();
    }

    const product =
      map(
        productSnap.val()
      );

    if (
      product.ownerUid !==
      payload.uid
    ) {
      return res
        .status(404)
        .end();
    }

    if (
      scope === "public"
    ) {
      const accountVisibility =
        await getAccountVisibility(
          payload.uid
        );

      const allowed =
        accountVisibility ===
          "public" &&
        product.status ===
          "active" &&
        product.visibility ===
          "public" &&
        safe(
          product.moderation
            ?.status
        ) === "approved";

      if (!allowed) {
        return res
          .status(403)
          .end();
      }

      res.setHeader(
        "Cache-Control",
        "public, max-age=300, stale-while-revalidate=300"
      );
    } else {
      if (
        !(await canViewPrivateProduct(
          req.auth,
          product
        ))
      ) {
        return res
          .status(403)
          .end();
      }

      res.setHeader(
        "Cache-Control",
        "private, max-age=60"
      );
    }

    if (!CLOUDINARY_CONFIGURED) return res.status(503).end();
    const transform = safe(payload.kind) === "thumb"
      ? [{width:480,height:480,crop:"fill",gravity:"auto",quality:"auto",fetch_format:"auto"}]
      : [{width:1080,height:1080,crop:"fill",gravity:"auto",quality:"auto",fetch_format:"auto"}];
    const signedUrl = cloudinary.url(payload.path, {
      resource_type: "image", type: "authenticated", sign_url: true,
      secure: true, expires_at: Math.floor(Date.now() / 1000) + 120,
      transformation: transform,
    });
    return res.redirect(302, signedUrl);
  } catch (_) {
    return res
      .status(404)
      .end();
  }
}

function validateProductTitle(
  value
) {
  const title =
    safe(value);

  if (
    title.length < 3 ||
    title.length > 120
  ) {
    const error =
      new Error(
        "INVALID_PRODUCT_TITLE"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "O título deve ter entre 3 e 120 caracteres.";

    throw error;
  }

  return title;
}

function validateProductDescription(
  value
) {
  const description =
    safe(value);

  if (
    description.length < 10 ||
    description.length > 5000
  ) {
    const error =
      new Error(
        "INVALID_PRODUCT_DESCRIPTION"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "A descrição deve ter entre 10 e 5000 caracteres.";

    throw error;
  }

  return description;
}

function validatePriceCents(
  value
) {
  const priceCents =
    integer(
      value,
      -1
    );

  if (
    priceCents <= 0 ||
    priceCents >
      1_000_000_000
  ) {
    const error =
      new Error(
        "INVALID_PRICE_CENTS"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Preço inválido.";

    throw error;
  }

  return priceCents;
}

async function validateCategory(
  categoryId,
  productType
) {
  const id =
    safe(
      categoryId
    );

  if (
    !id ||
    id.length > 80
  ) {
    const error =
      new Error(
        "CATEGORY_REQUIRED"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Selecione uma categoria válida.";

    throw error;
  }

  const snap =
    await db
      .ref(
        `categories/${id}`
      )
      .get();

  const category =
    map(
      snap.val()
    );

  if (
    !snap.exists() ||
    category.active !== true
  ) {
    const error =
      new Error(
        "CATEGORY_NOT_AVAILABLE"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Esta categoria não está disponível.";

    throw error;
  }

  const type =
    safe(
      category.type
    ).toLowerCase();

  if (
    productType === "local" &&
    (
      category.affiliateOnly ===
        true ||
      type === "affiliate"
    )
  ) {
    const error =
      new Error(
        "CATEGORY_NOT_LOCAL"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Esta categoria não aceita produtos locais.";

    throw error;
  }

  if (
    productType ===
      "affiliate" &&
    (
      category.localOnly ===
        true ||
      type === "local"
    )
  ) {
    const error =
      new Error(
        "CATEGORY_NOT_AFFILIATE"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Esta categoria não aceita produtos afiliados.";

    throw error;
  }

  return {
    id,
    title:
      clip(
        category.title ||
          id,
        100
      ),
    category,
  };
}

async function getStoreContext(
  storeId
) {
  const [
    storeSnap,
    settingsSnap,
  ] =
    await Promise.all([
      db
        .ref(
          `stores/${storeId}`
        )
        .get(),

      db
        .ref(
          `store_settings/${storeId}`
        )
        .get(),
    ]);

  if (
    !storeSnap.exists()
  ) {
    const error =
      new Error(
        "STORE_NOT_FOUND"
      );

    error.statusCode =
      404;

    error.publicMessage =
      "Loja não encontrada.";

    throw error;
  }

  return {
    store:
      map(
        storeSnap.val()
      ),
    settings:
      map(
        settingsSnap.val()
      ),
  };
}

function validateStoreFeature(
  settings,
  productType
) {
  if (
    productType ===
      "affiliate" &&
    settings
      .affiliateProductsEnabled ===
      false
  ) {
    const error =
      new Error(
        "AFFILIATE_PRODUCTS_DISABLED_FOR_STORE"
      );

    error.statusCode =
      409;

    error.publicMessage =
      "Produtos afiliados estão desativados nesta loja.";

    throw error;
  }

  if (
    productType ===
      "local" &&
    settings
      .localOrdersEnabled ===
      false
  ) {
    const error =
      new Error(
        "LOCAL_PRODUCTS_DISABLED_FOR_STORE"
      );

    error.statusCode =
      409;

    error.publicMessage =
      "Produtos locais estão desativados nesta loja.";

    throw error;
  }
}

function accountAndStoreCanBePublic(
  accountVisibility,
  store
) {
  return (
    accountVisibility ===
      "public" &&
    safe(
      store.status
    ).toLowerCase() ===
      "approved" &&
    safe(
      store.visibility
    ).toLowerCase() ===
      "public"
  );
}

const blockedAffiliateShorteners =
  new Set([
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "is.gd",
    "cutt.ly",
    "encurtador.com.br",
  ]);

function affiliateAllowedHosts() {
  return String(
    process.env
      .AFFILIATE_ALLOWED_HOSTS ||
      ""
  )
    .split(",")
    .map(
      (item) =>
        item
          .trim()
          .toLowerCase()
          .replace(
            /^www\./,
            ""
          )
    )
    .filter(Boolean);
}

function validateAffiliateUrl(
  value
) {
  let url;

  try {
    url =
      new URL(
        safe(value)
      );
  } catch (_) {
    const error =
      new Error(
        "INVALID_AFFILIATE_URL"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Informe um link afiliado HTTPS válido.";

    throw error;
  }

  if (
    url.protocol !==
    "https:"
  ) {
    const error =
      new Error(
        "AFFILIATE_HTTPS_REQUIRED"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "O link afiliado precisa usar HTTPS.";

    throw error;
  }

  const host =
    url.hostname
      .toLowerCase()
      .replace(
        /^www\./,
        ""
      );

  if (
    blockedAffiliateShorteners
      .has(host)
  ) {
    const error =
      new Error(
        "AFFILIATE_SHORTENER_BLOCKED"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Links encurtados não são aceitos.";

    throw error;
  }

  const allowlist =
    affiliateAllowedHosts();

  if (
    allowlist.length > 0 &&
    !allowlist.some(
      (allowed) =>
        host === allowed ||
        host.endsWith(
          `.${allowed}`
        )
    )
  ) {
    const error =
      new Error(
        "AFFILIATE_HOST_NOT_ALLOWED"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Este domínio afiliado ainda não está autorizado.";

    throw error;
  }

  let externalStoreName =
    host.split(".")[0] ||
    host;

  if (
    host.includes(
      "shopee"
    )
  ) {
    externalStoreName =
      "Shopee";
  }

  if (
    host.includes(
      "amazon"
    )
  ) {
    externalStoreName =
      "Amazon";
  }

  if (
    host.includes(
      "mercadolivre"
    ) ||
    host.includes(
      "mercadolibre"
    )
  ) {
    externalStoreName =
      "Mercado Livre";
  }

  return {
    url:
      url.toString(),
    domain:
      host,
    externalStoreName,
    sourceStore:
      normalizeSearchTerm(
        externalStoreName
      ) || host,
  };
}

function normalizePaymentMethods(
  value
) {
  const allowed =
    new Set([
      "pix_on_delivery",
      "cash_on_delivery",
      "card_machine",
      "pay_on_pickup",
      "combine_in_chat",
    ]);

  const output = {};

  if (
    Array.isArray(value)
  ) {
    for (
      const item
      of value
    ) {
      const key =
        safe(item);

      if (
        allowed.has(key)
      ) {
        output[key] =
          true;
      }
    }
  } else if (
    isObject(value)
  ) {
    for (
      const [
        key,
        enabled,
      ]
      of Object.entries(
        value
      )
    ) {
      if (
        allowed.has(key) &&
        enabled === true
      ) {
        output[key] =
          true;
      }
    }
  }

  if (
    Object.keys(output)
      .length === 0
  ) {
    const error =
      new Error(
        "LOCAL_PAYMENT_METHOD_REQUIRED"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Selecione uma forma de pagamento local.";

    throw error;
  }

  return output;
}

async function resolveLocalAddress(
  uid,
  addressId
) {
  const id =
    safe(
      addressId ||
        "primary"
    ).toLowerCase();

  if (
    ![
      "primary",
      "shipping",
    ].includes(id)
  ) {
    const error =
      new Error(
        "INVALID_ADDRESS_ID"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Endereço inválido.";

    throw error;
  }

  const snap =
    await db
      .ref(
        `user_addresses/${uid}/${id}`
      )
      .get();

  const address =
    map(
      snap.val()
    );

  if (
    !snap.exists() ||
    address.usableForOrder !==
      true ||
    address.needsReview ===
      true
  ) {
    const error =
      new Error(
        "ADDRESS_NOT_USABLE_FOR_ORDER"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Salve e valide um endereço antes de publicar um produto local.";

    throw error;
  }

  if (
    !safe(
      address.city
    ) ||
    !safe(
      address.state
    ) ||
    !safe(
      address.neighborhood
    )
  ) {
    const error =
      new Error(
        "ADDRESS_REGION_INCOMPLETE"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Complete cidade, estado e bairro do endereço.";

    throw error;
  }

  return {
    id,
    address,
  };
}

function validateLocalConfig(
  rawLocal,
  rawInventory
) {
  const local =
    map(rawLocal);

  const inventory =
    map(rawInventory);

  const localType =
    safe(
      local.localType
    ).toLowerCase();

  const allowedLocalTypes =
    new Set([
      "food",
      "custom_order",
      "physical_product",
      "clothing",
      "service",
      "other",
    ]);

  if (
    !allowedLocalTypes.has(
      localType
    )
  ) {
    const error =
      new Error(
        "INVALID_LOCAL_TYPE"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Tipo de produto local inválido.";

    throw error;
  }

  const deliveryAvailable =
    local.deliveryAvailable ===
    true;

  const pickupAvailable =
    local.pickupAvailable ===
    true;

  if (
    !deliveryAvailable &&
    !pickupAvailable
  ) {
    const error =
      new Error(
        "LOCAL_FULFILLMENT_REQUIRED"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Ative entrega, retirada ou as duas opções.";

    throw error;
  }

  const serviceRadiusKm =
    deliveryAvailable
      ? finiteNumber(
          local.serviceRadiusKm,
          -1
        )
      : 0;

  const deliveryFeeCents =
    deliveryAvailable
      ? integer(
          local.deliveryFeeCents,
          -1
        )
      : 0;

  const preparationTimeMin =
    integer(
      local.preparationTimeMin,
      0
    );

  if (
    deliveryAvailable &&
    (
      serviceRadiusKm <= 0 ||
      serviceRadiusKm > 300
    )
  ) {
    const error =
      new Error(
        "INVALID_SERVICE_RADIUS"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Raio de entrega inválido.";

    throw error;
  }

  if (
    deliveryFeeCents < 0 ||
    deliveryFeeCents >
      10_000_000
  ) {
    const error =
      new Error(
        "INVALID_DELIVERY_FEE"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Taxa de entrega inválida.";

    throw error;
  }

  if (
    preparationTimeMin < 0 ||
    preparationTimeMin > 43_200
  ) {
    const error =
      new Error(
        "INVALID_PREPARATION_TIME"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Tempo de preparo inválido.";

    throw error;
  }

  if (
    local
      .acceptedLocalSafetyNotice !==
      true
  ) {
    const error =
      new Error(
        "LOCAL_SAFETY_NOTICE_REQUIRED"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Confirme as regras da venda local.";

    throw error;
  }

  const usesStock =
    inventory.usesStock ===
    true;

  let initialQuantity =
    0;

  if (usesStock) {
    initialQuantity =
      integer(
        inventory.initialQuantity,
        -1
      );

    if (
      initialQuantity < 1 ||
      initialQuantity >
        10_000_000
    ) {
      const error =
        new Error(
          "INVALID_INITIAL_STOCK"
        );

      error.statusCode =
        422;

      error.publicMessage =
        "Estoque inicial inválido.";

      throw error;
    }
  }

  return {
    localType,
    orderType:
      clip(
        local.orderType ||
          "quick",
        40
      ),
    addressId:
      clip(
        local.sellerAddressKey ||
          "primary",
        40
      ),
    deliveryAvailable,
    pickupAvailable,
    sellerOwnDelivery:
      local.sellerOwnDelivery ===
      true,
    serviceRadiusKm,
    deliveryFeeCents,
    preparationTimeMin,
    paymentMethods:
      normalizePaymentMethods(
        local.paymentMethods
      ),
    usesStock,
    initialQuantity,
  };
}
function validateVariationDefinitions(
  raw
) {
  if (
    !Array.isArray(raw) ||
    raw.length === 0
  ) {
    return [];
  }

  if (
    raw.length > 12
  ) {
    const error =
      new Error(
        "TOO_MANY_VARIATION_GROUPS"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Há variações demais neste produto.";

    throw error;
  }

  let totalOptions =
    0;

  const definitions =
    [];

  for (
    const item
    of raw
  ) {
    const name =
      clip(
        item?.name,
        60
      );

    const options =
      Array.isArray(
        item?.options
      )
        ? [
            ...new Set(
              item.options
                .map(
                  (x) =>
                    clip(
                      x,
                      80
                    )
                )
                .filter(
                  Boolean
                )
            ),
          ]
        : [];

    if (
      !name ||
      options.length === 0 ||
      options.length > 20
    ) {
      const error =
        new Error(
          "INVALID_VARIATION_DEFINITION"
        );

      error.statusCode =
        422;

      error.publicMessage =
        "Revise as variações do produto.";

      throw error;
    }

    totalOptions +=
      options.length;

    if (
      totalOptions > 60
    ) {
      const error =
        new Error(
          "TOO_MANY_VARIATION_OPTIONS"
        );

      error.statusCode =
        422;

      error.publicMessage =
        "Há opções de variação demais.";

      throw error;
    }

    definitions.push({
      name,
      options,
    });
  }

  return definitions;
}

function cartesianVariantAttributes(
  definitions
) {
  if (
    definitions.length === 0
  ) {
    return [{}];
  }

  let combinations =
    [{}];

  for (
    const definition
    of definitions
  ) {
    const next = [];

    for (
      const current
      of combinations
    ) {
      for (
        const option
        of definition.options
      ) {
        next.push({
          ...current,
          [definition.name]:
            option,
        });

        if (
          next.length >
          MAX_VARIANT_COMBINATIONS
        ) {
          const error =
            new Error(
              "TOO_MANY_VARIANT_COMBINATIONS"
            );

          error.statusCode =
            422;

          error.publicMessage =
            "As variações geram combinações demais. Reduza as opções.";

          throw error;
        }
      }
    }

    combinations =
      next;
  }

  return combinations;
}

function buildVariantsAndInventory({
  productId,
  definitions,
  priceCents,
  usesStock,
  initialQuantity,
  t,
}) {
  const variants = {};
  const inventory = {};

  const combinations =
    cartesianVariantAttributes(
      definitions
    );

  const sharedSkuId =
    `${productId}__shared`;

  combinations.forEach(
    (
      attributes,
      index
    ) => {
      const variantId =
        combinations.length === 1 &&
        definitions.length === 0
          ? "default"
          : `v_${String(
              index + 1
            ).padStart(
              3,
              "0"
            )}`;

      const name =
        Object.values(
          attributes
        ).join(" / ") ||
        "Padrão";

      variants[variantId] = {
        variantId,
        skuId:
          sharedSkuId,
        name:
          clip(
            name,
            160
          ),
        attributes,
        priceCents,
        status:
          "active",
        createdAtMs:
          t,
        updatedAtMs:
          t,
      };
    }
  );

  if (usesStock) {
    inventory[sharedSkuId] = {
      skuId:
        sharedSkuId,
      productId,
      stockMode:
        "shared_across_variants",
      availableQuantity:
        initialQuantity,
      reservedQuantity:
        0,
      status:
        initialQuantity > 0
          ? "in_stock"
          : "out_of_stock",
      updatedAtMs:
        t,
    };
  }

  return {
    variants,
    inventory,
  };
}

function initialProductStats(
  t
) {
  return {
    boostClickCount:
      0,
    boostViewCount:
      0,
    chatStartCount:
      0,
    clickCount:
      0,
    commentCount:
      0,
    favoriteCount:
      0,
    likeCount:
      0,
    orderStartCount:
      0,
    uniqueViewsEstimate:
      0,
    viewsCount:
      0,
    updatedAtMs:
      t,
  };
}

function publicProductCard(
  product,
  coverThumbUrl,
  t,
  oldCard = {}
) {
  return {
    productId:
      product.productId,

    storeId:
      product.storeId,

    ownerUid:
      product.ownerUid,

    title:
      product.title,

    coverUrl:
      coverThumbUrl,

    priceCents:
      integer(
        product.pricing
          ?.priceCents
      ),

    currency:
      "BRL",

    categoryId:
      product.categoryId,

    productType:
      product.productType,

    ratingAverage:
      finiteNumber(
        oldCard.ratingAverage,
        0
      ),

    ratingCount:
      integer(
        oldCard.ratingCount,
        0
      ),

    city:
      clip(
        product.local
          ?.city || "",
        100
      ),

    state:
      clip(
        product.local
          ?.state || "",
        64
      ),

    createdAtMs:
      integer(
        product.lifecycle
          ?.createdAtMs,
        t
      ),

    updatedAtMs:
      t,

    rankScore:
      finiteNumber(
        oldCard.rankScore,
        0
      ),
  };
}

function addProjectionRemovals(
  updates,
  product,
  oldSearchTerms = []
) {
  const productId =
    safe(
      product.productId
    );

  if (!productId) {
    return;
  }

  updates[
    `product_cards/${productId}`
  ] =
    null;

  updates[
    `feed_index/${productId}`
  ] =
    null;

  updates[
    `active_boost_cards/${productId}`
  ] =
    null;

  if (
    product.categoryId
  ) {
    updates[
      `category_index/${firebaseSafeKey(
        product.categoryId
      )}/${productId}`
    ] =
      null;
  }

  for (
    const term
    of oldSearchTerms
  ) {
    if (term) {
      updates[
        `search_index_basic/${firebaseSafeKey(
          term
        )}/${productId}`
      ] =
        null;
    }
  }

  if (
    product.storeId
  ) {
    updates[
      `store_products/${product.storeId}/${productId}`
    ] =
      null;
  }
}

function addPublicProjections(
  updates,
  product,
  card,
  searchTerms,
  t
) {
  const productId =
    product.productId;

  updates[
    `product_cards/${productId}`
  ] =
    card;

  updates[
    `feed_index/${productId}`
  ] = {
    productId,
    createdAtMs:
      product.lifecycle
        .createdAtMs,
    score:
      finiteNumber(
        card.rankScore,
        0
      ),
  };

  updates[
    `category_index/${firebaseSafeKey(
      product.categoryId
    )}/${productId}`
  ] = {
    productId,
    createdAtMs:
      product.lifecycle
        .createdAtMs,
    score:
      finiteNumber(
        card.rankScore,
        0
      ),
  };

  updates[
    `store_products/${product.storeId}/${productId}`
  ] = {
    productId,
    createdAtMs:
      product.lifecycle
        .createdAtMs,
    status:
      "active",
  };

  for (
    const term
    of searchTerms
  ) {
    updates[
      `search_index_basic/${firebaseSafeKey(
        term
      )}/${productId}`
    ] = {
      productId,
      score:
        finiteNumber(
          card.rankScore,
          0
        ),
      createdAtMs:
        product.lifecycle
          .createdAtMs,
    };
  }

  updates[
    `product_cards/${productId}/updatedAtMs`
  ] =
    t;
}

async function mediaForNewProduct(
  bodyMedia,
  uid,
  productId,
  scope
) {
  const finalized =
    await finalizeUploadedMedia(
      bodyMedia,
      uid,
      productId,
      scope
    );

  return {
    detailUrls:
      finalized.map(
        (item) =>
          item.detailUrl
      ),

    thumbUrls:
      finalized.map(
        (item) =>
          item.thumbUrl
      ),
  };
}

async function mediaForProductUpdate(
  rawImages,
  existingProduct,
  uid,
  productId,
  scope
) {
  if (
    !Array.isArray(
      rawImages
    ) ||
    rawImages.length < 1 ||
    rawImages.length >
      MAX_PRODUCT_IMAGES
  ) {
    const error =
      new Error(
        "INVALID_MEDIA_COUNT"
      );

    error.statusCode =
      422;

    error.publicMessage =
      `Selecione entre 1 e ${MAX_PRODUCT_IMAGES} imagens.`;

    throw error;
  }

  const existingUrls =
    new Set(
      Array.isArray(
        existingProduct.media
          ?.images
      )
        ? existingProduct
            .media
            .images
            .map(safe)
        : []
    );

  if (
    existingProduct.media
      ?.coverUrl
  ) {
    existingUrls.add(
      safe(
        existingProduct.media
          .coverUrl
      )
    );
  }

  const ordered =
    [...rawImages].sort(
      (a, b) =>
        integer(a.order) -
        integer(b.order)
    );

  const detailUrls =
    [];

  const thumbUrls =
    [];

  for (
    const item
    of ordered
  ) {
    const kind =
      safe(
        item.kind
      ).toLowerCase();

    if (
      kind === "existing"
    ) {
      const url =
        safe(
          item.url
        );

      if (
        !url ||
        !existingUrls.has(url)
      ) {
        const error =
          new Error(
            "FOREIGN_EXISTING_MEDIA"
          );

        error.statusCode =
          403;

        error.publicMessage =
          "Uma imagem existente não pertence a este produto.";

        throw error;
      }

      const rescoped =
        rescopeExistingMediaUrl(
          url,
          uid,
          productId,
          scope
        );

      detailUrls.push(
        rescoped
      );

      const own =
        parseOwnDeliveryUrl(
          rescoped,
          uid,
          productId
        );

      thumbUrls.push(
        own
          ? deliveryMediaUrl({
              uid,
              productId,
              path:
                own.path.replace(
                  /detail\.webp$/,
                  "thumb.webp"
                ),
              scope,
              kind:
                "thumb",
            })
          : rescoped
      );

      continue;
    }

    if (
      kind === "uploaded"
    ) {
      const payload =
        verifyMediaUploadToken(
          item.mediaId,
          uid
        );

      detailUrls.push(
        deliveryMediaUrl({
          uid,
          productId,
          path:
            payload.detailPath,
          scope,
          kind:
            "detail",
        })
      );

      thumbUrls.push(
        deliveryMediaUrl({
          uid,
          productId,
          path:
            payload.thumbPath,
          scope,
          kind:
            "thumb",
        })
      );

      continue;
    }

    const error =
      new Error(
        "INVALID_MEDIA_KIND"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Formato de imagem inválido.";

    throw error;
  }

  return {
    detailUrls,
    thumbUrls,
  };
}

function publicError(
  res,
  error,
  fallback =
    "Não foi possível concluir a operação."
) {
  if (
    NODE_ENV !==
    "production"
  ) {
    console.error(
      error
    );
  } else {
    console.error(
      error?.message ||
        fallback
    );
  }

  return res
    .status(
      error.statusCode ||
        500
    )
    .json({
      ok: false,
      code:
        safe(
          error.message ||
            "SERVER_ERROR"
        ).slice(
          0,
          100
        ),
      message:
        error.publicMessage ||
        fallback,
    });
}

app.get(
  "/v1/media/public/:token",
  async (
    req,
    res
  ) => {
    return streamStoredMedia(
      req,
      res,
      "public"
    );
  }
);

app.get(
  "/v1/media/private/:token",
  requireUser,
  async (
    req,
    res
  ) => {
    return streamStoredMedia(
      req,
      res,
      "private"
    );
  }
);

app.post(
  "/v1/media/sign",
  requireUser,
  rateLimit("media-sign", 30, 10 * 60 * 1000),
  async (req, res) => {
    try {
      if (!CLOUDINARY_CONFIGURED || !CLOUDINARY_API_SECRET) {
        return res.status(503).json({
          ok: false,
          code: "CLOUDINARY_NOT_CONFIGURED",
          message: "O serviço de mídia ainda não está configurado.",
        });
      }

      const uid = req.auth.uid;
      const purpose = safe(req.body?.purpose).toLowerCase();
      const allowed = new Set([
        "product_image",
        "seller_identity",
        "delivery_identity",
        "profile_image",
      ]);

      if (!allowed.has(purpose)) {
        return res.status(422).json({
          ok: false,
          code: "INVALID_MEDIA_PURPOSE",
          message: "Finalidade de mídia inválida.",
        });
      }

      if (purpose === "product_image") {
        await assertSellerCanPublish(uid);
      }

      const timestamp = Math.floor(Date.now() / 1000);
      const nonce = crypto.randomBytes(10).toString("hex");
      const privateIdentity = purpose === "seller_identity" || purpose === "delivery_identity";
      const folder = privateIdentity
        ? `firerank/private/identity/${uid}/${purpose}`
        : purpose === "profile_image"
          ? `firerank/profiles/${uid}`
          : `firerank/products/${uid}`;
      const publicId = `${purpose}_${timestamp}_${nonce}`;
      const type = purpose === "profile_image" ? "upload" : "authenticated";
      const paramsToSign = {
        timestamp,
        folder,
        public_id: publicId,
        type,
      };
      const signature = cloudinary.utils.api_sign_request(
        paramsToSign,
        CLOUDINARY_API_SECRET
      );

      return res.json({
        ok: true,
        provider: "cloudinary",
        cloudName: CLOUDINARY_CLOUD_NAME,
        apiKey: CLOUDINARY_API_KEY,
        timestamp,
        signature,
        folder,
        publicId,
        type,
        resourceType: "image",
        uploadUrl: `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/image/upload`,
        expiresInSeconds: 300,
      });
    } catch (error) {
      return publicError(res, error, "Não foi possível autorizar o upload.");
    }
  }
);

app.post(
  "/v1/media/complete",
  requireUser,
  rateLimit("media-complete", 40, 10 * 60 * 1000),
  async (req, res) => {
    try {
      if (!CLOUDINARY_CONFIGURED || !CLOUDINARY_API_SECRET) {
        return res.status(503).json({ok:false,code:"CLOUDINARY_NOT_CONFIGURED",message:"O serviço de mídia ainda não está configurado."});
      }
      const uid=req.auth.uid;
      const purpose=safe(req.body?.purpose).toLowerCase();
      const publicId=safe(req.body?.publicId);
      const requestedType=safe(req.body?.type).toLowerCase();
      const allowed=new Set(["product_image","seller_identity","delivery_identity","profile_image"]);
      if(!allowed.has(purpose)||!publicId)return res.status(422).json({ok:false,code:"INVALID_MEDIA_COMPLETE"});
      if(purpose==="product_image")await assertSellerCanPublish(uid);
      const expectedPrefix=purpose==="seller_identity"||purpose==="delivery_identity"
        ?`firerank/private/identity/${uid}/${purpose}/`
        :purpose==="profile_image"?`firerank/profiles/${uid}/`:`firerank/products/${uid}/`;
      if(!publicId.startsWith(expectedPrefix))return res.status(403).json({ok:false,code:"MEDIA_OWNER_MISMATCH"});
      const expectedType=purpose==="profile_image"?"upload":"authenticated";
      if(requestedType&&requestedType!==expectedType)return res.status(422).json({ok:false,code:"MEDIA_TYPE_MISMATCH"});
      const resource=await cloudinary.api.resource(publicId,{resource_type:"image",type:expectedType});
      const bytes=integer(resource?.bytes,0);
      if(!resource?.public_id||bytes<=0||bytes>15*1024*1024)return res.status(422).json({ok:false,code:"MEDIA_RESOURCE_INVALID"});
      const t=nowMs();
      const mediaAssetRef=db.ref(`media_assets/${uid}`).push();
      const assetId=mediaAssetRef.key;
      const asset={assetId,ownerUid:uid,purpose,provider:"cloudinary",publicId:resource.public_id,resourceType:"image",type:expectedType,version:resource.version||0,bytes,format:safe(resource.format),width:integer(resource.width,0),height:integer(resource.height,0),createdAtMs:t,status:"ready"};
      await mediaAssetRef.set(asset);
      if(purpose==="product_image"){
        const mediaId=makeSignedToken({v:3,type:"upload",uid,mediaId:assetId,detailPath:resource.public_id,thumbPath:resource.public_id,detailVersion:resource.version,thumbVersion:resource.version,provider:"cloudinary",exp:t+MEDIA_UPLOAD_TOKEN_TTL_MS},resolvedMediaTokenSecret());
        return res.status(201).json({ok:true,mediaId,assetId});
      }
      const secureUrl=purpose==="profile_image"?safe(resource.secure_url):"";
      return res.status(201).json({ok:true,mediaId:assetId,assetId,publicId:resource.public_id,type:expectedType,secureUrl});
    }catch(error){return publicError(res,error,"Não foi possível confirmar a mídia.");}
  }
);

app.post(
  "/v1/media/product",
  requireUser,
  rateLimit(
    "media",
    20,
    10 * 60 * 1000
  ),
  express.raw({
    type:
      "multipart/form-data",
    limit:
      "14mb",
  }),
  async (
    req,
    res
  ) => {
    try {
      const uid =
        req.auth.uid;

      await assertSellerCanPublish(
        uid
      );

      const {
        fields,
        file,
      } =
        parseMultipartSingleFile(
          req
        );

      if (
        file.bytes.length <= 0 ||
        file.bytes.length >
          MAX_MEDIA_BYTES
      ) {
        return res
          .status(413)
          .json({
            ok: false,
            code:
              "MEDIA_TOO_LARGE",
            message:
              "A imagem ultrapassa o limite permitido.",
          });
      }

      if (
        !detectImageType(
          file.bytes
        )
      ) {
        return res
          .status(415)
          .json({
            ok: false,
            code:
              "UNSUPPORTED_MEDIA_TYPE",
            message:
              "Formato de imagem não aceito.",
          });
      }

      const productId =
        safe(
          fields.productId
        );

      if (productId) {
        const productSnap =
          await db
            .ref(
              `products/${productId}`
            )
            .get();

        const product =
          map(
            productSnap.val()
          );

        if (
          !productSnap.exists()
        ) {
          return res
            .status(404)
            .json({
              ok: false,
              code:
                "PRODUCT_NOT_FOUND",
            });
        }

        if (
          product.ownerUid !==
          uid
        ) {
          return res
            .status(403)
            .json({
              ok: false,
              code:
                "PRODUCT_OWNER_REQUIRED",
            });
        }
      }

      const session =
        await createMediaUploadSession(
          uid,
          file.bytes
        );

      return res
        .status(201)
        .json({
          ok: true,
          mediaId:
            session.mediaId,
          data: {
            mediaId:
              session.mediaId,
          },
        });
    } catch (error) {
      return publicError(
        res,
        error,
        "Não foi possível processar a imagem."
      );
    }
  }
);

app.post(
  "/v1/products",
  requireUser,
  rateLimit(
    "product-create",
    12,
    10 * 60 * 1000
  ),
  async (
    req,
    res
  ) => {
    try {
      const uid =
        req.auth.uid;

      await assertSellerCanPublish(
        uid
      );

      const body =
        map(
          req.body
        );

      const productType =
        safe(
          body.productType
        ).toLowerCase();

      if (
        ![
          "affiliate",
          "local",
        ].includes(
          productType
        )
      ) {
        const error =
          new Error(
            "INVALID_PRODUCT_TYPE"
          );

        error.statusCode =
          422;

        error.publicMessage =
          "Tipo de produto inválido.";

        throw error;
      }

      const flagName =
        productType ===
        "local"
          ? "localOrders"
          : "affiliateProducts";

      if (
        !(await getFeatureFlag(
          flagName,
          true
        ))
      ) {
        const error =
          new Error(
            "PRODUCT_TYPE_DISABLED"
          );

        error.statusCode =
          409;

        error.publicMessage =
          "Este tipo de produto está temporariamente desativado.";

        throw error;
      }

      const title =
        validateProductTitle(
          body.title
        );

      const description =
        validateProductDescription(
          body.description
        );

      const priceCents =
        validatePriceCents(
          body.priceCents
        );

      const category =
        await validateCategory(
          body.categoryId,
          productType
        );

      const storeId =
        await resolveStoreForUser(
          uid,
          body.storeId
        );

      const {
        store,
        settings,
      } =
        await getStoreContext(
          storeId
        );

      validateStoreFeature(
        settings,
        productType
      );

      const accountVisibility =
        await getAccountVisibility(
          uid
        );

      const publicEligible =
        accountAndStoreCanBePublic(
          accountVisibility,
          store
        );

      const visibility =
        publicEligible
          ? "public"
          : "private";

      const mediaScope =
        publicEligible
          ? "public"
          : "private";

      const t =
        nowMs();

      const productId =
        db
          .ref(
            "products"
          )
          .push()
          .key;

      if (!productId) {
        throw new Error(
          "PRODUCT_ID_GENERATION_FAILED"
        );
      }

      const media =
        await mediaForNewProduct(
          body.media,
          uid,
          productId,
          mediaScope
        );

      const product = {
        productId,
        storeId,
        ownerUid:
          uid,
        productType,
        status:
          "active",
        visibility,

        moderation: {
          status:
            "approved",
          reportCount:
            0,
          source:
            "backend_validation",
        },

        title,
        description,
        categoryId:
          category.id,

        pricing: {
          currency:
            "BRL",
          priceCents,
        },

        media: {
          coverUrl:
            media.detailUrls[0],
          images:
            media.detailUrls,
        },

        commerce: {
          purchaseMode:
            productType ===
            "affiliate"
              ? "affiliate_redirect"
              : "local_order",

          allowChat:
            settings.chatEnabled !==
            false,

          stockManagedByFireRank:
            false,
        },

        lifecycle: {
          createdAtMs:
            t,
          updatedAtMs:
            t,
          deletedAtMs:
            0,
        },
      };

      let variants = {};
      let inventory = {};

      if (
        productType ===
        "affiliate"
      ) {
        const affiliate =
          validateAffiliateUrl(
            body.affiliate
              ?.url
          );

        product.affiliate = {
          ...affiliate,
          validatedAtMs:
            t,
          serverRevalidationRequired:
            true,
        };
      } else {
        const localConfig =
          validateLocalConfig(
            body.local,
            body.inventory
          );

        const {
          id: addressId,
          address,
        } =
          await resolveLocalAddress(
            uid,
            localConfig.addressId
          );

        const definitions =
          validateVariationDefinitions(
            body.variations
          );

        const built =
          buildVariantsAndInventory({
            productId,
            definitions,
            priceCents,
            usesStock:
              localConfig.usesStock,
            initialQuantity:
              localConfig.initialQuantity,
            t,
          });

        variants =
          built.variants;

        inventory =
          built.inventory;

        product.commerce
          .stockManagedByFireRank =
          localConfig.usesStock;

        product.local = {
          localType:
            localConfig.localType,

          orderType:
            localConfig.orderType,

          addressId,

          city:
            clip(
              address.city,
              100
            ),

          state:
            clip(
              address.state,
              64
            ),

          neighborhood:
            clip(
              address.neighborhood,
              120
            ),

          locationPrivacy:
            "approximate_only_public",

          deliveryAvailable:
            localConfig
              .deliveryAvailable,

          pickupAvailable:
            localConfig
              .pickupAvailable,

          sellerOwnDelivery:
            localConfig
              .sellerOwnDelivery,

          serviceRadiusKm:
            localConfig
              .serviceRadiusKm,

          preparationTimeMin:
            localConfig
              .preparationTimeMin,

          deliveryFeeCents:
            localConfig
              .deliveryFeeCents,

          paymentMethods:
            localConfig
              .paymentMethods,

          variationDefinitions:
            definitions,
        };
      }

      const updates = {
        [`products/${productId}`]:
          product,

        [`product_stats/${productId}`]:
          initialProductStats(
            t
          ),
      };

      for (
        const [
          variantId,
          variant,
        ]
        of Object.entries(
          variants
        )
      ) {
        updates[
          `product_variants/${productId}/${variantId}`
        ] =
          variant;
      }

      for (
        const [
          skuId,
          stock,
        ]
        of Object.entries(
          inventory
        )
      ) {
        updates[
          `inventory/${skuId}`
        ] =
          stock;
      }

      if (
        publicEligible
      ) {
        const card =
          publicProductCard(
            product,
            media.thumbUrls[0],
            t
          );

        addPublicProjections(
          updates,
          product,
          card,
          searchTermsForProduct(
            title,
            category.id
          ),
          t
        );
      }

      await db
        .ref()
        .update(
          updates
        );

      await appendAudit(
        "product_created",
        {
          actorUid:
            uid,
          targetUid:
            uid,
          referenceId:
            productId,
        }
      );

      return res
        .status(201)
        .json({
          ok: true,
          productId,
          visibility,
          publicProjected:
            publicEligible,
        });
    } catch (error) {
      return publicError(
        res,
        error,
        "Não foi possível publicar o produto."
      );
    }
  }
);
app.post(
  "/v1/products/update",
  requireUser,
  rateLimit(
    "product-update",
    20,
    10 * 60 * 1000
  ),
  async (
    req,
    res
  ) => {
    try {
      const uid =
        req.auth.uid;

      await assertSellerCanPublish(
        uid
      );

      const body =
        map(
          req.body
        );

      const productId =
        safe(
          body.productId
        );

      if (!productId) {
        const error =
          new Error(
            "PRODUCT_ID_REQUIRED"
          );

        error.statusCode =
          400;

        error.publicMessage =
          "Produto inválido.";

        throw error;
      }

      const productSnap =
        await db
          .ref(
            `products/${productId}`
          )
          .get();

      if (
        !productSnap.exists()
      ) {
        const error =
          new Error(
            "PRODUCT_NOT_FOUND"
          );

        error.statusCode =
          404;

        error.publicMessage =
          "Produto não encontrado.";

        throw error;
      }

      const existing =
        map(
          productSnap.val()
        );

      if (
        existing.ownerUid !==
        uid
      ) {
        const error =
          new Error(
            "PRODUCT_OWNER_REQUIRED"
          );

        error.statusCode =
          403;

        error.publicMessage =
          "Você não pode editar este produto.";

        throw error;
      }

      const productType =
        safe(
          existing.productType
        ).toLowerCase();

      const expectedType =
        safe(
          body.expectedProductType
        ).toLowerCase();

      if (
        expectedType &&
        expectedType !==
          productType
      ) {
        const error =
          new Error(
            "PRODUCT_TYPE_CONFLICT"
          );

        error.statusCode =
          409;

        error.publicMessage =
          "O tipo original do produto mudou. Atualize a tela.";

        throw error;
      }

      if (
        ![
          "affiliate",
          "local",
        ].includes(
          productType
        )
      ) {
        const error =
          new Error(
            "UNSUPPORTED_PRODUCT_TYPE"
          );

        error.statusCode =
          409;

        error.publicMessage =
          "Este produto usa um formato antigo ainda não suportado.";

        throw error;
      }

      const title =
        validateProductTitle(
          body.title
        );

      const description =
        validateProductDescription(
          body.description
        );

      const priceCents =
        validatePriceCents(
          body.priceCents
        );

      const category =
        await validateCategory(
          body.categoryId,
          productType
        );

      const storeId =
        await resolveStoreForUser(
          uid,
          existing.storeId
        );

      const {
        store,
        settings,
      } =
        await getStoreContext(
          storeId
        );

      validateStoreFeature(
        settings,
        productType
      );

      const accountVisibility =
        await getAccountVisibility(
          uid
        );

      const publicEligible =
        accountAndStoreCanBePublic(
          accountVisibility,
          store
        );

      const visibility =
        publicEligible
          ? "public"
          : "private";

      const mediaScope =
        publicEligible
          ? "public"
          : "private";

      const t =
        nowMs();

      const media =
        await mediaForProductUpdate(
          body.images,
          existing,
          uid,
          productId,
          mediaScope
        );

      const updated = {
        ...existing,

        productId,
        storeId,

        ownerUid:
          uid,

        productType,

        status:
          existing.status ===
          "deleted"
            ? "deleted"
            : "active",

        visibility:
          existing.status ===
          "deleted"
            ? "hidden"
            : visibility,

        title,
        description,

        categoryId:
          category.id,

        pricing: {
          ...map(
            existing.pricing
          ),

          currency:
            "BRL",

          priceCents,
        },

        media: {
          coverUrl:
            media.detailUrls[0],

          images:
            media.detailUrls,
        },

        commerce: {
          ...map(
            existing.commerce
          ),

          allowChat:
            settings.chatEnabled !==
            false,
        },

        lifecycle: {
          ...map(
            existing.lifecycle
          ),

          createdAtMs:
            integer(
              existing.lifecycle
                ?.createdAtMs,
              t
            ),

          updatedAtMs:
            t,

          deletedAtMs:
            integer(
              existing.lifecycle
                ?.deletedAtMs,
              0
            ),
        },
      };

      if (
        productType ===
        "affiliate"
      ) {
        const affiliate =
          validateAffiliateUrl(
            body.affiliate
              ?.url
          );

        updated.affiliate = {
          ...map(
            existing.affiliate
          ),
          ...affiliate,

          validatedAtMs:
            t,

          serverRevalidationRequired:
            true,
        };

        delete updated.local;
      }

      const oldCardSnap =
        await db
          .ref(
            `product_cards/${productId}`
          )
          .get();

      const oldCard =
        map(
          oldCardSnap.val()
        );

      const oldTerms =
        searchTermsForProduct(
          existing.title,
          existing.categoryId
        );

      const updates = {
        [`products/${productId}`]:
          updated,
      };

      addProjectionRemovals(
        updates,
        existing,
        oldTerms
      );

      if (
        publicEligible &&
        updated.status ===
          "active" &&
        safe(
          updated.moderation
            ?.status
        ) === "approved"
      ) {
        const card =
          publicProductCard(
            updated,
            media.thumbUrls[0],
            t,
            oldCard
          );

        addPublicProjections(
          updates,
          updated,
          card,
          searchTermsForProduct(
            title,
            category.id
          ),
          t
        );

        const sponsoredCardSnap =
          await db
            .ref(
              `active_boost_cards/${productId}`
            )
            .get();

        const sponsoredCard =
          map(
            sponsoredCardSnap.val()
          );

        const currentBoostId =
          safe(
            sponsoredCard.boostId
          );

        if (currentBoostId) {
          const activeBoostSnap =
            await db
              .ref(
                `boosts/${currentBoostId}`
              )
              .get();

          const activeBoost =
            map(
              activeBoostSnap.val()
            );

          if (
            activeBoost.status ===
              "active" &&
            finiteNumber(
              activeBoost.expiresAtMs,
              0
            ) > t
          ) {
            updates[
              `active_boost_cards/${productId}`
            ] = {
              ...card,

              boostId:
                currentBoostId,

              startsAtMs:
                finiteNumber(
                  activeBoost.startsAtMs,
                  t
                ),

              expiresAtMs:
                finiteNumber(
                  activeBoost.expiresAtMs,
                  t
                ),
            };
          }
        }
      }

      await db
        .ref()
        .update(
          updates
        );

      await appendAudit(
        "product_updated",
        {
          actorUid:
            uid,

          targetUid:
            uid,

          referenceId:
            productId,
        }
      );

      return res.json({
        ok: true,

        productId,

        visibility:
          updated.visibility,

        publicProjected:
          publicEligible &&
          updated.status ===
            "active" &&
          updated.moderation
            ?.status ===
            "approved",
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "Não foi possível atualizar o produto."
      );
    }
  }
);

function validateAddressPayload(
  raw
) {
  const address =
    map(raw);

  const fullName =
    clip(
      address.fullName,
      120
    );

  const phone =
    safe(
      address.phone
    )
      .replace(
        /\D/g,
        ""
      )
      .slice(
        0,
        32
      );

  const cep =
    safe(
      address.cep
    )
      .replace(
        /\D/g,
        ""
      )
      .slice(
        0,
        16
      );

  const city =
    clip(
      address.city,
      100
    );

  const state =
    clip(
      address.state,
      64
    ).toUpperCase();

  const neighborhood =
    clip(
      address.neighborhood,
      120
    );

  const street =
    clip(
      address.street,
      180
    );

  const number =
    clip(
      address.number,
      24
    );

  const complement =
    clip(
      address.complement,
      160
    );

  const referencePoint =
    clip(
      address.referencePoint,
      180
    );

  if (
    fullName.length < 3
  ) {
    throwAddress(
      "Nome inválido."
    );
  }

  if (
    phone.length < 10 ||
    phone.length > 15
  ) {
    throwAddress(
      "Telefone inválido."
    );
  }

  if (
    cep &&
    cep.length !== 8
  ) {
    throwAddress(
      "CEP inválido."
    );
  }

  if (
    street.length < 2
  ) {
    throwAddress(
      "Rua inválida."
    );
  }

  if (!number) {
    throwAddress(
      "Número do endereço obrigatório."
    );
  }

  if (
    neighborhood.length < 2
  ) {
    throwAddress(
      "Bairro inválido."
    );
  }

  if (
    city.length < 2
  ) {
    throwAddress(
      "Cidade inválida."
    );
  }

  const validStates =
    new Set([
      "AC",
      "AL",
      "AP",
      "AM",
      "BA",
      "CE",
      "DF",
      "ES",
      "GO",
      "MA",
      "MT",
      "MS",
      "MG",
      "PA",
      "PB",
      "PR",
      "PE",
      "PI",
      "RJ",
      "RN",
      "RS",
      "RO",
      "RR",
      "SC",
      "SP",
      "SE",
      "TO",
    ]);

  if (
    !validStates.has(
      state
    )
  ) {
    throwAddress(
      "UF inválida."
    );
  }

  return {
    cep,
    city,
    state,
    neighborhood,
    street,
    number,
    complement,
    referencePoint,
    fullName,
    phone,
  };
}

function throwAddress(
  message
) {
  const error =
    new Error(
      "INVALID_ADDRESS"
    );

  error.statusCode =
    422;

  error.publicMessage =
    message;

  throw error;
}

function normalizePrivateLocation(
  raw
) {
  const value =
    map(raw);

  const latitude =
    finiteNumber(
      value.latitude,
      0
    );

  const longitude =
    finiteNumber(
      value.longitude,
      0
    );

  const accuracyMeters =
    Math.max(
      0,
      Math.min(
        100000,
        finiteNumber(
          value.accuracyMeters,
          0
        )
      )
    );

  const valid =
    latitude >= -90 &&
    latitude <= 90 &&
    longitude >= -180 &&
    longitude <= 180 &&
    latitude !== 0 &&
    longitude !== 0;

  return valid
    ? {
        latitude,
        longitude,
        accuracyMeters,
        source:
          "device_location",
      }
    : {
        latitude:
          0,
        longitude:
          0,
        accuracyMeters:
          0,
        source:
          "manual",
      };
}

app.post(
  "/v1/account/address",
  requireUser,
  rateLimit(
    "address-save",
    15,
    10 * 60 * 1000
  ),
  async (
    req,
    res
  ) => {
    try {
      const uid =
        req.auth.uid;

      const body =
        map(
          req.body
        );

      const addressId =
        safe(
          body.addressId ||
            "primary"
        ).toLowerCase();

      if (
        addressId !==
        "primary"
      ) {
        const error =
          new Error(
            "PRIMARY_ADDRESS_ONLY"
          );

        error.statusCode =
          422;

        error.publicMessage =
          "Esta tela gerencia o endereço principal.";

        throw error;
      }

      const address =
        validateAddressPayload(
          body.address
        );

      const location =
        normalizePrivateLocation(
          body.deviceLocation
        );

      const t =
        nowMs();

      const record = {
        ...address,

        latitude:
          location.latitude,

        longitude:
          location.longitude,

        accuracyMeters:
          location.accuracyMeters,

        source:
          location.source,

        confirmedByUser:
          true,

        confirmedAtMs:
          t,

        usableForOrder:
          true,

        needsReview:
          false,
      };

      const updates = {
        [`user_addresses/${uid}/primary`]:
          record,
      };

      if (
        body.alsoUseForShipping ===
        true
      ) {
        updates[
          `user_addresses/${uid}/shipping`
        ] =
          record;
      }

      await db
        .ref()
        .update(
          updates
        );

      await appendAudit(
        "address_updated",
        {
          actorUid:
            uid,
          targetUid:
            uid,
          referenceId:
            "primary",
        }
      );

      return res.json({
        ok: true,

        addressId:
          "primary",

        usableForOrder:
          true,

        needsReview:
          false,

        locationSource:
          location.source,
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "Não foi possível salvar o endereço."
      );
    }
  }
);

function escapeHtml(
  value
) {
  return String(
    value ?? ""
  )
    .replace(
      /&/g,
      "&amp;"
    )
    .replace(
      /</g,
      "&lt;"
    )
    .replace(
      />/g,
      "&gt;"
    )
    .replace(
      /"/g,
      "&quot;"
    )
    .replace(
      /'/g,
      "&#039;"
    );
}

function isValidEmail(
  email
) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    safe(email).toLowerCase()
  );
}

function maskEmail(
  email
) {
  const [
    name = "",
    domain = "",
  ] =
    safe(email).split("@");

  if (!domain) {
    return "***";
  }

  const visible =
    name.slice(
      0,
      Math.min(
        2,
        name.length
      )
    );

  return `${visible}***@${domain}`;
}
function htmlPage(
  title,
  message
) {
  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    *{box-sizing:border-box}
    body{
      margin:0;
      min-height:100vh;
      background:#05070b;
      color:#fff;
      font-family:Arial,sans-serif;
      display:grid;
      place-items:center;
      padding:24px
    }
    .card{
      width:min(100%,560px);
      padding:28px;
      border-radius:24px;
      background:#0f1722;
      border:1px solid #19364b;
      box-shadow:0 22px 70px rgba(0,0,0,.35)
    }
    .brand{
      display:inline-grid;
      place-items:center;
      width:52px;
      height:52px;
      border-radius:17px;
      background:rgba(14,165,255,.12);
      border:1px solid rgba(14,165,255,.28);
      color:#0ea5ff;
      font-weight:900;
      margin-bottom:16px
    }
    h1{
      margin:0 0 10px;
      font-size:28px
    }
    p{
      margin:0;
      color:#aab4c2;
      line-height:1.5
    }
    a{
      color:#0ea5ff
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="brand">FR</div>
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
  </main>
</body>
</html>`;
}

function resetPasswordPage() {
  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Redefinir senha - FireRank</title>
  <style>
    *{box-sizing:border-box}
    body{
      margin:0;
      min-height:100vh;
      background:#05070b;
      color:#fff;
      font-family:Arial,sans-serif;
      display:grid;
      place-items:center;
      padding:24px
    }
    .card{
      width:min(100%,470px);
      padding:28px;
      border-radius:24px;
      background:#0f1722;
      border:1px solid #19364b;
      box-shadow:0 22px 70px rgba(0,0,0,.35)
    }
    .brand{
      color:#0ea5ff;
      font-weight:900;
      font-size:20px;
      margin-bottom:18px
    }
    h1{
      margin:0 0 8px
    }
    .sub{
      color:#aab4c2;
      line-height:1.45;
      margin:0 0 18px
    }
    label{
      display:block;
      color:#aab4c2;
      font-weight:700;
      font-size:13px;
      margin:12px 0 7px
    }
    input{
      width:100%;
      height:50px;
      border-radius:14px;
      border:1px solid #19364b;
      background:#152131;
      color:#fff;
      padding:0 14px;
      outline:none
    }
    input:focus{
      border-color:#0ea5ff
    }
    button{
      width:100%;
      height:50px;
      border:0;
      border-radius:14px;
      background:#0677e8;
      color:#fff;
      font-weight:900;
      margin-top:16px;
      cursor:pointer
    }
    button:disabled{
      opacity:.55
    }
    .msg{
      display:none;
      margin-top:13px;
      padding:11px;
      border-radius:12px;
      background:#152131;
      color:#aab4c2
    }
    .msg.show{
      display:block
    }
    .msg.ok{
      border:1px solid rgba(22,163,106,.35)
    }
    .msg.err{
      border:1px solid rgba(217,61,74,.35)
    }
  </style>
</head>

<body>
  <main class="card">
    <div class="brand">FireRank</div>

    <h1>Crie uma nova senha</h1>

    <p class="sub">
      Digite sua nova senha e confirme.
    </p>

    <form id="form">
      <label>Nova senha</label>

      <input
        id="password"
        type="password"
        minlength="6"
        autocomplete="new-password"
        required
      />

      <label>Confirmar senha</label>

      <input
        id="confirm"
        type="password"
        minlength="6"
        autocomplete="new-password"
        required
      />

      <button
        id="btn"
        type="submit"
      >
        Salvar nova senha
      </button>

      <div
        id="msg"
        class="msg"
      ></div>
    </form>
  </main>

<script>
const form =
  document.getElementById('form');

const btn =
  document.getElementById('btn');

const msg =
  document.getElementById('msg');

const params =
  new URLSearchParams(
    location.search
  );

const oobCode =
  params.get('oobCode') ||
  params.get('oobcode') ||
  '';

function show(
  type,
  text
) {
  msg.className =
    'msg show ' + type;

  msg.textContent =
    text;
}

if (!oobCode) {
  show(
    'err',
    'Link inválido. Solicite uma nova recuperação no app.'
  );

  btn.disabled =
    true;
}

form.addEventListener(
  'submit',
  async (e) => {
    e.preventDefault();

    const password =
      document
        .getElementById(
          'password'
        )
        .value
        .trim();

    const confirm =
      document
        .getElementById(
          'confirm'
        )
        .value
        .trim();

    if (
      password.length < 6
    ) {
      return show(
        'err',
        'A senha precisa ter pelo menos 6 caracteres.'
      );
    }

    if (
      password !== confirm
    ) {
      return show(
        'err',
        'As senhas não conferem.'
      );
    }

    btn.disabled =
      true;

    btn.textContent =
      'Salvando...';

    try {
      const r =
        await fetch(
          '/api/auth/confirm-password-reset',
          {
            method:'POST',

            headers:{
              'Content-Type':'application/json'
            },

            body:
              JSON.stringify({
                oobCode,
                newPassword:
                  password
              })
          }
        );

      const d =
        await r
          .json()
          .catch(
            () => ({})
          );

      if (
        !r.ok ||
        !d.ok
      ) {
        throw new Error(
          d.error ||
          'Não foi possível redefinir a senha.'
        );
      }

      show(
        'ok',
        'Senha redefinida. Volte ao app e entre novamente.'
      );

      btn.textContent =
        'Senha salva';
    } catch (err) {
      show(
        'err',
        err.message ||
        'Link expirado ou inválido.'
      );

      btn.disabled =
        false;

      btn.textContent =
        'Salvar nova senha';
    }
  }
);
</script>
</body>
</html>`;
}

function ensureEmailConfig() {
  const missing = [];

  if (!SMTP_HOST) {
    missing.push(
      "SMTP_HOST"
    );
  }

  if (!SMTP_PORT) {
    missing.push(
      "SMTP_PORT"
    );
  }

  if (!SMTP_USER) {
    missing.push(
      "SMTP_USER"
    );
  }

  if (!SMTP_PASS) {
    missing.push(
      "SMTP_PASS"
    );
  }

  if (!MAIL_FROM_EMAIL) {
    missing.push(
      "MAIL_FROM_EMAIL"
    );
  }

  if (!FIREBASE_WEB_API_KEY) {
    missing.push(
      "FIREBASE_WEB_API_KEY"
    );
  }

  if (
    missing.length
  ) {
    throw new Error(
      `EMAIL_CONFIG_MISSING:${missing.join(",")}`
    );
  }
}

function mailTransporter() {
  ensureEmailConfig();

  return nodemailer
    .createTransport({
      host:
        SMTP_HOST,

      port:
        SMTP_PORT,

      secure:
        SMTP_SECURE,

      auth: {
        user:
          SMTP_USER,

        pass:
          SMTP_PASS,
      },
    });
}

function extractOobCodeFromFirebaseLink(
  link
) {
  try {
    const url =
      new URL(link);

    const direct =
      url
        .searchParams
        .get(
          "oobCode"
        );

    if (direct) {
      return direct;
    }

    const continuation =
      url
        .searchParams
        .get(
          "continueUrl"
        );

    if (!continuation) {
      return "";
    }

    return (
      new URL(
        continuation
      )
        .searchParams
        .get(
          "oobCode"
        ) ||
      ""
    );
  } catch (_) {
    return "";
  }
}

function buildResetEmailHtml(
  resetUrl
) {
  const url =
    escapeHtml(
      resetUrl
    );

  return `<div style="font-family:Arial,sans-serif;background:#f6f8fc;padding:24px">
  <div style="max-width:560px;margin:auto;background:#fff;border:1px solid #dce5ef;border-radius:20px;overflow:hidden">
    <div style="background:#05070b;padding:24px;color:#fff">
      <b style="color:#0ea5ff">FireRank</b>
      <h1 style="margin:12px 0 0">Redefina sua senha</h1>
    </div>

    <div style="padding:24px;color:#111827">
      <p>Recebemos uma solicitação para redefinir sua senha.</p>

      <p>
        <a
          href="${url}"
          style="display:inline-block;background:#0677e8;color:#fff;text-decoration:none;font-weight:900;padding:13px 20px;border-radius:12px"
        >
          Redefinir minha senha
        </a>
      </p>

      <p style="color:#5a6676;font-size:13px">
        Se você não pediu essa alteração, ignore este e-mail.
      </p>
    </div>
  </div>
</div>`;
}

async function sendPasswordResetEmail(
  email,
  resetUrl
) {
  const transporter =
    mailTransporter();

  await transporter.sendMail({
    from:
      `"${MAIL_FROM_NAME}" <${MAIL_FROM_EMAIL}>`,

    to:
      email,

    subject:
      "Redefina sua senha do FireRank",

    text:
      `Redefina sua senha do FireRank: ${resetUrl}\n\nSe você não solicitou, ignore este e-mail.`,

    html:
      buildResetEmailHtml(
        resetUrl
      ),
  });
}

const passwordResetThrottle =
  new Map();

function canRequestPasswordReset(
  email
) {
  const key =
    stableHash(
      safe(
        email
      ).toLowerCase()
    );

  const last =
    Number(
      passwordResetThrottle
        .get(key) || 0
    );

  const t =
    nowMs();

  if (
    last &&
    t - last <
      60 * 1000
  ) {
    return false;
  }

  passwordResetThrottle
    .set(
      key,
      t
    );

  return true;
}

app.post(
  "/api/auth/request-password-reset",
  rateLimit(
    "password-reset",
    8,
    15 * 60 * 1000
  ),
  async (
    req,
    res
  ) => {
    const email =
      safe(
        req.body?.email
      ).toLowerCase();

    try {
      if (
        !isValidEmail(
          email
        )
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Digite um e-mail válido.",
          });
      }

      if (
        !canRequestPasswordReset(
          email
        )
      ) {
        return res
          .status(429)
          .json({
            ok: false,
            error:
              "Aguarde antes de pedir outro link.",
          });
      }

      ensureEmailConfig();

      let userRecord =
        null;

      try {
        userRecord =
          await admin
            .auth()
            .getUserByEmail(
              email
            );
      } catch (_) {
        await appendAudit(
          "password_reset_requested",
          {
            referenceId:
              stableHash(
                email
              ).slice(
                0,
                20
              ),

            status:
              "generic_response",
          }
        );

        return res.json({
          ok: true,

          message:
            "Se existir uma conta com esse e-mail, enviaremos um link de recuperação.",
        });
      }

      const firebaseResetLink =
        await admin
          .auth()
          .generatePasswordResetLink(
            email
          );

      const oobCode =
        extractOobCodeFromFirebaseLink(
          firebaseResetLink
        );

      if (!oobCode) {
        throw new Error(
          "PASSWORD_RESET_CODE_GENERATION_FAILED"
        );
      }

      const resetUrl =
        `${PASSWORD_RESET_URL}?mode=resetPassword&oobCode=${encodeURIComponent(
          oobCode
        )}`;

      await sendPasswordResetEmail(
        email,
        resetUrl
      );

      await appendAudit(
        "password_reset_requested",
        {
          targetUid:
            userRecord.uid,

          referenceId:
            stableHash(
              email
            ).slice(
              0,
              20
            ),

          status:
            "sent",
        }
      );

      return res.json({
        ok: true,

        message:
          "Se existir uma conta com esse e-mail, enviaremos um link de recuperação.",
      });
    } catch (error) {
      console.error(
        "Password reset request:",
        error.message
      );

      return res
        .status(500)
        .json({
          ok: false,

          error:
            "Não foi possível enviar a recuperação agora. Tente novamente mais tarde.",
        });
    }
  }
);

app.post(
  "/api/auth/confirm-password-reset",
  rateLimit(
    "password-confirm",
    10,
    15 * 60 * 1000
  ),
  async (
    req,
    res
  ) => {
    try {
      const oobCode =
        safe(
          req.body?.oobCode ||
            req.body?.code
        );

      const newPassword =
        safe(
          req.body
            ?.newPassword ||
            req.body?.password
        );

      if (
        !FIREBASE_WEB_API_KEY
      ) {
        throw new Error(
          "FIREBASE_WEB_API_KEY_MISSING"
        );
      }

      if (!oobCode) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Link inválido.",
          });
      }

      if (
        newPassword.length <
        6
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "A senha precisa ter pelo menos 6 caracteres.",
          });
      }

      const response =
        await axios.post(
          `https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key=${encodeURIComponent(
            FIREBASE_WEB_API_KEY
          )}`,
          {
            oobCode,
            newPassword,
          },
          {
            headers: {
              "Content-Type":
                "application/json",
            },
          }
        );

      const email =
        safe(
          response.data?.email
        );

      let targetUid =
        "";

      if (email) {
        try {
          targetUid =
            (
              await admin
                .auth()
                .getUserByEmail(
                  email
                )
            ).uid;
        } catch (_) {}
      }

      await appendAudit(
        "password_reset_completed",
        {
          targetUid,

          referenceId:
            email
              ? stableHash(
                  email
                ).slice(
                  0,
                  20
                )
              : "",

          status:
            "completed",
        }
      );

      return res.json({
        ok: true,
        message:
          "Senha redefinida com sucesso.",
      });
    } catch (error) {
      const apiError =
        safe(
          error.response
            ?.data
            ?.error
            ?.message ||
            error.response
              ?.data
              ?.message ||
            error.message
        );

      let friendly =
        "Link expirado ou inválido. Solicite uma nova recuperação.";

      if (
        apiError.includes(
          "WEAK_PASSWORD"
        )
      ) {
        friendly =
          "A senha é muito fraca.";
      }

      if (
        apiError.includes(
          "EXPIRED_OOB_CODE"
        )
      ) {
        friendly =
          "Esse link expirou.";
      }

      if (
        apiError.includes(
          "INVALID_OOB_CODE"
        )
      ) {
        friendly =
          "Esse link é inválido ou já foi usado.";
      }

      return res
        .status(400)
        .json({
          ok: false,
          error:
            friendly,
        });
    }
  }
);

function ensureMP() {
  if (!MP_ACCESS_TOKEN) {
    const error = new Error(
      "MERCADO_PAGO_NOT_CONFIGURED"
    );
    error.statusCode = 503;
    error.publicMessage =
      "Pagamento temporariamente indisponível.";
    throw error;
  }

  if (
    NODE_ENV === "production" &&
    !MP_WEBHOOK_SECRET
  ) {
    const error = new Error(
      "MERCADO_PAGO_WEBHOOK_SECRET_NOT_CONFIGURED"
    );
    error.statusCode = 503;
    error.publicMessage =
      "Pagamento temporariamente indisponível.";
    throw error;
  }

  if (
    NODE_ENV === "production" &&
    !isHttpsUrl(MP_WEBHOOK_URL)
  ) {
    const error = new Error(
      "MERCADO_PAGO_WEBHOOK_URL_INVALID"
    );
    error.statusCode = 503;
    error.publicMessage =
      "Pagamento temporariamente indisponível.";
    throw error;
  }
}

function mpHeaders() {
  return {
    Authorization:
      `Bearer ${MP_ACCESS_TOKEN}`,

    "Content-Type":
      "application/json",
  };
}

function normalizePaymentStatus(
  status
) {
  const value =
    safe(
      status
    ).toLowerCase();

  if (
    [
      "approved",
      "paid",
      "confirmed",
      "active",
    ].includes(
      value
    )
  ) {
    return "approved";
  }

  if (
    [
      "pending",
      "in_process",
    ].includes(
      value
    )
  ) {
    return value;
  }

  if (
    [
      "cancelled",
      "canceled",
    ].includes(
      value
    )
  ) {
    return "cancelled";
  }

  if (
    [
      "rejected",
      "refunded",
      "charged_back",
    ].includes(
      value
    )
  ) {
    return value;
  }

  return value ||
    "pending";
}

function paymentRequestType(
  body
) {
  const raw =
    safe(
      body.type ||
        body.paymentType ||
        body.payment_type ||
        body.requestType ||
        body.kind
    ).toLowerCase();

  if (
    [
      "boost",
      "ad",
      "ads",
      "advertisement",
      "turbinado",
      "impulsionamento",
    ].includes(
      raw
    )
  ) {
    return "boost";
  }

  if (
    [
      "verification",
      "verified",
      "selo",
      "selo_verificado",
      "subscription",
    ].includes(
      raw
    )
  ) {
    return "verification";
  }

  if (
    body.productId ||
    body.product_id
  ) {
    return "boost";
  }

  return "verification";
}
async function readSubscriptionPlan(
  requested
) {
  const raw =
    safe(
      requested ||
        "normal"
    ).toLowerCase();

  const aliases = {
    verified_normal:
      "normal",

    verified_plus:
      "plus",

    verified_pro:
      "pro",
  };

  const key =
    aliases[raw] ||
    raw;

  const directSnap =
    await db
      .ref(
        `subscription_plans/${key}`
      )
      .get();

  if (
    directSnap.exists()
  ) {
    return {
      key,
      ...map(
        directSnap.val()
      ),
    };
  }

  const allSnap =
    await db
      .ref(
        "subscription_plans"
      )
      .get();

  const all =
    map(
      allSnap.val()
    );

  for (
    const [
      planKey,
      plan,
    ]
    of Object.entries(
      all
    )
  ) {
    if (
      safe(
        plan?.planId
      ).toLowerCase() ===
      raw
    ) {
      return {
        key:
          planKey,
        ...map(plan),
      };
    }
  }

  const error =
    new Error(
      "SUBSCRIPTION_PLAN_NOT_FOUND"
    );

  error.statusCode =
    422;

  error.publicMessage =
    "Plano de verificação inválido.";

  throw error;
}

async function assertVerificationPurchaseEligible(
  uid
) {
  if (
    !(await getFeatureFlag(
      "verificationSubscriptions",
      false
    ))
  ) {
    const error =
      new Error(
        "VERIFICATION_SUBSCRIPTIONS_DISABLED"
      );

    error.statusCode =
      409;

    error.publicMessage =
      "Assinaturas verificadas ainda não estão liberadas.";

    throw error;
  }

  const [
    eligibilitySnap,
    identitySnap,
  ] =
    await Promise.all([
      db
        .ref(
          `eligibility/${uid}`
        )
        .get(),

      db
        .ref(
          `identity_status/${uid}`
        )
        .get(),
    ]);

  const eligibility =
    map(
      eligibilitySnap.val()
    );

  const identity =
    map(
      identitySnap.val()
    );

  if (
    eligibility.canSubscribeVerified !==
      true ||
    eligibility.needsAgeReview ===
      true ||
    safe(
      identity.identityReviewStatus
    ).toLowerCase() !==
      "approved"
  ) {
    const error =
      new Error(
        "VERIFICATION_NOT_ELIGIBLE"
      );

    error.statusCode =
      403;

    error.publicMessage =
      "Sua conta ainda não está elegível para assinar a verificação.";

    throw error;
  }

  return {
    eligibility,
    identity,
  };
}

function parseBoostCatalogFromEnv() {
  if (
    !BOOST_CATALOG_JSON
  ) {
    return {};
  }

  try {
    return map(
      JSON.parse(
        BOOST_CATALOG_JSON
      )
    );
  } catch (_) {
    return {};
  }
}

async function getBoostCatalog() {
  const snap =
    await db
      .ref(
        "public_config/boostCatalog"
      )
      .get();

  const fromDb =
    map(
      snap.val()
    );

  if (
    Object.keys(
      fromDb
    ).length > 0
  ) {
    return fromDb;
  }

  return parseBoostCatalogFromEnv();
}

async function readBoostPlan(
  requested
) {
  const planId =
    safe(
      requested ||
        "one_day"
    ).toLowerCase();

  const catalog =
    await getBoostCatalog();

  const plan =
    map(
      catalog[planId]
    );

  if (
    !planId ||
    Object.keys(plan)
      .length === 0
  ) {
    const error =
      new Error(
        "BOOST_CATALOG_NOT_CONFIGURED"
      );

    error.statusCode =
      503;

    error.publicMessage =
      "Os preços de Patrocinado ainda não foram configurados no servidor.";

    throw error;
  }

  const priceCents =
    integer(
      plan.priceCents,
      -1
    );

  const days =
    integer(
      plan.days,
      -1
    );

  if (
    plan.active ===
      false ||
    priceCents <= 0 ||
    days <= 0 ||
    days > 365
  ) {
    const error =
      new Error(
        "BOOST_PLAN_NOT_AVAILABLE"
      );

    error.statusCode =
      422;

    error.publicMessage =
      "Plano de Patrocinado indisponível.";

    throw error;
  }

  return {
    planId,

    displayName:
      clip(
        plan.displayName ||
          "Patrocinado",
        100
      ),

    priceCents,

    days,

    placement:
      clip(
        plan.placement ||
          "discover_sponsored",
        80
      ),
  };
}

async function productIsCurrentlyPublic(
  product
) {
  if (
    !product ||
    product.status !==
      "active" ||
    product.visibility !==
      "public" ||
    safe(
      product.moderation
        ?.status
    ).toLowerCase() !==
      "approved"
  ) {
    return false;
  }

  const [
    visibility,
    storeSnap,
  ] =
    await Promise.all([
      getAccountVisibility(
        product.ownerUid
      ),

      db
        .ref(
          `stores/${product.storeId}`
        )
        .get(),
    ]);

  const store =
    map(
      storeSnap.val()
    );

  return accountAndStoreCanBePublic(
    visibility,
    store
  );
}

async function createPaymentPreference(
  req,
  res
) {
  try {
    ensureMP();

    const uid =
      req.auth.uid;

    const body =
      map(
        req.body
      );

    const requestType =
      paymentRequestType(
        body
      );

    const clientPlatform =
      safe(
        body.clientPlatform ||
          req.headers[
            "x-client-platform"
          ]
      ).toLowerCase();

    if (
      ENFORCE_GOOGLE_PLAY_BILLING &&
      (
        clientPlatform ===
          "android" ||
        clientPlatform ===
          "flutter_android" ||
        clientPlatform ===
          "flutter_app"
      )
    ) {
      return res
        .status(409)
        .json({
          ok: false,

          code:
            "GOOGLE_PLAY_BILLING_REQUIRED",

          message:
            "No Android, este serviço digital precisa usar o faturamento da Google Play.",
        });
    }

    const requestId =
      db
        .ref(
          "payments"
        )
        .push()
        .key;

    if (!requestId) {
      throw new Error(
        "PAYMENT_ID_GENERATION_FAILED"
      );
    }

    const t =
      nowMs();

    let title =
      "FireRank";

    let amountCents =
      0;

    let requestRecord =
      {};

    if (
      requestType ===
      "verification"
    ) {
      await assertVerificationPurchaseEligible(
        uid
      );

      const plan =
        await readSubscriptionPlan(
          body.plan ||
          body.planId
        );

      if (
        plan.activeForLaunch !==
          true ||
        safe(
          plan.currency ||
            "BRL"
        ) !== "BRL"
      ) {
        const error =
          new Error(
            "SUBSCRIPTION_PLAN_DISABLED"
          );

        error.statusCode =
          409;

        error.publicMessage =
          "Este plano não está disponível.";

        throw error;
      }

      amountCents =
        integer(
          plan.priceCents,
          -1
        );

      if (
        amountCents <= 0
      ) {
        throw new Error(
          "INVALID_SERVER_PLAN_PRICE"
        );
      }

      title =
        clip(
          plan.displayName ||
            "Verificado FireRank",
          120
        );

      requestRecord = {
        requestId,

        uid,

        type:
          "verification",

        planKey:
          plan.key,

        planId:
          safe(
            plan.planId ||
              plan.key
          ),

        amountCents,

        currency:
          "BRL",

        status:
          "creating_preference",

        createdAtMs:
          t,

        updatedAtMs:
          t,
      };
    } else {
      if (
        !(await getFeatureFlag(
          "boosts",
          true
        ))
      ) {
        const error =
          new Error(
            "BOOSTS_DISABLED"
          );

        error.statusCode =
          409;

        error.publicMessage =
          "Patrocinados estão temporariamente desativados.";

        throw error;
      }

      await assertSellerCanPublish(
        uid
      );

      const productId =
        safe(
          body.productId ||
            body.product_id
        );

      const productSnap =
        await db
          .ref(
            `products/${productId}`
          )
          .get();

      const product =
        map(
          productSnap.val()
        );

      if (
        !productSnap.exists() ||
        product.ownerUid !==
          uid
      ) {
        const error =
          new Error(
            "BOOST_PRODUCT_NOT_OWNED"
          );

        error.statusCode =
          403;

        error.publicMessage =
          "Você não pode patrocinar este produto.";

        throw error;
      }

      if (
        !(await productIsCurrentlyPublic(
          product
        ))
      ) {
        const error =
          new Error(
            "BOOST_PRODUCT_NOT_PUBLIC"
          );

        error.statusCode =
          409;

        error.publicMessage =
          "Somente produtos públicos e ativos podem ser patrocinados.";

        throw error;
      }

      const plan =
        await readBoostPlan(
          body.plan ||
          body.planId
        );

      amountCents =
        plan.priceCents;

      title =
        `${plan.displayName}: ${clip(
          product.title,
          80
        )}`;

      requestRecord = {
        requestId,

        ownerUid:
          uid,

        type:
          "boost",

        productId,

        planId:
          plan.planId,

        placement:
          plan.placement,

        days:
          plan.days,

        amountCents,

        currency:
          "BRL",

        status:
          "creating_preference",

        createdAtMs:
          t,

        updatedAtMs:
          t,
      };
    }

    const mpPayload = {
      items: [
        {
          id:
            requestId,

          title,

          quantity:
            1,

          currency_id:
            "BRL",

          unit_price:
            amountCents /
            100,
        },
      ],

      external_reference:
        requestId,

      back_urls: {
        success:
          PAYMENT_SUCCESS_URL,

        pending:
          PAYMENT_PENDING_URL,

        failure:
          PAYMENT_FAILURE_URL,
      },

      auto_return:
        "approved",

      notification_url:
        MP_WEBHOOK_URL,

      metadata: {
        type:
          requestType,

        request_id:
          requestId,
      },
    };

    const mpResponse =
      await axios.post(
        "https://api.mercadopago.com/checkout/preferences",

        mpPayload,

        {
          headers:
            mpHeaders(),

          timeout:
            20000,
        }
      );

    const preferenceId =
      safe(
        mpResponse.data?.id
      );

    const checkoutUrl =
      safe(
        mpResponse.data
          ?.init_point
      );

    const sandboxInitPoint =
      safe(
        mpResponse.data
          ?.sandbox_init_point
      );

    if (
      !preferenceId ||
      !checkoutUrl
    ) {
      throw new Error(
        "MP_PREFERENCE_INCOMPLETE"
      );
    }

    const paymentRecord = {
      paymentId:
        requestId,

      uid,

      type:
        requestType,

      requestId,

      provider:
        "mercado_pago",

      gatewayPreferenceId:
        preferenceId,

      amountCents,

      currency:
        "BRL",

      status:
        "pending",

      fulfillmentStatus:
        "pending_payment",

      createdAtMs:
        t,

      updatedAtMs:
        t,
    };

    const updates = {
      [`payments/${requestId}`]:
        paymentRecord,

      [`payment_requests/${uid}/${requestId}`]:
        {
          ...requestRecord,

          status:
            "pending_payment",

          gatewayPreferenceId:
            preferenceId,

          checkoutUrl,

          updatedAtMs:
            t,
        },

      [`payment_events/${requestId}/preference_created`]:
        {
          eventId:
            "preference_created",

          type:
            "preference_created",

          status:
            "pending",

          createdAtMs:
            t,

          immutable:
            true,
        },
    };

    if (
      requestType ===
      "boost"
    ) {
      updates[
        `boost_requests/${requestId}`
      ] = {
        ...requestRecord,

        status:
          "pending_payment",

        gatewayPreferenceId:
          preferenceId,
      };
    }

    await db
      .ref()
      .update(
        updates
      );

    await appendAudit(
      "payment_preference_created",
      {
        actorUid:
          uid,

        targetUid:
          uid,

        referenceId:
          requestId,

        status:
          requestType,
      }
    );

    return res.json({
      ok:
        true,

      type:
        requestType,

      publicKey:
        MP_PUBLIC_KEY,

      preferenceId,

      initPoint:
        checkoutUrl,

      checkoutUrl,

      sandboxInitPoint,

      externalReference:
        requestId,
    });
  } catch (error) {
    return publicError(
      res,
      error,
      "Não foi possível iniciar o pagamento."
    );
  }
}

app.post(
  "/api/mercadopago/create-preference",
  requireUser,
  rateLimit(
    "payment-create",
    8,
    10 * 60 * 1000
  ),
  createPaymentPreference
);

app.post(
  "/v1/billing/mercadopago/create-preference",
  requireUser,
  rateLimit(
    "payment-create-v1",
    8,
    10 * 60 * 1000
  ),
  createPaymentPreference
);

async function fetchMercadoPagoPayment(
  paymentId
) {
  ensureMP();

  const response =
    await axios.get(
      `https://api.mercadopago.com/v1/payments/${encodeURIComponent(
        paymentId
      )}`,
      {
        headers:
          mpHeaders(),

        timeout:
          20000,
      }
    );

  return map(
    response.data
  );
}

async function appendFinancialLedgerEvent({
  uid,
  requestId,
  gatewayPaymentId,
  amountCents,
  status,
  type,
}) {
  const eventId =
    `ledger_${stableHash(
      `${requestId}|${gatewayPaymentId}|${status}|${type}`
    ).slice(
      0,
      28
    )}`;

  const ref =
    db.ref(
      `financial_ledger/${eventId}`
    );

  const snap =
    await ref.get();

  if (
    snap.exists()
  ) {
    return;
  }

  await ref.set({
    eventId,

    uid,

    type,

    referenceId:
      requestId,

    gatewayPaymentId,

    amountCents,

    currency:
      "BRL",

    status,

    createdAtMs:
      nowMs(),

    immutable:
      true,

    doesNotGrantEntitlement:
      status !==
      "approved",
  });
}
async function activateVerificationFromPayment(
  payment,
  paymentDetail,
  t
) {
  const uid = safe(payment.uid);
  const requestId = safe(payment.requestId);

  const latestPaymentSnap = await db
    .ref(`payments/${requestId}`)
    .get();
  const latestPayment = map(latestPaymentSnap.val());

  if (latestPayment.fulfillmentStatus === "fulfilled") {
    return;
  }

  const requestSnap = await db
    .ref(`payment_requests/${uid}/${requestId}`)
    .get();
  const request = map(requestSnap.val());
  const plan = await readSubscriptionPlan(
    request.planKey || request.planId
  );

  try {
    await assertVerificationPurchaseEligible(uid);
  } catch (_) {
    await db.ref().update({
      [`payments/${requestId}/fulfillmentStatus`]:
        "manual_review",
      [`payments/${requestId}/updatedAtMs`]:
        t,
      [`payment_requests/${uid}/${requestId}/status`]:
        "manual_review",
      [`payment_requests/${uid}/${requestId}/updatedAtMs`]:
        t,
    });

    await bestEffort(
      "verification-manual-review-notification",
      () =>
        pushNotification(uid, {
          title: "Pagamento recebido",
          body:
            "Seu pagamento foi recebido, mas a verificação precisa de revisão antes da ativação.",
          type: "verification_manual_review",
          data: { requestId },
        })
    );

    return;
  }

  const entitlementSnap = await db
    .ref(`entitlements/${uid}`)
    .get();
  const current = map(entitlementSnap.val());

  // Evita estender duas vezes a mesma assinatura em retries do webhook.
  if (
    current.sourceRequestId === requestId &&
    current.subscriptionActive === true &&
    latestPayment.fulfillmentStatus === "fulfilled"
  ) {
    return;
  }

  const currentExpiry = finiteNumber(
    current.expiresAtMs,
    0
  );
  const base =
    current.subscriptionActive === true &&
    currentExpiry > t
      ? currentExpiry
      : t;
  const expiresAtMs = base + 30 * DAY_MS;

  const eventId = firebaseSafeKey(
    `activated_${requestId}_${safe(paymentDetail.id)}`
  );

  await db.ref().update({
    [`entitlements/${uid}`]: {
      ...current,
      verifiedBadge: true,
      verifiedPlan: safe(
        plan.key ||
          request.planKey ||
          "normal"
      ),
      subscriptionActive: true,
      expiresAtMs,
      source: "backend_validated_mercado_pago",
      sourceRequestId: requestId,
      updatedAtMs: t,
      requiresBackendValidatedReceiptForReactivation:
        false,
    },
    [`subscription_events/${uid}/${eventId}`]: {
      eventId,
      uid,
      type: "activated",
      planId: safe(plan.planId || plan.key),
      requestId,
      gatewayPaymentId: safe(paymentDetail.id),
      startsAtMs: t,
      expiresAtMs,
      createdAtMs: t,
      immutable: true,
    },
    [`payments/${requestId}/fulfillmentStatus`]:
      "fulfilled",
    [`payments/${requestId}/fulfilledAtMs`]:
      t,
    [`payments/${requestId}/updatedAtMs`]:
      t,
    [`payment_requests/${uid}/${requestId}/status`]:
      "active",
    [`payment_requests/${uid}/${requestId}/expiresAtMs`]:
      expiresAtMs,
    [`payment_requests/${uid}/${requestId}/updatedAtMs`]:
      t,
  });

  await bestEffort(
    "verification-activated-notification",
    () =>
      pushNotification(uid, {
        title: "Verificação ativada",
        body:
          "Seu pagamento foi validado e sua assinatura de verificação está ativa.",
        type: "verification_activated",
        data: { requestId },
      })
  );
}

async function activateBoostFromPayment(
  payment,
  paymentDetail,
  t
) {
  const uid = safe(payment.uid);
  const requestId = safe(payment.requestId);

  const latestPaymentSnap = await db
    .ref(`payments/${requestId}`)
    .get();
  const latestPayment = map(latestPaymentSnap.val());

  if (latestPayment.fulfillmentStatus === "fulfilled") {
    return;
  }

  const requestSnap = await db
    .ref(`boost_requests/${requestId}`)
    .get();
  const request = map(requestSnap.val());
  const productId = safe(request.productId);

  const productSnap = await db
    .ref(`products/${productId}`)
    .get();
  const product = map(productSnap.val());

  if (
    !productSnap.exists() ||
    product.ownerUid !== uid ||
    !(await productIsCurrentlyPublic(product))
  ) {
    await db.ref().update({
      [`payments/${requestId}/fulfillmentStatus`]:
        "manual_review",
      [`payments/${requestId}/updatedAtMs`]:
        t,
      [`boost_requests/${requestId}/status`]:
        "blocked_after_payment",
      [`boost_requests/${requestId}/updatedAtMs`]:
        t,
    });

    await bestEffort(
      "boost-manual-review-notification",
      () =>
        pushNotification(uid, {
          title: "Patrocinado aguardando revisão",
          body:
            "O pagamento foi recebido, mas o produto não está público/ativo para iniciar o Patrocinado.",
          type: "boost_manual_review",
          data: { requestId, productId },
        })
    );

    return;
  }

  const cardSnap = await db
    .ref(`product_cards/${productId}`)
    .get();
  const card = map(cardSnap.val());

  if (!cardSnap.exists()) {
    throw new Error("PUBLIC_PRODUCT_CARD_MISSING");
  }

  const boostId = requestId;
  const days = integer(request.days, 0);

  if (days <= 0 || days > 365) {
    throw new Error("INVALID_BOOST_DURATION");
  }

  const expiresAtMs = t + days * DAY_MS;
  const eventId = firebaseSafeKey(
    `activated_${safe(paymentDetail.id)}`
  );

  await db.ref().update({
    [`boosts/${boostId}`]: {
      boostId,
      ownerUid: uid,
      productId,
      requestId,
      planId: clip(request.planId, 80),
      placement: clip(
        request.placement || "discover_sponsored",
        80
      ),
      status: "active",
      amountCents: integer(payment.amountCents),
      currency: "BRL",
      startsAtMs: t,
      expiresAtMs,
      updatedAtMs: t,
    },
    [`active_boost_cards/${productId}`]: {
      ...card,
      boostId,
      startsAtMs: t,
      expiresAtMs,
      updatedAtMs: t,
    },
    [`boost_requests/${requestId}/status`]:
      "active",
    [`boost_requests/${requestId}/boostId`]:
      boostId,
    [`boost_requests/${requestId}/startsAtMs`]:
      t,
    [`boost_requests/${requestId}/expiresAtMs`]:
      expiresAtMs,
    [`boost_requests/${requestId}/updatedAtMs`]:
      t,
    [`boost_events/${boostId}/${eventId}`]: {
      eventId,
      boostId,
      ownerUid: uid,
      productId,
      requestId,
      type: "activated",
      createdAtMs: t,
      immutable: true,
    },
    [`payments/${requestId}/fulfillmentStatus`]:
      "fulfilled",
    [`payments/${requestId}/fulfilledAtMs`]:
      t,
    [`payments/${requestId}/updatedAtMs`]:
      t,
    [`payment_requests/${uid}/${requestId}/status`]:
      "active",
    [`payment_requests/${uid}/${requestId}/updatedAtMs`]:
      t,
  });

  await bestEffort(
    "boost-activated-notification",
    () =>
      pushNotification(uid, {
        title: "Patrocinado ativado",
        body:
          "Seu pagamento foi validado e o produto já está na área de Patrocinados.",
        type: "boost_activated",
        data: { requestId, productId, boostId },
      })
  );
}

async function revokeFulfillmentForPayment(
  payment,
  status,
  t
) {
  const uid =
    safe(
      payment.uid
    );

  const requestId =
    safe(
      payment.requestId
    );

  if (
    payment.type ===
    "verification"
  ) {
    const entitlementSnap =
      await db
        .ref(
          `entitlements/${uid}`
        )
        .get();

    const entitlement =
      map(
        entitlementSnap.val()
      );

    const eventId =
      firebaseSafeKey(
        `reversed_${requestId}_${status}`
      );

    if (
      entitlement.sourceRequestId ===
        requestId &&
      entitlement.subscriptionActive ===
        true
    ) {
      await db
        .ref()
        .update({
          [`entitlements/${uid}`]:
            {
              ...entitlement,

              verifiedBadge:
                false,

              verifiedPlan:
                "none",

              subscriptionActive:
                false,

              expiresAtMs:
                t,

              source:
                `payment_${status}`,

              updatedAtMs:
                t,

              requiresBackendValidatedReceiptForReactivation:
                true,
            },

          [`subscription_events/${uid}/${eventId}`]:
            {
              eventId,

              uid,

              type:
                "payment_reversed",

              requestId,

              paymentStatus:
                status,

              createdAtMs:
                t,

              immutable:
                true,
            },
        });
    } else {
      await appendAudit(
        "subscription_reversal_manual_review",
        {
          targetUid:
            uid,

          referenceId:
            requestId,

          status,
        }
      );
    }
  }

  if (
    payment.type ===
    "boost"
  ) {
    const boostSnap =
      await db
        .ref(
          `boosts/${requestId}`
        )
        .get();

    const boost =
      map(
        boostSnap.val()
      );

    const productId =
      safe(
        boost.productId
      );

    const updates = {
      [`boosts/${requestId}/status`]:
        "payment_reversed",

      [`boosts/${requestId}/paymentStatus`]:
        status,

      [`boosts/${requestId}/updatedAtMs`]:
        t,

      [`boost_requests/${requestId}/status`]:
        "payment_reversed",

      [`boost_requests/${requestId}/updatedAtMs`]:
        t,
    };

    if (productId) {
      const cardSnap =
        await db
          .ref(
            `active_boost_cards/${productId}`
          )
          .get();

      if (
        safe(
          map(
            cardSnap.val()
          ).boostId
        ) === requestId
      ) {
        updates[
          `active_boost_cards/${productId}`
        ] =
          null;
      }
    }

    const eventId =
      firebaseSafeKey(
        `reversed_${requestId}_${status}`
      );

    updates[
      `boost_events/${requestId}/${eventId}`
    ] = {
      eventId,

      boostId:
        requestId,

      ownerUid:
        uid,

      productId,

      type:
        "payment_reversed",

      paymentStatus:
        status,

      createdAtMs:
        t,

      immutable:
        true,
    };

    await db
      .ref()
      .update(
        updates
      );
  }

  await db
    .ref()
    .update({
      [`payments/${requestId}/fulfillmentStatus`]:
        "revoked",

      [`payments/${requestId}/updatedAtMs`]:
        t,

      [`payment_requests/${uid}/${requestId}/status`]:
        "payment_reversed",

      [`payment_requests/${uid}/${requestId}/updatedAtMs`]:
        t,
    });

  await bestEffort(
    "payment-reversed-notification",
    () => pushNotification(
    uid,
    {
      title:
        "Pagamento revertido",

      body:
        "Um pagamento foi revertido e o benefício digital relacionado foi desativado ou enviado para revisão.",

      type:
        "payment_reversed",

      data: {
        requestId,
      },
    }
  )
  );
}

async function acquirePaymentProcessingLock(
  requestId,
  eventId
) {
  const ref = db.ref(
    `payment_processing/${requestId}/${eventId}`
  );
  const t = nowMs();

  const result = await ref.transaction(
    (current) => {
      const value = map(current);
      const status = safe(value.status);
      const startedAtMs = finiteNumber(
        value.startedAtMs,
        0
      );

      if (status === "done") {
        return;
      }

      if (
        status === "processing" &&
        startedAtMs > 0 &&
        t - startedAtMs <
          PAYMENT_PROCESSING_LOCK_TTL_MS
      ) {
        return;
      }

      return {
        status: "processing",
        startedAtMs: t,
        updatedAtMs: t,
      };
    },
    undefined,
    false
  );

  return {
    acquired: result.committed === true,
    ref,
  };
}

async function markPaymentProcessingDone(
  ref
) {
  await ref.set({
    status: "done",
    completedAtMs: nowMs(),
    updatedAtMs: nowMs(),
  });
}

async function markPaymentProcessingRetryable(
  ref
) {
  await ref.set({
    status: "retryable_error",
    updatedAtMs: nowMs(),
  });
}

function validateMercadoPagoWebhookSignature(req) {
  if (!MP_WEBHOOK_SECRET) {
    if (
      NODE_ENV === "production" &&
      MP_ACCESS_TOKEN
    ) {
      const error = new Error(
        "MERCADO_PAGO_WEBHOOK_SECRET_REQUIRED"
      );
      error.statusCode = 503;
      throw error;
    }

    return true;
  }

  const dataId = safe(
    req.query["data.id"] ||
      req.body?.data?.id ||
      req.body?.["data.id"]
  );

  const xSignature = safe(
    req.headers["x-signature"]
  );
  const xRequestId = safe(
    req.headers["x-request-id"]
  );

  if (
    !dataId ||
    !xSignature ||
    !xRequestId
  ) {
    const error = new Error(
      "INVALID_MERCADO_PAGO_WEBHOOK_SIGNATURE"
    );
    error.statusCode = 401;
    throw error;
  }

  try {
    WebhookSignatureValidator.validate({
      xSignature,
      xRequestId,
      dataId,
      secret: MP_WEBHOOK_SECRET,
    });
  } catch (error) {
    if (
      error instanceof
        InvalidWebhookSignatureError
    ) {
      const signatureError = new Error(
        "INVALID_MERCADO_PAGO_WEBHOOK_SIGNATURE"
      );
      signatureError.statusCode = 401;
      throw signatureError;
    }

    throw error;
  }

  return true;
}

async function processMercadoPagoWebhookPayment(
  paymentId
) {
  const detail = await fetchMercadoPagoPayment(
    paymentId
  );
  const requestId = safe(
    detail.external_reference
  );

  if (!requestId) {
    await bestEffort(
      "payment-webhook-missing-reference-audit",
      () =>
        appendAudit(
          "payment_webhook_ignored",
          {
            referenceId: safe(paymentId),
            status: "missing_external_reference",
          }
        )
    );
    return;
  }

  const paymentSnap = await db
    .ref(`payments/${requestId}`)
    .get();

  if (!paymentSnap.exists()) {
    await bestEffort(
      "payment-webhook-unknown-request-audit",
      () =>
        appendAudit(
          "payment_webhook_ignored",
          {
            referenceId: requestId,
            status: "unknown_request",
          }
        )
    );
    return;
  }

  const payment = map(paymentSnap.val());
  const uid = safe(payment.uid);
  const status = normalizePaymentStatus(
    detail.status
  );
  const amountCents = Math.round(
    finiteNumber(
      detail.transaction_amount,
      -1
    ) * 100
  );
  const currency = safe(
    detail.currency_id || "BRL"
  ).toUpperCase();
  const expectedAmount = integer(
    payment.amountCents,
    -1
  );
  const gatewayPaymentId = safe(
    detail.id || paymentId
  );
  const t = nowMs();
  const eventId = firebaseSafeKey(
    `${gatewayPaymentId}_${status}`
  );

  const lock = await acquirePaymentProcessingLock(
    requestId,
    eventId
  );

  if (!lock.acquired) {
    return;
  }

  let completed = false;

  try {
    const integrityOk =
      uid &&
      expectedAmount > 0 &&
      amountCents === expectedAmount &&
      currency === "BRL";

    if (!integrityOk) {
      await db.ref().update({
        [`payments/${requestId}/status`]:
          "integrity_error",
        [`payments/${requestId}/fulfillmentStatus`]:
          "blocked",
        [`payments/${requestId}/gatewayPaymentId`]:
          gatewayPaymentId,
        [`payments/${requestId}/updatedAtMs`]:
          t,
        [`payment_events/${requestId}/${eventId}`]:
          {
            eventId,
            type: "integrity_error",
            status,
            createdAtMs: t,
            immutable: true,
          },
      });

      await bestEffort(
        "payment-integrity-audit",
        () =>
          appendAudit(
            "payment_integrity_error",
            {
              targetUid: uid,
              referenceId: requestId,
              status: "blocked",
            }
          )
      );

      completed = true;
      return;
    }

    await db.ref().update({
      [`payments/${requestId}/status`]:
        status,
      [`payments/${requestId}/gatewayPaymentId`]:
        gatewayPaymentId,
      [`payments/${requestId}/gatewayPreferenceId`]:
        safe(
          detail.metadata?.preference_id ||
            payment.gatewayPreferenceId
        ),
      [`payments/${requestId}/updatedAtMs`]:
        t,
      [`payment_requests/${uid}/${requestId}/paymentStatus`]:
        status,
      [`payment_requests/${uid}/${requestId}/gatewayPaymentId`]:
        gatewayPaymentId,
      [`payment_requests/${uid}/${requestId}/updatedAtMs`]:
        t,
      [`payment_events/${requestId}/${eventId}`]:
        {
          eventId,
          type: "gateway_status",
          status,
          gatewayPaymentId,
          createdAtMs: t,
          immutable: true,
        },
    });

    await appendFinancialLedgerEvent({
      uid,
      requestId,
      gatewayPaymentId,
      amountCents,
      status,
      type:
        `mercado_pago_${safe(payment.type)}`,
    });

    if (status === "approved") {
      if (payment.type === "verification") {
        await activateVerificationFromPayment(
          payment,
          detail,
          t
        );
      } else if (payment.type === "boost") {
        await activateBoostFromPayment(
          payment,
          detail,
          t
        );
      }
    } else if (
      !["pending", "in_process"].includes(
        status
      )
    ) {
      if (
        [
          "refunded",
          "charged_back",
          "cancelled",
        ].includes(status)
      ) {
        await revokeFulfillmentForPayment(
          payment,
          status,
          t
        );
      } else {
        const updates = {
          [`payments/${requestId}/fulfillmentStatus`]:
            "not_fulfilled",
          [`payment_requests/${uid}/${requestId}/status`]:
            "payment_failed",
          [`payment_requests/${uid}/${requestId}/updatedAtMs`]:
            t,
        };

        if (payment.type === "boost") {
          updates[
            `boost_requests/${requestId}/status`
          ] = "payment_failed";
          updates[
            `boost_requests/${requestId}/updatedAtMs`
          ] = t;
        }

        await db.ref().update(updates);
      }
    }

    completed = true;
  } finally {
    if (completed) {
      await markPaymentProcessingDone(
        lock.ref
      );
    } else {
      await bestEffort(
        "payment-processing-retryable",
        () =>
          markPaymentProcessingRetryable(
            lock.ref
          )
      );
    }
  }
}
function extractWebhookPaymentId(
  req
) {
  const body =
    map(
      req.body
    );

  const type =
    safe(
      body.type ||
        body.topic ||
        req.query.type ||
        req.query.topic
    ).toLowerCase();

  const id =
    safe(
      body.data?.id ||
        body["data.id"] ||
        req.query["data.id"] ||
        req.query.id
    );

  return type ===
    "payment"
    ? id
    : "";
}

async function handleMercadoPagoWebhook(
  req,
  res,
  wantsJson
) {
  try {
    validateMercadoPagoWebhookSignature(req);

    const id = extractWebhookPaymentId(req);

    if (id) {
      await processMercadoPagoWebhookPayment(id);
    }

    if (wantsJson) {
      return res.status(200).json({
        ok: true,
      });
    }

    return res.status(200).send("ok");
  } catch (error) {
    const statusCode =
      error?.statusCode === 401
        ? 401
        : error?.statusCode === 503
          ? 503
          : 500;

    console.error(
      "Mercado Pago webhook:",
      error?.message || "webhook_error"
    );

    if (wantsJson) {
      return res.status(statusCode).json({
        ok: false,
        code:
          statusCode === 401
            ? "INVALID_WEBHOOK_SIGNATURE"
            : statusCode === 503
              ? "WEBHOOK_NOT_CONFIGURED"
              : "WEBHOOK_ERROR",
      });
    }

    return res
      .status(statusCode)
      .send(
        statusCode === 401
          ? "unauthorized"
          : "webhook error"
      );
  }
}

// Mantido para compatibilidade. Em produção, também exige assinatura válida.
app.get(
  "/api/mercadopago/webhook",
  (req, res) =>
    handleMercadoPagoWebhook(
      req,
      res,
      false
    )
);

app.post(
  "/api/mercadopago/webhook",
  (req, res) =>
    handleMercadoPagoWebhook(
      req,
      res,
      true
    )
);


const professionalUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 12 * 1024 * 1024, files: 3, fields: 30 },
}).fields([
  { name: "documentFront", maxCount: 1 },
  { name: "documentBack", maxCount: 1 },
  { name: "selfie", maxCount: 1 },
]);


function requireAdmin(req, res, next) {
  if (req.auth?.admin === true) return next();
  return res.status(403).json({
    ok: false,
    code: "ADMIN_CLAIM_REQUIRED",
    message: "Acesso administrativo exige custom claim admin=true."
  });
}
function ageFromBirthDate(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(safe(value));
  if (!m) return -1;
  const b = new Date(Number(m[1]), Number(m[2])-1, Number(m[3]));
  if (Number.isNaN(b.getTime())) return -1;
  const n = new Date(); let age=n.getFullYear()-b.getFullYear();
  const before=n.getMonth()<b.getMonth() || (n.getMonth()===b.getMonth() && n.getDate()<b.getDate());
  return age-(before?1:0);
}

async function uploadIdentityFile(uid, role, applicationId, label, file) {
  if (!file?.buffer?.length) throw Object.assign(new Error("DOCUMENT_REQUIRED"), {statusCode:422, publicMessage:"Envie todos os documentos obrigatórios."});
  const folder=`firerank/private/identity/${uid}/${role}/${applicationId}`;
  const result=await cloudinaryUploadBuffer(file.buffer,{folder, publicId:label, type:"authenticated"});
  return {provider:"cloudinary", publicId:result.public_id, version:result.version, resourceType:"image", type:"authenticated", bytes:result.bytes||file.size||0, format:result.format||""};
}

async function loadIdentityMediaAsset(uid, role, assetId, label) {
  const cleanId = safe(assetId);
  if (!cleanId) {
    const error = new Error("DOCUMENT_REQUIRED");
    error.statusCode = 422;
    error.publicMessage = "Envie todos os documentos obrigatórios.";
    throw error;
  }
  const purpose = role === "seller" ? "seller_identity" : "delivery_identity";
  const snap = await db.ref(`media_assets/${uid}/${cleanId}`).get();
  const asset = map(snap.val());
  if (!snap.exists() || safe(asset.ownerUid) !== uid || safe(asset.purpose) !== purpose || safe(asset.status) !== "ready" || safe(asset.type) !== "authenticated") {
    const error = new Error("IDENTITY_MEDIA_INVALID");
    error.statusCode = 403;
    error.publicMessage = "Um dos documentos enviados não pôde ser validado.";
    throw error;
  }
  return {
    provider:"cloudinary", assetId:cleanId, publicId:safe(asset.publicId),
    version:asset.version||0, resourceType:"image", type:"authenticated",
    bytes:integer(asset.bytes,0), format:safe(asset.format), label,
  };
}

async function handleProfessionalApplication(role, req, res) {
  try {
    const uid=req.auth.uid; const body=req.body||{}; const t=nowMs();
    const age=ageFromBirthDate(body.birthDate);
    if (age < 18) return res.status(422).json({ok:false,code:"AGE_NOT_ELIGIBLE",message:"É necessário ter 18 anos ou mais."});
    if (!safe(body.fullName) || !safe(body.cpf) || !safe(body.phone) || !safe(body.city) || !safe(body.state)) return res.status(422).json({ok:false,code:"REQUIRED_FIELDS",message:"Preencha todos os dados obrigatórios."});
    if (!bool(body.termsAccepted) || !bool(body.dataProcessingAccepted)) return res.status(422).json({ok:false,code:"CONSENT_REQUIRED",message:"Aceite os termos e o tratamento de dados."});
    const appRef=db.ref(`application_history/${uid}/${role}`).push(); const applicationId=appRef.key;
    const files=req.files||{};
    const directMedia = safe(body.documentFrontMediaId) && safe(body.documentBackMediaId) && safe(body.selfieMediaId);
    const [front,back,selfie]=directMedia
      ? await Promise.all([
          loadIdentityMediaAsset(uid,role,body.documentFrontMediaId,"document_front"),
          loadIdentityMediaAsset(uid,role,body.documentBackMediaId,"document_back"),
          loadIdentityMediaAsset(uid,role,body.selfieMediaId,"selfie"),
        ])
      : await Promise.all([
          uploadIdentityFile(uid,role,applicationId,"document_front",files.documentFront?.[0]),
          uploadIdentityFile(uid,role,applicationId,"document_back",files.documentBack?.[0]),
          uploadIdentityFile(uid,role,applicationId,"selfie",files.selfie?.[0]),
        ]);
    const common={applicationId,uid,role,status:"pending",fullName:clip(body.fullName,120),birthDate:safe(body.birthDate),phone:clip(body.phone,32),city:clip(body.city,100),state:clip(body.state,8),createdAtMs:t,updatedAtMs:t,source:clip(body.source,40)};
    const roleData=role==="seller"?{storeName:clip(body.storeName,120),sellerBio:clip(body.sellerBio,500)}:{vehicleType:clip(body.vehicleType,60),vehiclePlate:clip(body.vehiclePlate,16)};
    const privateData={cpf:clip(body.cpf,20),documents:{documentFront:front,documentBack:back,selfie}};
    const updates={
      [`current_applications/${role}/${uid}`]:{...common,...roleData},
      [`application_history/${uid}/${role}/${applicationId}`]:{...common,...roleData,immutable:true},
      [`identity_private/${uid}/applications/${role}/${applicationId}`]:privateData,
      [`role_state/${uid}/${role}`]:{active:false,accessEnabled:false,applicationOpen:true,uiState:"pending",updatedAtMs:t},
    };
    if (role==="seller") updates[`admin_seller_requests/${uid}`]={...common,...roleData};
    else { updates[`admin_delivery_requests/${uid}`]={...common,...roleData}; updates[`delivery_private_profiles/${uid}`]={...roleData,phone:common.phone,city:common.city,state:common.state,status:"pending",updatedAtMs:t}; }
    await db.ref().update(updates); await appendAudit(`${role}_application_submitted`,{actorUid:uid,targetUid:uid,referenceId:applicationId,status:"pending"});
    return res.status(201).json({ok:true,applicationId,status:"pending"});
  } catch(e){ return publicError(res,e,"Não foi possível enviar o cadastro."); }
}

app.post("/v1/applications/seller", requireUser, rateLimit("seller-application",3,60*60*1000), professionalUpload, (req,res)=>handleProfessionalApplication("seller",req,res));
app.post("/v1/applications/delivery", requireUser, rateLimit("delivery-application",3,60*60*1000), professionalUpload, (req,res)=>handleProfessionalApplication("delivery",req,res));

async function ensureDeliveryPublicCode(uid) {
  const existingSnap = await db.ref(`delivery_public_profiles/${uid}/publicCode`).get();
  const existing = safe(existingSnap.val()).toUpperCase();
  if (existing) return existing;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const suffix = crypto.randomBytes(5).toString("hex").slice(0, 8).toUpperCase();
    const code = `FRD-${suffix}`;
    const codeRef = db.ref(`delivery_public_codes/${firebaseSafeKey(code)}`);
    const tx = await codeRef.transaction((value) => value ? undefined : uid, {applyLocally:false});
    if (tx.committed && tx.snapshot.val() === uid) return code;
  }
  const error = new Error("DELIVERY_CODE_GENERATION_FAILED");
  error.statusCode = 503;
  error.publicMessage = "Não foi possível gerar o código público do entregador.";
  throw error;
}

app.post("/v1/admin/applications/:role/:uid/decision", requireUser, requireAdmin, async(req,res)=>{
  try{
    const role=safe(req.params.role).toLowerCase();
    const uid=safe(req.params.uid);
    const rawDecision=safe(req.body?.decision).toLowerCase();
    const decisionMap={approve:"approved",approved:"approved",reject:"rejected",rejected:"rejected",suspend:"suspended",suspended:"suspended",reactivate:"reactivated",reactivated:"reactivated",reopen:"reopened",reopened:"reopened",under_review:"reopened",pending:"reopened"};
    const decision=decisionMap[rawDecision]||"";
    const t=nowMs();
    if(!["seller","delivery"].includes(role)||!decision) return res.status(422).json({ok:false,code:"INVALID_DECISION",message:"Decisão administrativa inválida."});

    const currentSnap=await db.ref(`current_applications/${role}/${uid}`).get();
    const cur=map(currentSnap.val());
    const activating=decision==="approved"||decision==="reactivated";
    const suspended=decision==="suspended";
    const rejected=decision==="rejected";
    const reopened=decision==="reopened";
    const status=activating?"approved":reopened?"pending":decision;
    const uiState=activating?"active":reopened?"pending":decision;
    const deliveryPublicCode = role === "delivery" && activating ? await ensureDeliveryPublicCode(uid) : "";
    const updates={
      [`role_state/${uid}/${role}/active`]:activating,
      [`role_state/${uid}/${role}/accessEnabled`]:activating,
      [`role_state/${uid}/${role}/applicationOpen`]:reopened,
      [`role_state/${uid}/${role}/status`]:status,
      [`role_state/${uid}/${role}/uiState`]:uiState,
      [`role_state/${uid}/${role}/canReapply`]:rejected,
      [`role_state/${uid}/${role}/updatedAtMs`]:t,
      [`eligibility/${uid}/${role==="seller"?"canSell":"canDeliver"}`]:activating,
      [`eligibility/${uid}/updatedAtMs`]:t,
    };

    if(activating){
      updates[`user_roles/${uid}/${role}`]=true;
      updates[`eligibility/${uid}/needsAgeReview`]=false;
      if(safe(cur.applicationId)){
        updates[`identity_status/${uid}/identityReviewStatus`]="approved";
        updates[`identity_status/${uid}/source`]=`${role}_application`;
        updates[`identity_status/${uid}/reviewedAtMs`]=t;
        updates[`identity_status/${uid}/reviewedBy`]=req.auth.uid;
        updates[`eligibility/${uid}/canSubscribeVerified`]=true;
      }
    } else if(rejected||reopened||suspended){
      updates[`user_roles/${uid}/${role}`]=false;
    }

    if(currentSnap.exists){
      updates[`current_applications/${role}/${uid}/status`]=status;
      updates[`current_applications/${role}/${uid}/updatedAtMs`]=t;
    }

    if(role==="seller"){
      updates[`admin_seller_requests/${uid}/status`]=status;
      updates[`admin_seller_requests/${uid}/updatedAtMs`]=t;
      if(activating){
        const storesByUser=map((await db.ref(`stores_by_user/${uid}`).get()).val());
        let storeId=safe(cur.storeId)||Object.keys(storesByUser)[0]||`store_${uid}`;
        const storeName=clip(cur.storeName||"Minha Loja",120);
        updates[`stores_by_user/${uid}/${storeId}`]=true;
        updates[`store_members/${storeId}/${uid}`]={role:"owner",active:true,updatedAtMs:t};
        updates[`stores/${storeId}/storeId`]=storeId;
        updates[`stores/${storeId}/ownerUid`]=uid;
        updates[`stores/${storeId}/name`]=storeName;
        updates[`stores/${storeId}/status`]="approved";
        updates[`stores/${storeId}/visibility`]="public";
        updates[`stores/${storeId}/updatedAtMs`]=t;
        if(!storesByUser[storeId]) updates[`stores/${storeId}/createdAtMs`]=t;
      }
    } else {
      updates[`admin_delivery_requests/${uid}/status`]=status;
      updates[`admin_delivery_requests/${uid}/updatedAtMs`]=t;
      updates[`delivery_public_profiles/${uid}/status`]=activating?"active":suspended?"suspended":reopened?"pending":"rejected";
      updates[`delivery_public_profiles/${uid}/updatedAtMs`]=t;
      if (deliveryPublicCode) {
        updates[`delivery_public_profiles/${uid}/publicCode`]=deliveryPublicCode;
        updates[`delivery_public_codes/${firebaseSafeKey(deliveryPublicCode)}`]=uid;
      } else {
        const currentCode=safe((await db.ref(`delivery_public_profiles/${uid}/publicCode`).get()).val()).toUpperCase();
        if(currentCode) updates[`delivery_public_codes/${firebaseSafeKey(currentCode)}`]=null;
      }
    }

    const decisionRef=db.ref(`application_decisions/${uid}/${role}`).push();
    updates[`application_decisions/${uid}/${role}/${decisionRef.key}`]={decision,status,actorUid:req.auth.uid,applicationId:safe(cur.applicationId),reason:clip(req.body?.reason,500),createdAtMs:t};
    await db.ref().update(updates);
    await appendAudit(`${role}_${decision}`,{actorUid:req.auth.uid,targetUid:uid,referenceId:cur.applicationId||"",status});
    await pushNotification(uid,{title:activating?"Cadastro aprovado":suspended?"Acesso suspenso":reopened?"Cadastro reaberto":"Cadastro analisado",body:activating?`Seu acesso de ${role==="seller"?"vendedor":"entregador"} foi liberado.`:suspended?"Seu acesso foi suspenso pela equipe FireRank.":reopened?"Seu cadastro voltou para análise.":"Sua solicitação não foi aprovada.",type:`${role}_${decision}`});
    return res.json({ok:true,role,uid,status,decision});
  }catch(e){return publicError(res,e,"Não foi possível concluir a análise.");}
});

app.post("/v1/account/privacy", requireUser, rateLimit("account-privacy",12,60*60*1000), async(req,res)=>{
  try{
    const uid=req.auth.uid, visibility=safe(req.body?.visibility).toLowerCase(), t=nowMs();
    if(!["public","private"].includes(visibility)) return res.status(422).json({ok:false,code:"INVALID_VISIBILITY",message:"Privacidade inválida."});

    const updates={
      [`account_visibility/${uid}`]:visibility,
      [`public_users/${uid}/accountVisibility`]:visibility,
      [`public_users/${uid}/updatedAtMs`]:t,
    };

    const productsSnap=await db.ref("products").orderByChild("ownerUid").equalTo(uid).get();
    productsSnap.forEach(child=>{
      const product=map(child.val());
      const productId=child.key;
      const categoryId=safe(product.categoryId);
      const isPublishable=product.status==="active" && safe(product.visibility||"public")==="public" && safe(product.moderation?.status||"approved")==="approved" && finiteNumber(product.lifecycle?.deletedAtMs,0)===0;

      if(visibility==="private" || !isPublishable){
        updates[`product_cards/${productId}`]=null;
        updates[`feed_index/${productId}`]=null;
        updates[`search_index_basic/${productId}`]=null;
        updates[`active_boost_cards/${productId}`]=null;
        if(categoryId) updates[`category_index/${categoryId}/${productId}`]=null;
        return;
      }

      const pricing=map(product.pricing);
      const media=map(product.media);
      const card={
        productId,
        ownerUid:uid,
        storeId:safe(product.storeId),
        categoryId,
        title:clip(product.title,180),
        productType:safe(product.productType),
        coverUrl:safe(media.coverUrl),
        priceCents:integer(pricing.priceCents,0),
        currency:safe(pricing.currency)||"BRL",
        createdAtMs:finiteNumber(product.lifecycle?.createdAtMs,t),
        updatedAtMs:t,
        accountVisibility:"public",
      };
      updates[`product_cards/${productId}`]=card;
      updates[`feed_index/${productId}`]={productId,createdAtMs:card.createdAtMs,score:0};
      updates[`search_index_basic/${productId}`]={productId,title:card.title.toLowerCase(),categoryId,storeId:card.storeId,ownerUid:uid,updatedAtMs:t};
      if(categoryId) updates[`category_index/${categoryId}/${productId}`]={productId,createdAtMs:card.createdAtMs,score:0};
    });

    await db.ref().update(updates);
    await appendAudit("account_privacy_changed",{actorUid:uid,targetUid:uid,status:visibility});
    return res.json({ok:true,visibility});
  }catch(e){return publicError(res,e,"Não foi possível alterar a privacidade.");}
});

app.post("/v1/support/chat", requireUser, rateLimit("support-chat",15,60*60*1000), async(req,res)=>{
  try{
    const uid=req.auth.uid,t=nowMs(); const ent=map((await db.ref(`entitlements/${uid}`).get()).val());
    const active=ent.subscriptionActive===true && (!finiteNumber(ent.expiresAtMs,0)||finiteNumber(ent.expiresAtMs,0)>t); const plan=safe(ent.verifiedPlan).replace(/^verified_/,"").toLowerCase();
    if(!active || !["plus","pro"].includes(plan)) return res.status(403).json({ok:false,code:"SUPPORT_ENTITLEMENT_REQUIRED",message:"O chat humano é exclusivo dos planos Plus e Pro."});
    const existing=safe((await db.ref(`support_active_by_user/${uid}`).get()).val()); const chatId=existing||`support_${uid}`; const otherUid="firerank_support";
    const priority=plan==="pro"?"highest":"priority";
    await db.ref().update({
      [`chats/${chatId}`]:{chatId,type:"support",participants:{[uid]:true,[otherUid]:true},ownerUid:uid,status:"open",priority,createdAtMs:t,updatedAtMs:t},
      [`chats_by_user/${uid}/${chatId}`]:{chatId,type:"support",otherUid,updatedAtMs:t,lastMessageAtMs:t},
      [`support_tickets/${uid}/${chatId}`]:{ticketId:chatId,uid,chatId,status:"open",plan,priority,createdAtMs:t,updatedAtMs:t},
      [`support_admin_index/${chatId}`]:{ticketId:chatId,uid,chatId,status:"open",plan,priority,createdAtMs:t,updatedAtMs:t},
      [`support_active_by_user/${uid}`]:chatId,
    });
    return res.json({ok:true,chatId,otherUid,priority});
  }catch(e){return publicError(res,e,"Não foi possível abrir o atendimento.");}
});



// ============================================================================
// FIRE RANK ADMIN - HOME CAROUSEL
// Backend-authoritative banner media + banner mutations.
// ============================================================================

app.post(
  "/v1/admin/media/banner/sign",
  requireUser,
  requireAdmin,
  rateLimit("admin-banner-media-sign", 20, 10 * 60 * 1000),
  async (req, res) => {
    try {
      if (!CLOUDINARY_CONFIGURED || !CLOUDINARY_API_SECRET) {
        return res.status(503).json({
          ok: false,
          code: "CLOUDINARY_NOT_CONFIGURED",
          message: "Servico de midia indisponivel."
        });
      }

      const adminUid = req.auth.uid;
      const timestamp = Math.floor(Date.now() / 1000);
      const nonce = crypto.randomBytes(10).toString("hex");

      const folder =
        "firerank/home_banners/" + adminUid;

      const publicId =
        "home_banner_" + timestamp + "_" + nonce;

      const type = "upload";

      const paramsToSign = {
        timestamp,
        folder,
        public_id: publicId,
        type
      };

      const signature =
        cloudinary.utils.api_sign_request(
          paramsToSign,
          CLOUDINARY_API_SECRET
        );

      return res.json({
        ok: true,
        provider: "cloudinary",
        cloudName: CLOUDINARY_CLOUD_NAME,
        apiKey: CLOUDINARY_API_KEY,
        timestamp,
        signature,
        folder,
        publicId,
        type,
        resourceType: "image",
        uploadUrl:
          "https://api.cloudinary.com/v1_1/" +
          CLOUDINARY_CLOUD_NAME +
          "/image/upload",
        expiresInSeconds: 300
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "Nao foi possivel autorizar o banner."
      );
    }
  }
);

app.post(
  "/v1/admin/media/banner/complete",
  requireUser,
  requireAdmin,
  rateLimit("admin-banner-media-complete", 30, 10 * 60 * 1000),
  async (req, res) => {
    try {
      if (!CLOUDINARY_CONFIGURED || !CLOUDINARY_API_SECRET) {
        return res.status(503).json({
          ok: false,
          code: "CLOUDINARY_NOT_CONFIGURED",
          message: "Servico de midia indisponivel."
        });
      }

      const adminUid = req.auth.uid;
      const publicId = safe(req.body?.publicId);
      const requestedType =
        safe(req.body?.type).toLowerCase();

      if (!publicId) {
        return res.status(422).json({
          ok: false,
          code: "PUBLIC_ID_REQUIRED"
        });
      }

      const expectedPrefix =
        "firerank/home_banners/" +
        adminUid +
        "/";

      if (!publicId.startsWith(expectedPrefix)) {
        return res.status(403).json({
          ok: false,
          code: "BANNER_MEDIA_OWNER_MISMATCH"
        });
      }

      const expectedType = "upload";

      if (
        requestedType &&
        requestedType !== expectedType
      ) {
        return res.status(422).json({
          ok: false,
          code: "BANNER_MEDIA_TYPE_MISMATCH"
        });
      }

      const resource =
        await cloudinary.api.resource(
          publicId,
          {
            resource_type: "image",
            type: expectedType
          }
        );

      const bytes = integer(resource?.bytes, 0);
      const width = integer(resource?.width, 0);
      const height = integer(resource?.height, 0);

      const maxBytes = 5 * 1024 * 1024;

      if (
        !resource?.public_id ||
        bytes <= 0 ||
        bytes > maxBytes ||
        width < 400 ||
        height < 400 ||
        width > 1600 ||
        height > 1600 ||
        Math.abs(width - height) > 2
      ) {
        return res.status(422).json({
          ok: false,
          code: "BANNER_MEDIA_INVALID",
          message:
            "O banner deve ser quadrado, ter dimensoes seguras e no maximo 5 MB."
        });
      }

      const t = nowMs();

      const mediaRef =
        db.ref(
          "media_assets/" + adminUid
        ).push();

      const assetId = mediaRef.key;

      const asset = {
        assetId,
        ownerUid: adminUid,
        purpose: "home_banner",
        provider: "cloudinary",
        publicId: resource.public_id,
        resourceType: "image",
        type: expectedType,
        version: resource.version || 0,
        bytes,
        format: safe(resource.format),
        width,
        height,
        secureUrl: safe(resource.secure_url),
        createdAtMs: t,
        status: "ready"
      };

      await mediaRef.set(asset);

      await appendAudit(
        "home_banner_media_uploaded",
        {
          actorUid: adminUid,
          targetUid: adminUid,
          referenceId: assetId,
          status: "ready"
        }
      );

      return res.status(201).json({
        ok: true,
        mediaId: assetId,
        assetId,
        publicId: resource.public_id,
        type: expectedType,
        secureUrl: safe(resource.secure_url),
        width,
        height,
        bytes
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "Nao foi possivel confirmar o banner."
      );
    }
  }
);

app.post(
  "/v1/admin/banners/upsert",
  requireUser,
  requireAdmin,
  rateLimit("admin-banner-upsert", 60, 60 * 60 * 1000),
  async (req, res) => {
    try {
      const adminUid = req.auth.uid;
      const body = map(req.body);
      const t = nowMs();

      let bannerId = safe(body.bannerId);

      if (!bannerId) {
        bannerId =
          db.ref("public_home_banners").push().key;
      }

      if (
        !bannerId ||
        /[.#$\[\]\/]/.test(bannerId)
      ) {
        return res.status(422).json({
          ok: false,
          code: "INVALID_BANNER_ID"
        });
      }

      const title = clip(body.title, 120);
      const imageUrl = safe(body.imageUrl);

      if (
        !imageUrl ||
        imageUrl.length > 2048 ||
        !isHttpsUrl(imageUrl)
      ) {
        return res.status(422).json({
          ok: false,
          code: "INVALID_BANNER_IMAGE",
          message: "Use uma imagem HTTPS valida."
        });
      }

      let actionType =
        safe(body.actionType).toLowerCase();

      let actionValue =
        safe(body.actionValue);

      const targetUrl = safe(body.targetUrl);

      if (!actionType && targetUrl) {
        if (isHttpsUrl(targetUrl)) {
          actionType = "external_url";
          actionValue = targetUrl;
        } else {
          const match =
            targetUrl.match(
              /^(product|store|profile):(.+)$/i
            );

          if (match) {
            actionType =
              match[1].toLowerCase();

            actionValue =
              safe(match[2]);
          }
        }
      }

      const allowedActions =
        new Set([
          "external_url",
          "store",
          "product",
          "profile"
        ]);

      if (
        !allowedActions.has(actionType) ||
        !actionValue ||
        actionValue.length > 2048
      ) {
        return res.status(422).json({
          ok: false,
          code: "INVALID_BANNER_ACTION",
          message:
            "Escolha um destino valido para o banner."
        });
      }

      if (
        actionType === "external_url" &&
        !isHttpsUrl(actionValue)
      ) {
        return res.status(422).json({
          ok: false,
          code: "INVALID_EXTERNAL_URL",
          message:
            "Links externos devem usar HTTPS."
        });
      }

      const enabled =
        typeof body.enabled === "boolean"
          ? body.enabled
          : body.active === true;

      const sponsored =
        body.sponsored === true;

      const label =
        clip(body.label, 80);

      const startsAtMs =
        Math.max(
          0,
          integer(body.startsAtMs, 0)
        );

      const endsAtMs =
        Math.max(
          0,
          integer(body.endsAtMs, 0)
        );

      if (
        startsAtMs > 0 &&
        endsAtMs > 0 &&
        endsAtMs <= startsAtMs
      ) {
        return res.status(422).json({
          ok: false,
          code: "INVALID_BANNER_PERIOD",
          message:
            "A data final deve ser posterior a data inicial."
        });
      }

      const currentSnap =
        await db.ref(
          "public_home_banners/" +
          bannerId
        ).get();

      const current =
        map(currentSnap.val());

      let sortOrder =
        integer(body.sortOrder, 0);

      if (sortOrder <= 0) {
        const allSnap =
          await db
            .ref("public_home_banners")
            .limitToLast(20)
            .get();

        let highest = 0;

        if (allSnap.exists()) {
          for (
            const value of Object.values(
              map(allSnap.val())
            )
          ) {
            highest = Math.max(
              highest,
              integer(
                map(value).sortOrder,
                0
              )
            );
          }
        }

        sortOrder =
          integer(
            current.sortOrder,
            highest + 1
          );

        if (sortOrder <= 0) {
          sortOrder = highest + 1;
        }
      }

      const createdAtMs =
        integer(
          current.createdAtMs,
          t
        );

      const publicBanner = {
        id: bannerId,
        bannerId,
        title,
        imageUrl,
        actionType,
        actionValue,
        enabled,
        sponsored,
        label,
        sortOrder,
        startsAtMs,
        endsAtMs,
        createdAtMs,
        updatedAtMs: t
      };

      const adminBanner = {
        ...publicBanner,
        targetUrl: actionValue,
        position:
          safe(body.position) || "home",
        active: enabled
      };

      await db.ref().update({
        ["public_home_banners/" + bannerId]:
          publicBanner,
        ["home_banners/" + bannerId]:
          adminBanner
      });

      await appendAudit(
        currentSnap.exists()
          ? "carousel_banner_updated"
          : "carousel_banner_created",
        {
          actorUid: adminUid,
          targetUid: adminUid,
          referenceId: bannerId,
          status:
            enabled
              ? "active"
              : "disabled"
        }
      );

      return res
        .status(
          currentSnap.exists()
            ? 200
            : 201
        )
        .json({
          ok: true,
          bannerId,
          banner: adminBanner
        });
    } catch (error) {
      return publicError(
        res,
        error,
        "Nao foi possivel salvar o banner."
      );
    }
  }
);

app.post(
  "/v1/admin/banners/:bannerId/archive",
  requireUser,
  requireAdmin,
  rateLimit("admin-banner-archive", 30, 60 * 60 * 1000),
  async (req, res) => {
    try {
      const adminUid = req.auth.uid;
      const bannerId =
        safe(req.params.bannerId);

      if (
        !bannerId ||
        /[.#$\[\]\/]/.test(bannerId)
      ) {
        return res.status(422).json({
          ok: false,
          code: "INVALID_BANNER_ID"
        });
      }

      if (req.body?.confirm !== true) {
        return res.status(422).json({
          ok: false,
          code: "CONFIRM_REQUIRED"
        });
      }

      const snap =
        await db.ref(
          "public_home_banners/" +
          bannerId
        ).get();

      if (!snap.exists()) {
        return res.status(404).json({
          ok: false,
          code: "BANNER_NOT_FOUND",
          message: "Banner nao encontrado."
        });
      }

      const t = nowMs();

      await db.ref().update({
        [
          "public_home_banners/" +
          bannerId +
          "/enabled"
        ]: false,

        [
          "public_home_banners/" +
          bannerId +
          "/updatedAtMs"
        ]: t,

        [
          "home_banners/" +
          bannerId +
          "/enabled"
        ]: false,

        [
          "home_banners/" +
          bannerId +
          "/active"
        ]: false,

        [
          "home_banners/" +
          bannerId +
          "/updatedAtMs"
        ]: t
      });

      await appendAudit(
        "carousel_banner_archived",
        {
          actorUid: adminUid,
          targetUid: adminUid,
          referenceId: bannerId,
          status: "disabled"
        }
      );

      return res.json({
        ok: true,
        bannerId,
        active: false
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "Nao foi possivel arquivar o banner."
      );
    }
  }
);


app.post(
  "/v1/admin/ai/chat",
  requireUser,
  requireAdmin,
  rateLimit("admin-ai-chat", 60, 60 * 60 * 1000),
  async (req, res) => {
    try {
      if (!GEMINI_API_KEY || !GEMINI_MODEL) {
        return res.status(503).json({
          ok: false,
          code: "AI_NOT_CONFIGURED",
          message: "FireRank Admin AI is not configured."
        });
      }

      const uid = req.auth.uid;

      const message = clip(
        req.body?.message || req.body?.text,
        6000
      );

      if (!message) {
        return res.status(422).json({
          ok: false,
          code: "MESSAGE_REQUIRED"
        });
      }

      const history = Array.isArray(req.body?.history)
        ? req.body.history.slice(-8)
        : [];

      const contents = [
        ...history.map((item) => ({
          role:
            safe(item.role) === "assistant"
              ? "model"
              : "user",
          parts: [
            {
              text: clip(item.text, 3000)
            }
          ]
        })),
        {
          role: "user",
          parts: [
            {
              text: message
            }
          ]
        }
      ];

      const url =
        "https://generativelanguage.googleapis.com/v1beta/models/" +
        encodeURIComponent(GEMINI_MODEL) +
        ":generateContent?key=" +
        encodeURIComponent(GEMINI_API_KEY);

      const geminiResponse = await axios.post(
        url,
        {
          contents,
          systemInstruction: {
            parts: [
              {
                text:
                  "You are FireRank AI Admin, the private administrative assistant for FireRank. " +
                  "Help the administrator understand users, sellers, deliveries, products, orders, reports, application behavior, database contracts and operational problems. " +
                  "You may diagnose and recommend actions. " +
                  "Never claim to have changed FireRank data unless an authorized backend operation actually performed the change. " +
                  "Never expose credentials, tokens, API keys, Firebase private keys or other secrets. " +
                  "Never autonomously modify payments, financial ledgers, Firebase admin claims, Firebase security rules, environment variables, deployments or credentials."
              }
            ]
          },
          generationConfig: {
            temperature: 0.3,
            maxOutputTokens: 1400
          }
        },
        {
          timeout: 30000
        }
      );

      const answer =
        safe(
          geminiResponse.data?.candidates?.[0]?.content?.parts
            ?.map((part) => part.text || "")
            .join("\n")
        ) || "No response was generated.";

      await appendAudit("admin_ai_chat", {
        actorUid: uid,
        targetUid: uid,
        status: "ok"
      });

      return res.json({
        ok: true,
        text: answer,
        answer
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "FireRank Admin AI could not respond."
      );
    }
  }
);

app.post("/v1/ai/v2/chat", requireUser, rateLimit("gemini-chat",30,60*60*1000), async(req,res)=>{
  try{
    if(!GEMINI_API_KEY || !GEMINI_MODEL) return res.status(503).json({ok:false,code:"AI_NOT_CONFIGURED",message:"A IA ainda não está configurada."});
    const uid=req.auth.uid,t=nowMs(); const message=clip(req.body?.message||req.body?.text,6000); if(!message) return res.status(422).json({ok:false,code:"MESSAGE_REQUIRED"});
    const ent=map((await db.ref(`entitlements/${uid}`).get()).val()); let quota=20; const plan=safe(ent.verifiedPlan).replace(/^verified_/,"").toLowerCase(); if(ent.subscriptionActive===true){if(plan==="plus")quota=100;if(plan==="pro")quota=300;}
    const day=new Date().toISOString().slice(0,10); const usageRef=db.ref(`ai_usage/${uid}/${day}`); const usage=map((await usageRef.get()).val()); const used=integer(usage.messages,0); if(used>=quota) return res.status(429).json({ok:false,code:"AI_DAILY_QUOTA",message:"Sua cota diária de IA foi atingida.",quota,used});
    const history=Array.isArray(req.body?.history)?req.body.history.slice(-6):[];
    const contents=[...history.map(x=>({role:safe(x.role)==="assistant"?"model":"user",parts:[{text:clip(x.text,3000)}]})),{role:"user",parts:[{text:message}]}];
    const url=`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
    const gr=await axios.post(url,{contents,systemInstruction:{parts:[{text:"Você é o FireRank AI. Ajude usuários do aplicativo FireRank com respostas úteis e seguras. Nunca afirme ter alterado pagamentos, permissões, cadastros ou banco de dados. Não peça nem exponha segredos."}]},generationConfig:{temperature:0.5,maxOutputTokens:900}},{timeout:30000});
    const answer=safe(gr.data?.candidates?.[0]?.content?.parts?.map(p=>p.text||"").join("\n"))||"Não consegui gerar uma resposta agora.";
    await usageRef.set({messages:used+1,quota,plan:plan||"normal",updatedAtMs:t});
    return res.json({ok:true,text:answer,answer,usage:{used:used+1,quota}});
  }catch(e){return publicError(res,e,"A IA não conseguiu responder agora.");}
});

app.post("/v1/analytics/banner", rateLimit("banner-analytics",120,60*60*1000), async(req,res)=>{
  try{const bannerId=clip(req.body?.bannerId,160),event=clip(req.body?.event||req.body?.type,40);if(!bannerId||!["impression","click"].includes(event))return res.status(422).json({ok:false});const ref=db.ref("home_banner_events").push();await ref.set({eventId:ref.key,bannerId,event,createdAtMs:nowMs(),clientPlatform:clip(req.body?.clientPlatform,40)});return res.status(202).json({ok:true});}catch(e){return publicError(res,e,"Evento não registrado.");}
});




// Conta oficial e benefícios por contrato são conceitos separados.
// O badge oficial sai em public_badges; Pro por contrato é opcional e auditável.
app.post('/v1/admin/official-accounts/grant', requireUser, requireAdmin, rateLimit('admin-official-grant', 30, 60 * 60 * 1000), async(req,res)=>{
  try{
    const adminUid=req.auth.uid,body=map(req.body),uid=safe(body.uid),t=nowMs();
    if(!uid)return res.status(422).json({ok:false,code:'UID_REQUIRED'});
    const [pubSnap,userSnap,entSnap]=await Promise.all([db.ref(`public_users/${uid}`).get(),db.ref(`users/${uid}`).get(),db.ref(`entitlements/${uid}`).get()]);
    const user={...map(userSnap.val()),...map(pubSnap.val())};
    if(!pubSnap.exists()&&!userSnap.exists())return res.status(404).json({ok:false,code:'USER_NOT_FOUND',message:'Conta não encontrada.'});
    const grantRef=db.ref(`partner_contracts/${uid}`).push(); const grantId=grantRef.key;
    const grantPro=bool(body.grantPro); const plan=grantPro?'pro':'normal'; const previousEntitlement=map(entSnap.val());
    const partnerName=clip(body.partnerName||user.displayName||user.username,120);
    const official={uid,official:true,active:true,entityType:clip(body.entityType||'account',40),storeId:clip(body.storeId,160),partnerName,displayName:clip(user.displayName,120),benefitPlan:grantPro?plan:'none',contractRef:clip(body.contractRef,160),note:clip(body.note,500),sourceGrantId:grantId,grantedByAdminUid:adminUid,createdAtMs:t,updatedAtMs:t};
    const updates={
      [`official_accounts/${uid}`]:official,
      [`public_badges/${uid}`]:{uid,official:true,active:true,badgeType:'official',label:'Oficial',entityType:official.entityType,updatedAtMs:t},
      [`partner_contracts/${uid}/${grantId}`]:{grantId,uid,storeId:official.storeId,entityType:official.entityType,partnerName,contractRef:official.contractRef,note:official.note,officialBadge:true,benefitPlan:grantPro?plan:'none',active:true,source:'admin_contract_grant',grantedByAdminUid:adminUid,createdAtMs:t,updatedAtMs:t,previousEntitlement},
    };
    if(grantPro){
      updates[`entitlements/${uid}`]={...previousEntitlement,verifiedBadge:true,verifiedPlan:'pro',subscriptionActive:true,expiresAtMs:Date.UTC(2100,0,1),permanent:true,contractGrantActive:true,paymentRequired:false,source:'admin_contract_grant',sourceGrantId:grantId,grantedByAdminUid:adminUid,updatedAtMs:t};
    }
    await db.ref().update(updates); await appendAudit('official_account_granted',{actorUid:adminUid,targetUid:uid,referenceId:grantId,status:'active'});
    return res.status(201).json({ok:true,uid,grantId,official:true,proGranted:grantPro});
  }catch(e){return publicError(res,e,'Não foi possível conceder a conta oficial.');}
});

app.post('/v1/admin/official-accounts/revoke', requireUser, requireAdmin, rateLimit('admin-official-revoke', 30, 60 * 60 * 1000), async(req,res)=>{
  try{
    const adminUid=req.auth.uid,uid=safe(req.body?.uid),grantId=safe(req.body?.grantId),t=nowMs();
    if(!uid||!grantId)return res.status(422).json({ok:false,code:'UID_GRANT_REQUIRED'});
    const [grantSnap,entSnap]=await Promise.all([db.ref(`partner_contracts/${uid}/${grantId}`).get(),db.ref(`entitlements/${uid}`).get()]);
    const grant=map(grantSnap.val()),current=map(entSnap.val()),previous=map(grant.previousEntitlement);
    const updates={
      [`public_badges/${uid}/active`]:false,[`public_badges/${uid}/updatedAtMs`]:t,
      [`official_accounts/${uid}/active`]:false,[`official_accounts/${uid}/revokedAtMs`]:t,[`official_accounts/${uid}/revokedByAdminUid`]:adminUid,[`official_accounts/${uid}/updatedAtMs`]:t,
      [`partner_contracts/${uid}/${grantId}/active`]:false,[`partner_contracts/${uid}/${grantId}/revokedAtMs`]:t,[`partner_contracts/${uid}/${grantId}/revokedByAdminUid`]:adminUid,[`partner_contracts/${uid}/${grantId}/updatedAtMs`]:t,
    };
    if(safe(current.source)==='admin_contract_grant'&&safe(current.sourceGrantId)===grantId){updates[`entitlements/${uid}`]=Object.keys(previous).length?previous:{verifiedBadge:false,verifiedPlan:'normal',subscriptionActive:false,expiresAtMs:t,permanent:false,contractGrantActive:false,source:'admin_contract_revoked',updatedAtMs:t};}
    await db.ref().update(updates); await appendAudit('official_account_revoked',{actorUid:adminUid,targetUid:uid,referenceId:grantId,status:'revoked'});
    return res.json({ok:true,uid,grantId});
  }catch(e){return publicError(res,e,'Não foi possível revogar a conta oficial.');}
});

// ============================================================================
// FireRank production closure V4.2 — rotas esperadas pelo Flutter atual.
// Mantem Render como backend oficial e Firebase RTDB como persistencia.
// ============================================================================

const V42_ORDER_LIMIT = 50;
const V42_GUEST_LIMIT = 50;

function v42NormalizeStatus(value) {
  const status = safe(value).toLowerCase();
  const aliases = {
    created: 'sent', pending: 'sent', sent: 'sent',
    accepted: 'accepted', seller_accepted: 'accepted',
    preparing: 'preparing', in_preparation: 'preparing',
    ready: 'ready', ready_for_delivery: 'ready',
    assigned: 'assigned', assigned_delivery: 'assigned',
    driver_accepted: 'delivery_accepted', accepted_by_delivery: 'delivery_accepted', delivery_accepted: 'delivery_accepted',
    picked_up: 'picked_up', collected: 'picked_up',
    on_route: 'on_route', out_for_delivery: 'on_route',
    arriving: 'arriving',
    delivered: 'delivered', completed: 'delivered',
    cancelled: 'cancelled', canceled: 'cancelled',
    rejected: 'rejected', declined: 'rejected',
    archived: 'archived',
  };
  return aliases[status] || status;
}

function v42OrderIndexValue(orderId, status, t) {
  return { orderId, status, updatedAtMs: t, createdAtMs: t };
}

async function v42SellerOwnsStore(uid, storeId) {
  if (!uid || !storeId) return false;
  const [storeSnap, memberSnap] = await Promise.all([
    db.ref(`stores/${storeId}`).get(),
    db.ref(`store_members/${storeId}/${uid}`).get(),
  ]);
  const store = map(storeSnap.val());
  const member = map(memberSnap.val());
  return safe(store.ownerUid) === uid || (member.active === true && ['owner','admin','manager'].includes(safe(member.role).toLowerCase()));
}

async function v42AssertDeliveryActive(uid) {
  const [roleSnap, stateSnap, eligibilitySnap] = await Promise.all([
    db.ref(`user_roles/${uid}/delivery`).get(),
    db.ref(`role_state/${uid}/delivery`).get(),
    db.ref(`eligibility/${uid}`).get(),
  ]);
  const state = map(stateSnap.val());
  const eligibility = map(eligibilitySnap.val());
  if (roleSnap.val() !== true || state.active !== true || state.accessEnabled !== true || eligibility.canDeliver !== true || eligibility.needsAgeReview === true) {
    const error = new Error('DELIVERY_NOT_ELIGIBLE');
    error.statusCode = 403;
    error.publicMessage = 'Seu acesso de entregador não está ativo.';
    throw error;
  }
}

async function v42CanBuyerAccessProduct(uid, product) {
  if (safe(product.ownerUid) === uid) return true;
  if (safe(product.visibility || 'public') === 'public') return true;
  const followSnap = await db.ref(`follow_edges/${safe(product.ownerUid)}/${uid}`).get();
  if (followSnap.val() === true) return true;
  const follow = map(followSnap.val());
  const status = safe(follow.status).toLowerCase();
  return follow.approved === true || follow.active === true || status === 'approved' || status === 'active';
}

async function v42LoadOrder(orderId) {
  const snap = await db.ref(`orders/${orderId}`).get();
  if (!snap.exists()) {
    const error = new Error('ORDER_NOT_FOUND');
    error.statusCode = 404;
    error.publicMessage = 'Pedido não encontrado.';
    throw error;
  }
  return map(snap.val());
}

async function v42WriteOrderState(orderId, order, nextStatus, actorUid, actorRole, action, extra = {}) {
  const t = nowMs();
  const eventRef = db.ref(`order_events/${orderId}`).push();
  const buyerUid = safe(order.buyerUid);
  const sellerUid = safe(order.sellerUid || order.ownerUid);
  const storeId = safe(order.storeId);
  const deliveryUid = safe(extra.deliveryUid || order.deliveryUid);
  const updates = {
    [`orders/${orderId}/status`]: nextStatus,
    [`orders/${orderId}/updatedAtMs`]: t,
    [`orders/${orderId}/timestamps/updatedAtMs`]: t,
    [`orders_by_buyer/${buyerUid}/${orderId}`]: { orderId, status: nextStatus, updatedAtMs: t, createdAtMs: finiteNumber(order.createdAtMs || order.timestamps?.createdAtMs, t) },
    [`orders_by_store/${storeId}/${orderId}`]: { orderId, status: nextStatus, updatedAtMs: t, createdAtMs: finiteNumber(order.createdAtMs || order.timestamps?.createdAtMs, t) },
    [`order_events/${orderId}/${eventRef.key}`]: { eventId: eventRef.key, orderId, action, status: nextStatus, actorUid, actorRole, createdAtMs: t, immutable: true },
  };
  if (sellerUid) updates[`orders/${orderId}/sellerUid`] = sellerUid;
  if (deliveryUid) {
    updates[`orders/${orderId}/deliveryUid`] = deliveryUid;
    updates[`orders_by_delivery/${deliveryUid}/${orderId}`] = { orderId, status: nextStatus, updatedAtMs: t, createdAtMs: finiteNumber(order.createdAtMs || order.timestamps?.createdAtMs, t) };
  }
  for (const [key, value] of Object.entries(extra)) {
    if (key === 'deliveryUid') continue;
    updates[`orders/${orderId}/${key}`] = value;
  }
  await db.ref().update(updates);
  return { t, updates };
}

function v42PublicUserProjection(uid, source, t) {
  return {
    uid,
    displayName: clip(source.displayName || source.name, 120),
    username: clip(source.username, 40),
    bio: clip(source.bio, 500),
    profileLink: clip(source.profileLink, 500),
    photoUrl: safe(source.photoUrl || source.profilePhotoUrl),
    accountVisibility: safe(source.accountVisibility || 'public') === 'private' ? 'private' : 'public',
    updatedAtMs: t,
  };
}

app.post('/v1/account/guest-merge', requireUser, rateLimit('guest-merge', 10, 10 * 60 * 1000), async (req, res) => {
  try {
    const uid = req.auth.uid;
    const body = map(req.body);
    const cart = map(body.cart);
    const favorites = map(body.favorites);
    const currentCart = map((await db.ref(`carts/${uid}`).get()).val());
    const currentFavorites = map((await db.ref(`favorites/${uid}`).get()).val());
    const updates = {};
    let cartMerged = 0;
    let favoritesMerged = 0;
    for (const [rawProductId, raw] of Object.entries(cart).slice(0, V42_GUEST_LIMIT)) {
      const productId = firebaseSafeKey(rawProductId).slice(0, 180);
      if (!productId || currentCart[productId]) continue;
      const value = map(raw);
      const quantity = Math.max(1, Math.min(99, integer(value.quantity, 1)));
      updates[`carts/${uid}/${productId}`] = { productId, quantity, updatedAtMs: nowMs(), source: 'guest_merge' };
      cartMerged++;
    }
    for (const [rawProductId] of Object.entries(favorites).slice(0, V42_GUEST_LIMIT)) {
      const productId = firebaseSafeKey(rawProductId).slice(0, 180);
      if (!productId || currentFavorites[productId]) continue;
      updates[`favorites/${uid}/${productId}`] = { productId, createdAtMs: nowMs(), source: 'guest_merge' };
      favoritesMerged++;
    }
    if (Object.keys(updates).length) await db.ref().update(updates);
    await appendAudit('guest_state_merged', { actorUid: uid, targetUid: uid, status: 'ok' });
    return res.json({ ok: true, cartMerged, favoritesMerged });
  } catch (e) { return publicError(res, e, 'Não foi possível sincronizar o modo visitante.'); }
});

app.post('/v1/account/profile', requireUser, rateLimit('profile-update', 20, 10 * 60 * 1000), async (req, res) => {
  try {
    const uid = req.auth.uid;
    const body = map(req.body);
    const username = safe(body.username).toLowerCase();
    const displayName = clip(body.displayName, 120);
    const bio = clip(body.bio, 500);
    const profileLink = safe(body.profileLink);
    const removePhoto = bool(body.removePhoto);
    if (!/^[a-z][a-z0-9._]{2,19}$/.test(username)) return res.status(422).json({ ok:false, code:'INVALID_USERNAME', message:'Username inválido.' });
    if (!displayName) return res.status(422).json({ ok:false, code:'DISPLAY_NAME_REQUIRED', message:'Nome obrigatório.' });
    if (profileLink && !isHttpsUrl(profileLink)) return res.status(422).json({ ok:false, code:'INVALID_PROFILE_LINK', message:'Use um link HTTPS válido.' });
    const current = map((await db.ref(`user_profiles/${uid}`).get()).val());
    const oldUsername = safe(current.username).toLowerCase();
    const indexRef = db.ref(`username_index/${firebaseSafeKey(username)}`);
    const tx = await indexRef.transaction((value) => (!value || value === uid ? uid : value), { applyLocally:false });
    if (!tx.committed || tx.snapshot.val() !== uid) return res.status(409).json({ ok:false, code:'USERNAME_TAKEN', message:'Esse username já está em uso.' });
    const t = nowMs();
    let photoUrl = safe(current.photoUrl);
    if (removePhoto) photoUrl = '';
    const profileMediaId = safe(body.profileMediaId);
    if (profileMediaId) {
      let media = map((await db.ref(`media_assets/${uid}/${profileMediaId}`).get()).val());
      if (!safe(media.assetId)) media = map((await db.ref(`media_assets/${profileMediaId}`).get()).val());
      if (safe(media.ownerUid) !== uid || safe(media.purpose) !== 'profile_image') return res.status(403).json({ok:false,code:'PROFILE_MEDIA_INVALID',message:'Foto inválida.'});
      if (safe(media.type) === 'upload') {
        photoUrl = cloudinary.url(safe(media.publicId), {resource_type:'image',type:'upload',secure:true,transformation:[{width:400,height:400,crop:'fill',gravity:'face',quality:'auto',fetch_format:'auto'}]});
      } else {
        photoUrl = safe(media.deliveryUrl || media.secureUrl);
      }
    }
    const profile = { uid, username, displayName, bio, profileLink, photoUrl, updatedAtMs:t, createdAtMs: finiteNumber(current.createdAtMs,t) };
    const visibility = await getAccountVisibility(uid);
    const updates = {
      [`user_profiles/${uid}`]: profile,
      [`public_users/${uid}`]: v42PublicUserProjection(uid, { ...profile, accountVisibility: visibility }, t),
    };
    if (oldUsername && oldUsername !== username) updates[`username_index/${firebaseSafeKey(oldUsername)}`] = null;
    await db.ref().update(updates);
    await firebaseAuth.updateUser(uid, { displayName, photoURL: photoUrl || null });
    await appendAudit('profile_updated', { actorUid: uid, targetUid: uid, status:'ok' });
    return res.json({ ok:true, profile });
  } catch (e) { return publicError(res, e, 'Não foi possível salvar o perfil.'); }
});

app.post('/v1/account/delete-request', requireUser, rateLimit('account-delete-request', 3, 24 * 60 * 60 * 1000), async (req, res) => {
  try {
    const uid = req.auth.uid;
    if (req.body?.confirmation !== true) return res.status(422).json({ok:false,code:'CONFIRMATION_REQUIRED',message:'Confirme a exclusão.'});
    const t = nowMs();
    const ref = db.ref(`account_deletion_requests/${uid}`).push();
    const requestId = ref.key;
    await ref.set({ requestId, uid, status:'requested', createdAtMs:t, updatedAtMs:t, immutable:true });
    await db.ref(`account_state/${uid}`).update({ deletionRequested:true, deletionRequestId:requestId, updatedAtMs:t });
    await appendAudit('account_deletion_requested', { actorUid:uid, targetUid:uid, referenceId:requestId, status:'requested' });
    return res.status(202).json({ok:true,requestId,status:'requested'});
  } catch (e) { return publicError(res, e, 'Não foi possível registrar a exclusão.'); }
});

app.post('/v1/account/export', requireUser, rateLimit('account-export', 3, 60 * 60 * 1000), async (req, res) => {
  try {
    const uid = req.auth.uid;
    const paths = ['user_profiles','user_preferences','account_visibility','carts','favorites','orders_by_buyer','notifications','entitlements','user_roles','role_state','eligibility','current_applications'];
    const data = {};
    for (const root of paths) data[root] = (await db.ref(`${root}/${uid}`).get()).val() ?? null;
    const ref = db.ref(`data_export_requests/${uid}`).push();
    const requestId = ref.key;
    const t = nowMs();
    await ref.set({ requestId, uid, status:'completed_inline', createdAtMs:t, completedAtMs:t, immutable:true });
    return res.json({ok:true,requestId,generatedAtMs:t,data});
  } catch (e) { return publicError(res, e, 'Não foi possível gerar a exportação.'); }
});

app.get('/v1/boost/catalog', requireUser, rateLimit('boost-catalog', 60, 10 * 60 * 1000), async (_req, res) => {
  try {
    let raw = {};
    if (BOOST_CATALOG_JSON) { try { raw = JSON.parse(BOOST_CATALOG_JSON); } catch (_) {} }
    if (!Object.keys(map(raw)).length) raw = map((await db.ref('public_config/boostCatalog').get()).val());
    const plans = Object.entries(map(raw)).map(([id, value]) => ({ id, ...map(value) })).filter((x) => integer(x.days,0) > 0 && integer(x.priceCents,0) > 0).slice(0,20);
    return res.json({ok:true,plans});
  } catch (e) { return publicError(res,e,'Não foi possível carregar os Patrocinados.'); }
});

app.post('/v1/chats/start', requireUser, rateLimit('chat-start', 30, 10 * 60 * 1000), async (req,res) => {
  try {
    const uid=req.auth.uid, productId=safe(req.body?.productId), type=clip(req.body?.type||'product_question',40), t=nowMs();
    const product=map((await db.ref(`products/${productId}`).get()).val());
    if (!productId || !safe(product.ownerUid)) return res.status(404).json({ok:false,code:'PRODUCT_NOT_FOUND'});
    const otherUid=safe(product.ownerUid); if(otherUid===uid) return res.status(409).json({ok:false,code:'SELF_CHAT'});
    const key=[uid,otherUid,productId].sort().join(':'); const chatId=`product_${stableHash(key).slice(0,32)}`;
    await db.ref().update({
      [`chats/${chatId}`]:{chatId,type,productId,participants:{[uid]:true,[otherUid]:true},status:'open',createdAtMs:t,updatedAtMs:t},
      [`chats_by_user/${uid}/${chatId}`]:{chatId,type,productId,otherUid,updatedAtMs:t,lastMessageAtMs:t},
      [`chats_by_user/${otherUid}/${chatId}`]:{chatId,type,productId,otherUid:uid,updatedAtMs:t,lastMessageAtMs:t},
    });
    return res.json({ok:true,chatId,otherUid});
  }catch(e){return publicError(res,e,'Não foi possível iniciar a conversa.');}
});

app.post('/v1/reports', requireUser, rateLimit('report-create', 10, 60 * 60 * 1000), async(req,res)=>{
  try{
    const uid=req.auth.uid,targetType=clip(req.body?.targetType,40),targetId=clip(req.body?.targetId,180),reason=clip(req.body?.reason,80),description=clip(req.body?.description,1500),t=nowMs();
    if(!targetType||!targetId||!reason||description.length<3)return res.status(422).json({ok:false,code:'REPORT_INVALID'});
    const ref=db.ref('moderation_reports').push(); const reportId=ref.key;
    await ref.set({reportId,reporterUid:uid,targetType,targetId,reason,description,status:'open',createdAtMs:t,updatedAtMs:t});
    await appendAudit('report_created',{actorUid:uid,referenceId:reportId,status:'open'});
    return res.status(201).json({ok:true,reportId});
  }catch(e){return publicError(res,e,'Não foi possível enviar a denúncia.');}
});

app.post('/v1/products/event', rateLimit('product-event', 180, 60 * 60 * 1000), async(req,res)=>{
  try{
    const productId=clip(req.body?.productId,180),event=clip(req.body?.event,40),allowed=new Set(['view','affiliate_click','share','favorite']);
    if(!productId||!allowed.has(event))return res.status(422).json({ok:false});
    const ref=db.ref(`product_events/${productId}`).push(); const t=nowMs();
    await ref.set({eventId:ref.key,productId,event,createdAtMs:t,clientPlatform:clip(req.body?.clientPlatform,40)});
    const statKey=event==='view'?'views':event==='affiliate_click'?'affiliateClicks':event==='share'?'shares':'favorites';
    await db.ref(`product_stats/${productId}/${statKey}`).transaction((v)=>integer(v,0)+1,{applyLocally:false});
    return res.status(202).json({ok:true});
  }catch(e){return publicError(res,e,'Evento não registrado.');}
});

app.post('/v1/products/action', requireUser, rateLimit('product-action', 30, 10 * 60 * 1000), async(req,res)=>{
  try{
    const uid=req.auth.uid,productId=safe(req.body?.productId),action=safe(req.body?.action).toLowerCase(),t=nowMs();
    const snap=await db.ref(`products/${productId}`).get(); const product=map(snap.val());
    if(!snap.exists())return res.status(404).json({ok:false,code:'PRODUCT_NOT_FOUND'});
    if(safe(product.ownerUid)!==uid)return res.status(403).json({ok:false,code:'PRODUCT_OWNER_REQUIRED'});
    if(!['pause','reactivate','delete'].includes(action))return res.status(422).json({ok:false,code:'INVALID_ACTION'});
    const nextStatus=action==='pause'?'paused':action==='reactivate'?'active':'deleted';
    const updates={
      [`products/${productId}/status`]:nextStatus,[`products/${productId}/lifecycle/updatedAtMs`]:t,
      [`product_cards/${productId}`]:null,[`feed_index/${productId}`]:null,[`search_index_basic/${productId}`]:null,[`active_boost_cards/${productId}`]:null,
    };
    const categoryId=safe(product.categoryId); if(categoryId)updates[`category_index/${categoryId}/${productId}`]=null;
    if(action==='delete')updates[`products/${productId}/lifecycle/deletedAtMs`]=t;
    if(action==='reactivate'){
      const visibility=await getAccountVisibility(uid); const store=map((await db.ref(`stores/${safe(product.storeId)}`).get()).val());
      if(accountAndStoreCanBePublic(visibility,store) && safe(product.moderation?.status||'approved')==='approved'){
        const card=publicProductCard({...product,status:'active',visibility:'public'},safe(product.media?.coverUrl),t); addPublicProjections(updates,{...product,status:'active',visibility:'public'},card,searchTermsForProduct(safe(product.title),categoryId),t);
      }
    }
    await db.ref().update(updates); await appendAudit(`product_${action}`,{actorUid:uid,targetUid:uid,referenceId:productId,status:nextStatus});
    return res.json({ok:true,productId,status:nextStatus});
  }catch(e){return publicError(res,e,'Não foi possível atualizar o produto.');}
});

app.post('/v1/orders', requireUser, rateLimit('order-create', 12, 10 * 60 * 1000), async(req,res)=>{
  try{
    const uid=req.auth.uid, body=map(req.body), productId=safe(body.productId), quantity=Math.max(1,Math.min(99,integer(body.quantity,1))), fulfillmentType=safe(body.fulfillmentType).toLowerCase(), paymentMethod=clip(body.paymentMethod,60), buyerNote=clip(body.buyerNote,1000), t=nowMs();
    const productSnap=await db.ref(`products/${productId}`).get(); const product=map(productSnap.val());
    if(!productSnap.exists()||safe(product.status)!=='active'||safe(product.productType)!=='local')return res.status(404).json({ok:false,code:'PRODUCT_NOT_AVAILABLE'});
    if(safe(product.ownerUid)===uid)return res.status(403).json({ok:false,code:'OWN_PRODUCT'});
    if(!(await v42CanBuyerAccessProduct(uid,product)))return res.status(403).json({ok:false,code:'PRODUCT_PRIVATE'});
    const local=map(product.local); if(!['delivery','pickup'].includes(fulfillmentType))return res.status(422).json({ok:false,code:'INVALID_FULFILLMENT'});
    if(fulfillmentType==='delivery'&&local.deliveryAvailable!==true)return res.status(422).json({ok:false,code:'DELIVERY_UNAVAILABLE'});
    if(fulfillmentType==='pickup'&&local.pickupAvailable!==true)return res.status(422).json({ok:false,code:'PICKUP_UNAVAILABLE'});
    const unitPriceCents=integer(product.pricing?.priceCents,0); if(unitPriceCents<=0)return res.status(409).json({ok:false,code:'PRICE_CHANGED'});
    const storeId=safe(product.storeId), sellerUid=safe(product.ownerUid); const store=map((await db.ref(`stores/${storeId}`).get()).val());
    const addressKey=safe(body.addressKey||'primary'); let address={};
    if(fulfillmentType==='delivery'){
      const addressSnap=await db.ref(`user_addresses/${uid}/${addressKey}`).get(); address=map(addressSnap.val());
      if(!addressSnap.exists()||!safe(address.city)||!safe(address.state))return res.status(422).json({ok:false,code:'ADDRESS_REQUIRED',message:'Cadastre um endereço válido.'});
    }
    const deliveryFeeCents=fulfillmentType==='delivery'?Math.max(0,integer(local.deliveryFeeCents,0)):0; const productAmountCents=unitPriceCents*quantity; const totalCents=productAmountCents+deliveryFeeCents;
    const orderId=db.ref('orders').push().key; const code=String(crypto.randomInt(100000,999999)); const codeHash=stableHash(`${orderId}:${code}`);
    const order={orderId,buyerUid:uid,sellerUid,storeId,productId,quantity,status:'sent',fulfillmentType,paymentMethod,productAmountCents,deliveryFeeCents,totalCents,deliveryCodeRequired:fulfillmentType==='delivery',deliveryCodeVerified:false,productSnapshot:{productId,title:safe(product.title),coverUrl:safe(product.media?.coverUrl),priceCents:unitPriceCents},storeSnapshot:{storeId,name:safe(store.name)},review:{status:'pending'},createdAtMs:t,updatedAtMs:t,timestamps:{createdAtMs:t,updatedAtMs:t}};
    const privateData={buyer:{uid},buyerNote,payment:{method:paymentMethod,totalCents,productAmountCents,deliveryFeeCents},deliveryAddress:fulfillmentType==='delivery'?address:null,deliveryCode:fulfillmentType==='delivery'?{plainForBuyer:code,codeHash,required:true,verified:false}:null};
    const updates={
      [`orders/${orderId}`]:order,[`order_private/${orderId}`]:privateData,
      [`orders_by_buyer/${uid}/${orderId}`]:v42OrderIndexValue(orderId,'sent',t),
      [`orders_by_store/${storeId}/${orderId}`]:v42OrderIndexValue(orderId,'sent',t),
      [`buyer_orders/${uid}/${orderId}`]:{orderId,status:'sent',updatedAtMs:t},
    };
    await db.ref().update(updates); await appendAudit('order_created',{actorUid:uid,targetUid:sellerUid,referenceId:orderId,status:'sent'});
    await pushNotification(sellerUid,{title:'Novo pedido',body:`Você recebeu um novo pedido de ${clip(product.title,80)}.`,type:'order_created',data:{orderId,productId}});
    return res.status(201).json({ok:true,orderId,status:'sent'});
  }catch(e){return publicError(res,e,'Não foi possível criar o pedido.');}
});

app.post('/v1/orders/action', requireUser, rateLimit('order-action', 40, 10 * 60 * 1000), async(req,res)=>{
  try{
    const uid=req.auth.uid,orderId=safe(req.body?.orderId),actorRole=safe(req.body?.actorRole).toLowerCase(),action=safe(req.body?.action).toLowerCase();
    const order=await v42LoadOrder(orderId); const status=v42NormalizeStatus(order.status); const buyerUid=safe(order.buyerUid), sellerUid=safe(order.sellerUid||order.ownerUid), storeId=safe(order.storeId);
    if(actorRole==='buyer'&&buyerUid!==uid)return res.status(403).json({ok:false,code:'ORDER_ACTOR_INVALID'});
    if(actorRole==='seller'&&!(sellerUid===uid||await v42SellerOwnsStore(uid,storeId)))return res.status(403).json({ok:false,code:'ORDER_ACTOR_INVALID'});
    if(actorRole==='delivery'){await v42AssertDeliveryActive(uid); if(safe(order.deliveryUid)&&safe(order.deliveryUid)!==uid)return res.status(403).json({ok:false,code:'ORDER_ACTOR_INVALID'});}
    const transitions={
      buyer:{cancel:{from:['sent'],to:'cancelled'},archive:{from:['delivered','cancelled','rejected'],to:'archived'}},
      seller:{accept:{from:['sent'],to:'accepted'},reject:{from:['sent'],to:'rejected'},mark_preparing:{from:['accepted'],to:'preparing'},mark_ready:{from:['preparing'],to:'ready'},complete_pickup:{from:['ready'],to:'delivered'},archive:{from:['delivered','cancelled','rejected'],to:'archived'}},
      delivery:{accept_delivery:{from:['assigned'],to:'delivery_accepted'},accept:{from:['assigned'],to:'delivery_accepted'},mark_picked_up:{from:['delivery_accepted'],to:'picked_up'},start_route:{from:['picked_up'],to:'on_route'},mark_arriving:{from:['on_route'],to:'arriving'},confirm_delivery:{from:['arriving','on_route'],to:'delivered'},archive:{from:['delivered','cancelled','rejected'],to:'archived'}},
    };
    if(action==='assign_delivery'){
      if(actorRole!=='seller'||status!=='ready')return res.status(409).json({ok:false,code:'INVALID_ORDER_TRANSITION'});
      const code=safe(req.body?.deliveryCode).toUpperCase(); const codeSnap=await db.ref(`delivery_public_codes/${firebaseSafeKey(code)}`).get(); let deliveryUid='';
      if(typeof codeSnap.val()==='string')deliveryUid=safe(codeSnap.val());else deliveryUid=safe(map(codeSnap.val()).uid||map(codeSnap.val()).deliveryUid);
      if(!deliveryUid)return res.status(404).json({ok:false,code:'DELIVERY_NOT_FOUND'});
      const connection=map((await db.ref(`delivery_connections/${storeId}/${deliveryUid}`).get()).val()); if(!['active','accepted'].includes(safe(connection.status).toLowerCase()))return res.status(403).json({ok:false,code:'DELIVERY_NOT_CONNECTED'});
      await v42WriteOrderState(orderId,order,'assigned',uid,'seller',action,{deliveryUid}); await pushNotification(deliveryUid,{title:'Nova entrega',body:'Uma loja conectada enviou um pedido para você.',type:'delivery_assigned',data:{orderId}}); return res.json({ok:true,orderId,status:'assigned',deliveryUid});
    }
    if(action==='verify_delivery_code'){
      if(actorRole!=='delivery'||!['arriving','on_route'].includes(status))return res.status(409).json({ok:false,code:'INVALID_ORDER_TRANSITION'});
      const typed=safe(req.body?.code||req.body?.deliveryCode).replace(/[^0-9A-Za-z]/g,''); const priv=map((await db.ref(`order_private/${orderId}`).get()).val()); const codeData=map(priv.deliveryCode||priv.deliveryConfirmation); const expected=safe(codeData.codeHash||priv.deliveryCodeHash||priv.confirmationCodeHash);
      if(!typed||!expected||stableHash(`${orderId}:${typed}`)!==expected)return res.status(422).json({ok:false,code:'DELIVERY_CODE_INVALID',message:'Código de entrega inválido.'});
      await db.ref().update({[`orders/${orderId}/deliveryCodeVerified`]:true,[`order_private/${orderId}/deliveryCode/verified`]:true,[`order_private/${orderId}/deliveryCode/verifiedAtMs`]:nowMs()}); await v42WriteOrderState(orderId,order,'delivered',uid,'delivery',action,{deliveryCodeVerified:true}); await pushNotification(buyerUid,{title:'Entrega concluída',body:'Seu pedido foi marcado como entregue.',type:'order_delivered',data:{orderId}}); return res.json({ok:true,orderId,status:'delivered'});
    }
    const tr=transitions[actorRole]?.[action]; if(!tr)return res.status(422).json({ok:false,code:'INVALID_ACTION'}); if(!tr.from.includes(status))return res.status(409).json({ok:false,code:'INVALID_ORDER_TRANSITION',status});
    if(actorRole==='delivery'&&!safe(order.deliveryUid))return res.status(409).json({ok:false,code:'DELIVERY_NOT_ASSIGNED'});
    await v42WriteOrderState(orderId,order,tr.to,uid,actorRole,action,actorRole==='delivery'?{deliveryUid:uid}:{});
    if(tr.to==='delivered')await pushNotification(buyerUid,{title:'Pedido entregue',body:'Seu pedido foi concluído.',type:'order_delivered',data:{orderId}});
    else if(actorRole==='seller')await pushNotification(buyerUid,{title:'Pedido atualizado',body:`Novo status: ${tr.to}.`,type:'order_status',data:{orderId,status:tr.to}});
    return res.json({ok:true,orderId,status:tr.to});
  }catch(e){return publicError(res,e,'Não foi possível atualizar o pedido.');}
});

app.post('/v1/delivery/orders/action', requireUser, rateLimit('delivery-order-action', 40, 10 * 60 * 1000), async(req,res)=>{
  req.body={...map(req.body),actorRole:'delivery'};
  // Reutiliza a mesma lógica por chamada interna HTTP-less: replica apenas o formato esperado.
  const orderId=safe(req.body.orderId); const action=safe(req.body.action).toLowerCase();
  try{
    const uid=req.auth.uid; await v42AssertDeliveryActive(uid); const order=await v42LoadOrder(orderId); const assigned=safe(order.deliveryUid); if(assigned&&assigned!==uid)return res.status(403).json({ok:false,code:'ORDER_ACTOR_INVALID'});
    const mapAction={accept:'accept_delivery',reject:'reject_delivery',mark_picked_up:'mark_picked_up',start_route:'start_route',mark_arriving:'mark_arriving',verify_delivery_code:'verify_delivery_code',confirm_delivery:'confirm_delivery',archive:'archive'}; const normalized=mapAction[action]||action;
    if(normalized==='reject_delivery'){
      if(v42NormalizeStatus(order.status)!=='assigned')return res.status(409).json({ok:false,code:'INVALID_ORDER_TRANSITION'});
      await db.ref(`orders_by_delivery/${uid}/${orderId}`).remove(); await v42WriteOrderState(orderId,order,'ready',uid,'delivery','reject_delivery',{deliveryUid:null}); await db.ref(`orders/${orderId}/deliveryUid`).remove(); return res.json({ok:true,orderId,status:'ready'});
    }
    // Implementacao direta das demais transicoes.
    const status=v42NormalizeStatus(order.status); const transitions={accept_delivery:{from:['assigned'],to:'delivery_accepted'},mark_picked_up:{from:['delivery_accepted'],to:'picked_up'},start_route:{from:['picked_up'],to:'on_route'},mark_arriving:{from:['on_route'],to:'arriving'},confirm_delivery:{from:['arriving','on_route'],to:'delivered'},archive:{from:['delivered','cancelled','rejected'],to:'archived'}};
    if(normalized==='verify_delivery_code'){
      const typed=safe(req.body.code||req.body.deliveryCode).replace(/[^0-9A-Za-z]/g,''); const priv=map((await db.ref(`order_private/${orderId}`).get()).val()); const codeData=map(priv.deliveryCode||priv.deliveryConfirmation); const expected=safe(codeData.codeHash||priv.deliveryCodeHash||priv.confirmationCodeHash); if(!typed||!expected||stableHash(`${orderId}:${typed}`)!==expected)return res.status(422).json({ok:false,code:'DELIVERY_CODE_INVALID',message:'Código de entrega inválido.'}); await db.ref().update({[`orders/${orderId}/deliveryCodeVerified`]:true,[`order_private/${orderId}/deliveryCode/verified`]:true,[`order_private/${orderId}/deliveryCode/verifiedAtMs`]:nowMs()}); await v42WriteOrderState(orderId,order,'delivered',uid,'delivery','verify_delivery_code',{deliveryUid:uid,deliveryCodeVerified:true}); return res.json({ok:true,orderId,status:'delivered'});
    }
    const tr=transitions[normalized]; if(!tr)return res.status(422).json({ok:false,code:'INVALID_ACTION'}); if(!tr.from.includes(status))return res.status(409).json({ok:false,code:'INVALID_ORDER_TRANSITION',status}); await v42WriteOrderState(orderId,order,tr.to,uid,'delivery',normalized,{deliveryUid:uid}); return res.json({ok:true,orderId,status:tr.to});
  }catch(e){return publicError(res,e,'Não foi possível atualizar a entrega.');}
});

app.post('/v1/delivery/connections/request', requireUser, rateLimit('delivery-connection-request', 20, 60 * 60 * 1000), async(req,res)=>{
  try{
    const uid=req.auth.uid,storeId=safe(req.body?.storeId),code=safe(req.body?.publicCode).toUpperCase(),t=nowMs(); await assertSellerCanPublish(uid); if(!(await v42SellerOwnsStore(uid,storeId)))return res.status(403).json({ok:false,code:'STORE_ACCESS_DENIED'});
    const codeSnap=await db.ref(`delivery_public_codes/${firebaseSafeKey(code)}`).get(); let deliveryUid=typeof codeSnap.val()==='string'?safe(codeSnap.val()):safe(map(codeSnap.val()).uid||map(codeSnap.val()).deliveryUid); if(!deliveryUid)return res.status(404).json({ok:false,code:'DELIVERY_NOT_FOUND'}); await v42AssertDeliveryActive(deliveryUid);
    const connectionId=stableHash(`${storeId}:${deliveryUid}`).slice(0,32); const item={connectionId,storeId,deliveryUid,sellerUid:uid,status:'pending',requestedAtMs:t,updatedAtMs:t}; await db.ref().update({[`delivery_connections/${storeId}/${deliveryUid}`]:item,[`delivery_connections_by_user/${uid}/${connectionId}`]:item,[`delivery_connections_by_user/${deliveryUid}/${connectionId}`]:item}); await pushNotification(deliveryUid,{title:'Nova conexão de loja',body:'Uma loja quer conectar você como entregador.',type:'delivery_connection_request',data:{storeId,connectionId}}); return res.status(201).json({ok:true,connectionId,status:'pending'});
  }catch(e){return publicError(res,e,'Não foi possível enviar a solicitação.');}
});

app.post('/v1/delivery/connections/respond', requireUser, rateLimit('delivery-connection-respond', 20, 60 * 60 * 1000), async(req,res)=>{
  try{
    const uid=req.auth.uid,storeId=safe(req.body?.storeId),action=safe(req.body?.action).toLowerCase(),t=nowMs(); await v42AssertDeliveryActive(uid); const ref=db.ref(`delivery_connections/${storeId}/${uid}`); const snap=await ref.get(); const item=map(snap.val()); if(!snap.exists())return res.status(404).json({ok:false,code:'CONNECTION_NOT_FOUND'}); if(!['accept','reject'].includes(action))return res.status(422).json({ok:false,code:'INVALID_ACTION'}); const status=action==='accept'?'active':'rejected'; const connectionId=safe(item.connectionId)||stableHash(`${storeId}:${uid}`).slice(0,32); const next={...item,connectionId,status,updatedAtMs:t}; await db.ref().update({[`delivery_connections/${storeId}/${uid}`]:next,[`delivery_connections_by_user/${safe(item.sellerUid)}/${connectionId}`]:next,[`delivery_connections_by_user/${uid}/${connectionId}`]:next}); return res.json({ok:true,connectionId,status});
  }catch(e){return publicError(res,e,'Não foi possível responder à conexão.');}
});

app.post('/v1/delivery/connections/update', requireUser, rateLimit('delivery-connection-update', 20, 60 * 60 * 1000), async(req,res)=>{
  try{
    const uid=req.auth.uid,storeId=safe(req.body?.storeId),deliveryUid=safe(req.body?.deliveryUid),action=safe(req.body?.action).toLowerCase(),t=nowMs(); await assertSellerCanPublish(uid); if(!(await v42SellerOwnsStore(uid,storeId)))return res.status(403).json({ok:false,code:'STORE_ACCESS_DENIED'}); const snap=await db.ref(`delivery_connections/${storeId}/${deliveryUid}`).get(); const item=map(snap.val()); if(!snap.exists())return res.status(404).json({ok:false,code:'CONNECTION_NOT_FOUND'}); if(!['remove','cancel'].includes(action))return res.status(422).json({ok:false,code:'INVALID_ACTION'}); const status=action==='remove'?'removed':'cancelled'; const connectionId=safe(item.connectionId)||stableHash(`${storeId}:${deliveryUid}`).slice(0,32); const next={...item,status,updatedAtMs:t}; await db.ref().update({[`delivery_connections/${storeId}/${deliveryUid}`]:next,[`delivery_connections_by_user/${uid}/${connectionId}`]:next,[`delivery_connections_by_user/${deliveryUid}/${connectionId}`]:next}); return res.json({ok:true,connectionId,status});
  }catch(e){return publicError(res,e,'Não foi possível atualizar a conexão.');}
});

app.post('/v1/reviews', requireUser, rateLimit('review-create', 8, 60 * 60 * 1000), async(req,res)=>{
  try{
    const uid=req.auth.uid,orderId=safe(req.body?.orderId),rating=integer(req.body?.rating,0),comment=clip(req.body?.comment,1200),t=nowMs(); if(rating<1||rating>5)return res.status(422).json({ok:false,code:'INVALID_RATING'}); const order=await v42LoadOrder(orderId); if(safe(order.buyerUid)!==uid)return res.status(403).json({ok:false,code:'BUYER_REQUIRED'}); if(v42NormalizeStatus(order.status)!=='delivered')return res.status(409).json({ok:false,code:'ORDER_NOT_DELIVERED'}); if(safe(order.review?.reviewId)||order.review?.submitted===true)return res.status(409).json({ok:false,code:'REVIEW_ALREADY_SUBMITTED'}); const reviewId=db.ref('reviews').push().key,productId=safe(order.productId||order.productSnapshot?.productId),sellerUid=safe(order.sellerUid),review={reviewId,orderId,productId,sellerUid,buyerUid:uid,rating,comment,status:'published',createdAtMs:t}; await db.ref().update({[`reviews/${reviewId}`]:review,[`reviews_by_product/${productId}/${reviewId}`]:{reviewId,rating,createdAtMs:t},[`reviews_by_seller/${sellerUid}/${reviewId}`]:{reviewId,rating,createdAtMs:t},[`orders/${orderId}/review`]:{reviewId,submitted:true,rating,createdAtMs:t}}); const statsRef=db.ref(`product_stats/${productId}`); await statsRef.transaction((raw)=>{const s=map(raw);const count=integer(s.ratingCount,0);const sum=finiteNumber(s.ratingSum,0);return {...s,ratingCount:count+1,ratingSum:sum+rating,ratingAverage:(sum+rating)/(count+1),updatedAtMs:t};},{applyLocally:false}); return res.status(201).json({ok:true,reviewId});
  }catch(e){return publicError(res,e,'Não foi possível enviar a avaliação.');}
});

app.post('/api/orders/:orderId/confirm-delivery', requireUser, rateLimit('confirm-delivery-legacy', 20, 10 * 60 * 1000), async(req,res)=>{
  try{const uid=req.auth.uid,orderId=safe(req.params.orderId),order=await v42LoadOrder(orderId);await v42AssertDeliveryActive(uid);if(safe(order.deliveryUid)!==uid)return res.status(403).json({ok:false,code:'ORDER_ACTOR_INVALID'});const status=v42NormalizeStatus(order.status);if(!['arriving','on_route'].includes(status))return res.status(409).json({ok:false,code:'INVALID_ORDER_TRANSITION'});await v42WriteOrderState(orderId,order,'delivered',uid,'delivery','confirm_delivery',{deliveryUid:uid});return res.json({ok:true,orderId,status:'delivered'});}catch(e){return publicError(res,e,'Não foi possível confirmar a entrega.');}
});


async function expireBoosts() {
  const t =
    nowMs();

  const snap =
    await db
      .ref(
        "boosts"
      )
      .orderByChild(
        "status"
      )
      .equalTo(
        "active"
      )
      .get();

  let expiredBoosts =
    0;

  if (
    !snap.exists()
  ) {
    return {
      expiredBoosts,
      checkedAtMs:
        t,
    };
  }

  const work = [];

  snap.forEach(
    (child) => {
      work.push({
        boostId:
          child.key,

        value:
          map(
            child.val()
          ),
      });
    }
  );

  for (
    const item
    of work
  ) {
    const expiresAtMs =
      finiteNumber(
        item.value.expiresAtMs,
        0
      );

    if (
      !expiresAtMs ||
      expiresAtMs > t
    ) {
      continue;
    }

    expiredBoosts +=
      1;

    const uid =
      safe(
        item.value.ownerUid
      );

    const productId =
      safe(
        item.value.productId
      );

    const eventId =
      firebaseSafeKey(
        `expired_${t}`
      );

    const updates = {
      [`boosts/${item.boostId}/status`]:
        "expired",

      [`boosts/${item.boostId}/expiredAtMs`]:
        t,

      [`boosts/${item.boostId}/updatedAtMs`]:
        t,

      [`boost_events/${item.boostId}/${eventId}`]:
        {
          eventId,

          boostId:
            item.boostId,

          ownerUid:
            uid,

          productId,

          type:
            "expired",

          createdAtMs:
            t,

          immutable:
            true,
        },
    };

    if (productId) {
      const cardSnap =
        await db
          .ref(
            `active_boost_cards/${productId}`
          )
          .get();

      const card =
        map(
          cardSnap.val()
        );

      if (
        safe(
          card.boostId
        ) ===
        item.boostId
      ) {
        updates[
          `active_boost_cards/${productId}`
        ] =
          null;
      }
    }

    await db
      .ref()
      .update(
        updates
      );

    if (uid) {
      await pushNotification(
        uid,
        {
          title:
            "Patrocinado encerrado",

          body:
            "O período do seu Patrocinado terminou.",

          type:
            "boost_expired",

          data: {
            boostId:
              item.boostId,

            productId,
          },
        }
      );
    }
  }

  return {
    expiredBoosts,
    checkedAtMs:
      t,
  };
}

async function expireSubscriptions() {
  const t =
    nowMs();

  const snap =
    await db
      .ref(
        "entitlements"
      )
      .orderByChild(
        "subscriptionActive"
      )
      .equalTo(
        true
      )
      .get();

  let expiredSubscriptions =
    0;

  if (
    !snap.exists()
  ) {
    return {
      expiredSubscriptions,
      checkedAtMs:
        t,
    };
  }

  const work = [];

  snap.forEach(
    (child) => {
      work.push({
        uid:
          child.key,

        value:
          map(
            child.val()
          ),
      });
    }
  );

  for (
    const item
    of work
  ) {
    const expiresAtMs =
      finiteNumber(
        item.value.expiresAtMs,
        0
      );

    if (
      !expiresAtMs ||
      expiresAtMs > t
    ) {
      continue;
    }

    expiredSubscriptions +=
      1;

    const eventId =
      firebaseSafeKey(
        `expired_${expiresAtMs}`
      );

    await db
      .ref()
      .update({
        [`entitlements/${item.uid}`]:
          {
            ...item.value,

            verifiedBadge:
              false,

            verifiedPlan:
              "none",

            subscriptionActive:
              false,

            expiresAtMs,

            source:
              "backend_expiration",

            updatedAtMs:
              t,

            requiresBackendValidatedReceiptForReactivation:
              true,
          },

        [`subscription_events/${item.uid}/${eventId}`]:
          {
            eventId,

            uid:
              item.uid,

            type:
              "expired",

            expiresAtMs,

            createdAtMs:
              t,

            immutable:
              true,
          },
      });

    await pushNotification(
      item.uid,
      {
        title:
          "Verificação expirada",

        body:
          "Sua assinatura de verificação terminou.",

        type:
          "verification_expired",
      }
    );
  }

  return {
    expiredSubscriptions,
    checkedAtMs:
      t,
  };
}

app.post(
  "/api/internal/expire-boosts",
  requireInternalSecret,
  async (
    _,
    res
  ) => {
    try {
      return res.json({
        ok: true,
        ...(await expireBoosts()),
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "Erro ao expirar Patrocinados."
      );
    }
  }
);

app.post(
  "/api/internal/expire-verifications",
  requireInternalSecret,
  async (
    _,
    res
  ) => {
    try {
      const result =
        await expireSubscriptions();

      return res.json({
        ok:
          true,

        expiredVerifications:
          result.expiredSubscriptions,

        ...result,
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "Erro ao expirar verificações."
      );
    }
  }
);

app.post(
  "/api/internal/expire-subscriptions",
  requireInternalSecret,
  async (
    _,
    res
  ) => {
    try {
      return res.json({
        ok:
          true,

        ...(await expireSubscriptions()),
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "Erro ao expirar assinaturas."
      );
    }
  }
);

app.post(
  "/api/internal/run-maintenance",
  requireInternalSecret,
  async (
    _,
    res
  ) => {
    try {
      const [
        boostResult,
        subscriptionResult,
      ] =
        await Promise.all([
          expireBoosts(),
          expireSubscriptions(),
        ]);

      return res.json({
        ok:
          true,

        expiredBoosts:
          boostResult.expiredBoosts,

        expiredSubscriptions:
          subscriptionResult
            .expiredSubscriptions,

        expiredVerifications:
          subscriptionResult
            .expiredSubscriptions,

        checkedAtMs:
          nowMs(),
      });
    } catch (error) {
      return publicError(
        res,
        error,
        "Erro ao rodar manutenção."
      );
    }
  }
);

app.get(
  "/",
  (
    _,
    res
  ) => {
    res.send(
      htmlPage(
        "FireRank API",
        `Backend V${FIRERANK_SCHEMA_VERSION} online: autenticação, catálogo, endereços, mídia Cloudinary protegida e serviços digitais.`
      )
    );
  }
);

app.get(
  "/health",
  async (_, res) => {
    let databaseOk = false;
    let databaseError = "";

    try {
      await db
        .ref("public_config/app/schemaVersion")
        .get();
      databaseOk = true;
    } catch (error) {
      databaseError =
        error?.code ||
        "database_unavailable";
    }

    const publicBaseUrlConfigured =
      NODE_ENV !== "production" ||
      isHttpsUrl(APP_BASE_URL);

    const mediaSecretConfigured =
      NODE_ENV !== "production" ||
      !!MEDIA_TOKEN_SECRET;

    const mercadoPagoWebhookReady =
      !MP_ACCESS_TOKEN ||
      !!MP_WEBHOOK_SECRET;

    const ready =
      databaseOk &&
      CLOUDINARY_CONFIGURED &&
      !!sharp &&
      mediaSecretConfigured &&
      mercadoPagoWebhookReady;

    return res
      .status(ready ? 200 : 503)
      .json({
        ok: ready,
        schemaVersion:
          FIRERANK_SCHEMA_VERSION,
        nodeEnv: NODE_ENV,
        databaseOk,
        databaseError:
          databaseOk
            ? undefined
            : databaseError,
        firebaseConfigured:
          !!FIREBASE_DATABASE_URL,
        cloudinaryConfigured:
          CLOUDINARY_CONFIGURED,
        cloudinaryCloudName: CLOUDINARY_CLOUD_NAME,
        firebaseStorageUsed: false,
        mediaProcessorConfigured:
          !!sharp,
        mediaTokenSecretConfigured:
          !!MEDIA_TOKEN_SECRET,
        publicBaseUrlConfigured,
        publicBaseUrl: APP_BASE_URL,
        mercadoPagoConfigured:
          !!MP_ACCESS_TOKEN,
        mercadoPagoWebhookSecretConfigured:
          !!MP_WEBHOOK_SECRET,
        mercadoPagoWebhookReady,
        emailConfigured:
          !!SMTP_HOST &&
          !!SMTP_USER &&
          !!SMTP_PASS &&
          !!MAIL_FROM_EMAIL,
        appCheckRequired:
          REQUIRE_APP_CHECK,
        googlePlayBillingEnforced:
          ENFORCE_GOOGLE_PLAY_BILLING,
        maintenanceSecretConfigured:
          !!INTERNAL_MAINTENANCE_SECRET,
        boostCatalogEnvConfigured:
          !!BOOST_CATALOG_JSON,
      });
  }
);

app.get(
  "/success",
  (
    _,
    res
  ) => {
    res.send(
      htmlPage(
        "Pagamento aprovado",
        "Pagamento concluído. Você já pode voltar ao app."
      )
    );
  }
);

app.get(
  "/pending",
  (
    _,
    res
  ) => {
    res.send(
      htmlPage(
        "Pagamento pendente",
        "Seu pagamento está pendente. Volte ao app para acompanhar o status."
      )
    );
  }
);

app.get(
  "/failure",
  (
    _,
    res
  ) => {
    res.send(
      htmlPage(
        "Pagamento não concluído",
        "O pagamento não foi concluído. Você pode tentar novamente no app."
      )
    );
  }
);

app.get(
  "/reset-password",
  (
    _,
    res
  ) => {
    res.send(
      resetPasswordPage()
    );
  }
);

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }

    if (
      error?.type ===
      "entity.too.large"
    ) {
      return res
        .status(413)
        .json({
          ok:
            false,

          code:
            "REQUEST_TOO_LARGE",

          message:
            "O arquivo ou conteúdo enviado é grande demais.",
        });
    }

    if (
      error?.message ===
      "CORS_ORIGIN_NOT_ALLOWED"
    ) {
      return res
        .status(403)
        .json({
          ok:
            false,

          code:
            "CORS_ORIGIN_NOT_ALLOWED",

          message:
            "Origem não autorizada.",
        });
    }

    console.error(
      "Unhandled Express error:",
      error?.message ||
      error
    );

    return res
      .status(500)
      .json({
        ok:
          false,

        code:
          "SERVER_ERROR",

        message:
          "Erro interno do servidor.",
      });
  }
);

let server = null;




async function start() {
  validateCriticalRuntimeConfig();

  try {
    await ensurePublicApiConfig();

  
  } catch (error) {
    console.error(
      "Falha ao sincronizar public_config/api:",
      error?.code ||
        error?.message ||
        "unknown_error"
    );
  }

  server = app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `FireRank API ${FIRERANK_SCHEMA_VERSION} online na porta ${PORT}`
      );
      console.log(`Public base URL: ${APP_BASE_URL}`);
      console.log(
        `App Check enforced: ${REQUIRE_APP_CHECK}`
      );
    }
  );
}

function shutdown(signal) {
  console.log(
    `${signal}: encerrando FireRank API...`
  );

  if (!server) {
    return process.exit(0);
  }

  server.close(() =>
    process.exit(0)
  );

  setTimeout(
    () => process.exit(1),
    10_000
  ).unref();
}

process.on(
  "SIGTERM",
  () => shutdown("SIGTERM")
);
process.on(
  "SIGINT",
  () => shutdown("SIGINT")
);

process.on(
  "unhandledRejection",
  (reason) => {
    console.error(
      "Unhandled rejection:",
      reason?.code ||
        reason?.message ||
        "unknown"
    );
  }
);

start().catch((error) => {
  console.error(
    "Falha ao iniciar FireRank API:",
    error?.code ||
      error?.message ||
      "unknown_error"
  );
  process.exit(1);
});

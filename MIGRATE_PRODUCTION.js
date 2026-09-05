require("dotenv").config();
const { initializeApp, cert } = require("firebase-admin/app");
const { getDatabase } = require("firebase-admin/database");

const encoded = String(process.env.FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 || "").trim();
if (!encoded) throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON_BASE64 ausente no ambiente local/seguro");
const serviceAccount = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
const databaseURL = String(process.env.FIREBASE_DATABASE_URL || "").trim();
if (!databaseURL) throw new Error("FIREBASE_DATABASE_URL ausente");
const app = initializeApp({ credential: cert(serviceAccount), databaseURL });
const db = getDatabase(app);
const base = "https://firerank-api-oxy1.onrender.com";
const t = Date.now();

(async () => {
  const updates = {
    "public_config/app/schemaVersion": "4.2.0",
    "public_config/app/anonymousAuthEnabled": false,
    "public_config/app/guestBrowsingEnabled": true,
    "public_config/app/guestStorage": "shared_preferences_local",
    "public_config/api/schemaVersion": "4.2.0",
    "public_config/api/baseUrl": base,
    "public_config/api/gatewayBaseUrl": base,
    "public_config/api/backendBaseUrl": base,
    "public_config/api/productCreateEndpoint": base + "/v1/products",
    "public_config/api/productUpdateEndpoint": base + "/v1/products/update",
    "public_config/api/productActionEndpoint": base + "/v1/products/action",
    "public_config/api/productEventEndpoint": base + "/v1/products/event",
    "public_config/api/mediaSignEndpoint": base + "/v1/media/sign",
    "public_config/api/mediaCompleteEndpoint": base + "/v1/media/complete",
    "public_config/api/addressSaveEndpoint": base + "/v1/account/address",
    "public_config/api/accountProfileEndpoint": base + "/v1/account/profile",
    "public_config/api/accountPrivacyEndpoint": base + "/v1/account/privacy",
    "public_config/api/accountDeleteEndpoint": base + "/v1/account/delete-request",
    "public_config/api/accountExportEndpoint": base + "/v1/account/export",
    "public_config/api/guestMergeEndpoint": base + "/v1/account/guest-merge",
    "public_config/api/orderCreateEndpoint": base + "/v1/orders",
    "public_config/api/orderActionEndpoint": base + "/v1/orders/action",
    "public_config/api/chatStartEndpoint": base + "/v1/chats/start",
    "public_config/api/reviewEndpoint": base + "/v1/reviews",
    "public_config/api/reportEndpoint": base + "/v1/reports",
    "public_config/api/deliveryOrderActionEndpoint": base + "/v1/delivery/orders/action",
    "public_config/api/deliveryConnectionRequestEndpoint": base + "/v1/delivery/connections/request",
    "public_config/api/deliveryConnectionRespondEndpoint": base + "/v1/delivery/connections/respond",
    "public_config/api/deliveryConnectionUpdateEndpoint": base + "/v1/delivery/connections/update",
    "public_config/api/boostCatalogEndpoint": base + "/v1/boost/catalog",
    "public_config/api/billingMercadoPagoEndpoint": base + "/v1/billing/mercadopago/create-preference",
    "public_config/api/sellerApplicationEndpoint": base + "/v1/applications/seller",
    "public_config/api/deliveryApplicationEndpoint": base + "/v1/applications/delivery",
    "public_config/api/adminApplicationDecisionEndpointTemplate": base + "/v1/admin/applications/{role}/{uid}/decision",
    "public_config/api/supportChatEndpoint": base + "/v1/support/chat",
    "public_config/api/aiAssistantEndpoint": base + "/v1/ai/v2/chat",
    "public_config/api/analyticsBannerEndpoint": base + "/v1/analytics/banner",
    "public_config/api/mediaProvider": "cloudinary",
    "public_config/api/firebaseStorageUsed": false,
    "public_config/api/updatedAtMs": t,
    "public_config/media/provider": "cloudinary",
    "public_config/media/cloudName": "dkrwufqxc",
    "public_config/media/directUpload": true,
    "public_config/media/firebaseStorageUsed": false,

    "anonymous_policy/enabled": false,
    "anonymous_policy/authMethod": "none_local_guest",
    "anonymous_policy/localGuestEnabled": true,
    "anonymous_policy/localStorage": "shared_preferences",
    "anonymous_policy/mergeEndpoint": base + "/v1/account/guest-merge",
    "anonymous_policy/preserveUidWhenLinkingCredential": false,
    "anonymous_policy/mergeCartAndFavoritesIfCredentialAlreadyExists": true,

    "subscription_plans/normal": {
      planId: "verified_normal", displayName: "Verificado", currency: "BRL", billingPeriod: "monthly", priceCents: 3499, activeForLaunch: true, identityVerificationRequired: true,
      features: { verifiedBadge:true, aiDailyQuota:20, aiAccess:"basic", basicInsights:true, advancedInsights:false, humanSupportChat:false, prioritySupport:false, accountProtection:true, teamSeats:1 }
    },
    "subscription_plans/plus": {
      planId: "verified_plus", displayName: "Verificado Plus", currency: "BRL", billingPeriod: "monthly", priceCents: 5699, activeForLaunch: true, identityVerificationRequired: true,
      features: { verifiedBadge:true, aiDailyQuota:100, aiAccess:"plus", basicInsights:true, advancedInsights:true, humanSupportChat:true, prioritySupport:true, accountProtection:true, teamSeats:1 }
    },
    "subscription_plans/pro": {
      planId: "verified_pro", displayName: "Verificado Pro", currency: "BRL", billingPeriod: "monthly", priceCents: 8999, activeForLaunch: true, identityVerificationRequired: true,
      features: { verifiedBadge:true, aiDailyQuota:300, aiAccess:"pro", basicInsights:true, advancedInsights:true, humanSupportChat:true, prioritySupport:true, accountProtection:true, teamSeats:3, bulkListingTools:true, scheduledPublishing:true, sellerCopilot:true, analyticsExport:true }
    },

    "migration_state/production_ultra_06/version": "4.2.0",
    "migration_state/production_ultra_06/appliedAtMs": t
  };

  const officialSnap = await db.ref("official_accounts").get();
  if (officialSnap.exists() && officialSnap.val() && typeof officialSnap.val() === "object") {
    for (const [uid, raw] of Object.entries(officialSnap.val())) {
      if (!uid || !raw || typeof raw !== "object") continue;
      updates[`public_badges/${uid}`] = {
        uid,
        official: raw.active === true && raw.official !== false,
        active: raw.active === true,
        badgeType: "official",
        label: "Oficial",
        entityType: String(raw.entityType || "account").slice(0, 40),
        updatedAtMs: t
      };
    }
  }

  await db.ref().update(updates);
  console.log("MIGRACAO_OK", t, Object.keys(updates).length);
  process.exit(0);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

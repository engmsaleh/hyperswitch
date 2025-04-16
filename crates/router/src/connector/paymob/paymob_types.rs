use masking::Secret;
use serde::{Deserialize, Serialize};

use crate::types;

// Authentication Request & Response
#[derive(Debug, Serialize)]
pub struct PaymobAuthRequest {
    pub api_key: Secret<String>,
}

#[derive(Debug, Deserialize)]
pub struct PaymobAuthResponse {
    pub token: Secret<String>,
    // profile: Profile, // Add if needed
}

// Order Registration Request & Response
#[derive(Debug, Serialize)]
pub struct PaymobOrderRequest {
    pub auth_token: Secret<String>,
    pub delivery_needed: bool,
    pub amount_cents: i64,
    pub currency: String, // ISO 4217 currency code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_order_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<Item>, // Optional but recommended
    // shipping_data: Option<ShippingData>, // Add if needed
    // shipping_details: Option<ShippingDetails>, // Add if needed
}

#[derive(Debug, Serialize, Default)]
pub struct Item {
    pub name: String,
    pub amount_cents: String,
    pub description: String,
    pub quantity: String,
}

#[derive(Debug, Deserialize)]
pub struct PaymobOrderResponse {
    pub id: i64, // Paymob Order ID
    // ... other fields like created_at, shipping_data, etc.
}

// Payment Key Request & Response
#[derive(Debug, Serialize)]
pub struct PaymobPaymentKeyRequest {
    pub auth_token: Secret<String>,
    pub amount_cents: i64,
    pub expiration: u32, // Default 3600 seconds
    pub order_id: String,
    pub billing_data: BillingData,
    pub currency: String,
    pub integration_id: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_order_when_paid: Option<String>, // "true" or "false"
    // ... other optional fields like customer_id, tokenization, etc.
}

#[derive(Debug, Serialize, Default)]
pub struct BillingData {
    pub apartment: String,
    pub email: String,
    pub floor: String,
    pub first_name: String,
    pub street: String,
    pub building: String,
    pub phone_number: String,
    pub shipping_method: String, // Consider making this optional or enum
    pub postal_code: String,
    pub city: String,
    pub country: String,
    pub last_name: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct PaymobPaymentKeyResponse {
    pub token: Secret<String>, // The payment key to be used in iframe/redirection
}

// Generic Error Response
#[derive(Debug, Deserialize)]
pub struct PaymobErrorResponse {
    pub message: String,
    pub errors: Option<serde_json::Value>, // Can be object or string
    pub detail: Option<String>,
    pub error: Option<String>,
}

// Webhook Types (Placeholder - Define based on specific webhook events)
#[derive(Debug, Deserialize)]
pub struct PaymobWebhookObject {
    pub id: i64,
    pub pending: bool,
    pub amount_cents: i64,
    pub success: bool,
    pub is_auth: bool,
    pub is_capture: bool,
    pub is_standalone_payment: bool,
    pub is_voided: bool,
    pub is_refunded: bool,
    pub is_3d_secure: bool,
    pub integration_id: i64,
    pub profile_id: i64,
    pub has_parent_transaction: bool,
    pub order: PaymobWebhookOrder,
    pub created_at: String, // Consider parsing to DateTime
    pub currency: String,
    pub terminal_id: Option<i64>,
    pub merchant_commission: i64,
    pub is_void: bool,
    pub is_refund: bool,
    pub error_occured: bool, // Note the typo in Paymob's field name
    pub refunded_amount_cents: i64,
    pub captured_amount: i64,
    pub merchant_staff_tag: Option<String>,
    pub updated_at: String, // Consider parsing to DateTime
    pub is_settled: bool,
    pub bill_balanced: bool,
    pub is_bill: bool,
    pub owner: i64,
    pub data: PaymobWebhookData,
    pub source_data: PaymobWebhookSourceData,
    pub payment_key_claims: PaymobWebhookPaymentKeyClaims,
    // ... other fields
}

#[derive(Debug, Deserialize)]
pub struct PaymobWebhookOrder {
    pub id: i64,
    // ... other order fields if needed
}

#[derive(Debug, Deserialize)]
pub struct PaymobWebhookData {
    // Define fields based on the 'data' object in the webhook payload
    // e.g., card details, wallet details
    pub klass: Option<String>,
    pub gateway_integration_pk: Option<i64>,
    pub order: Option<i64>,
    pub amount: Option<i64>,
    pub created_at: Option<String>,
    pub wallet_issuer: Option<String>,
    pub method: Option<i64>,
    pub upg_txn_id: Option<String>,
    pub message: Option<String>,
    pub txn_response_code: Option<String>,
    pub avs_result_code: Option<String>,
    pub cvv_result_code: Option<String>,
    pub secure_hash: Option<String>,
    pub card_num: Option<Secret<String>>,
    pub card_type: Option<String>,
    pub pan: Option<String>,
    pub sub_type: Option<String>,
    pub type_field: Option<String>, // 'type' is a reserved keyword
}

#[derive(Debug, Deserialize)]
pub struct PaymobWebhookSourceData {
    pub pan: String, // e.g., "card", "wallet"
    pub sub_type: String, // e.g., "MasterCard", "VodafoneCash"
    #[serde(rename = "type")]
    pub type_field: String, // 'type' is a reserved keyword
}

#[derive(Debug, Deserialize)]
pub struct PaymobWebhookPaymentKeyClaims {
    pub user_id: i64,
    pub order_id: i64,
    pub billing_data: BillingData,
    pub currency: String,
    pub amount_cents: i64,
    pub integration_id: i64,
    pub lock_order_when_paid: bool,
    pub exp: i64, // Expiry timestamp
    // ... other claims
}

#[derive(Debug, Deserialize)]
pub struct PaymobWebhookRequest {
    #[serde(rename = "type")]
    pub transaction_type: String, // "TRANSACTION" or "TOKEN"
    pub obj: PaymobWebhookObject,
    pub hmac: String, // For verification
}
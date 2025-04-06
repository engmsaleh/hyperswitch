# Paymob KSA Connector Implementation Plan

## 1. Overview

This document outlines the plan for integrating the Paymob KSA payment gateway into the Hyperswitch platform. It summarizes the understanding gained from the Paymob KSA developer documentation ([https://developers.paymob.com/ksa/](https://developers.paymob.com/ksa/)).

## 2. API Base URL

The base URL for all Paymob KSA API interactions is: `https://ksa.paymob.com/`

## 3. Authentication

Paymob uses two primary authentication methods:

1.  **Secret Key Token:** Used for the initial `/v1/intention/` call.
    *   Header: `Authorization: Token <secret_key>`
    *   `<secret_key>` is obtained from the Paymob Merchant Dashboard.
2.  **Bearer Token (JWT):** Used for subsequent actions like Capture, Void, Refund, and Transaction Inquiry.
    *   Header: `Authorization: Bearer <auth_token>`
    *   This token is short-lived (60 minutes) and must be obtained first.
    *   **Auth Token Endpoint:** `POST /api/auth/tokens`
    *   **Request:** `{ "api_key": "YOUR_API_KEY" }` (API Key is separate from Secret Key, also from dashboard).
    *   **Response:** `{ "token": "...", ... }`

*Implementation Note:* A mechanism to retrieve and cache the Bearer Token using the API Key will be needed for Capture, Void, Refund, and Sync flows.

## 4. Core Payment Flows

### 4.1. Authorize / Sale (Unified Intention API)

*   **Flow:** This is the primary flow for initiating payments. It involves creating an "intention" and redirecting the user. It supports both direct capture (Sale) and authorize-only, likely controlled by the Integration ID configuration in the Paymob dashboard, although not explicitly stated for the intention API itself (Auth/Capture is mentioned as a payment *type*).
*   **Endpoint:** `POST /v1/intention/`
*   **Authentication:** Secret Key Token (`Authorization: Token ...`)
*   **Key Request Parameters:**
    *   `amount`: Integer (Minor unit, e.g., Halalas)
    *   `currency`: String (e.g., `"SAR"`)
    *   `payment_methods`: Array of Integers (Paymob Integration IDs) / Strings (e.g. `"card"`) - *Crucial configuration needed per merchant.*
    *   `billing_data`: Object (first_name, last_name, email, phone_number mandatory)
    *   `customer`: Object (first_name, last_name, email mandatory)
    *   `special_reference`: String (Optional, maps to Hyperswitch `connector_request_reference_id`)
    *   `notification_url`: String (Optional, overrides webhook)
    *   `redirection_url`: String (Optional, overrides redirect)
*   **Key Response Parameters:**
    *   `id`: String (Intention ID, `pi_...`)
    *   `client_secret`: String (Needed for redirect, `ksa_csk_...`)
    *   `status`: String (e.g., `"intended"`)
*   **Redirection:** The user must be redirected to:
    `https://ksa.paymob.com/unifiedcheckout/?publicKey=<public_key>&clientSecret=<client_secret>`
    *   `<public_key>` is obtained from the Paymob Dashboard and required in connector config.

### 4.2. Capture

*   **Purpose:** To capture funds previously authorized using an Auth/Capture configured Integration ID.
*   **Endpoint:** `POST /api/acceptance/capture`
*   **Authentication:** Bearer Token (`Authorization: Bearer ...`)
*   **Key Request Parameters:**
    *   `transaction_id`: String (ID of the *authorization* transaction)
    *   `amount_cents`: String (Amount to capture in minor units)

### 4.3. Void (Cancel)

*   **Purpose:** To cancel an authorized or captured transaction *on the same business day*.
*   **Endpoint:** `POST /api/acceptance/void_refund/void`
*   **Authentication:** Bearer Token (`Authorization: Bearer ...`)
*   **Key Request Parameters:**
    *   `transaction_id`: String (ID of the transaction to void)

### 4.4. Refund

*   **Purpose:** To refund a captured transaction (partial or full).
*   **Endpoint:** `POST /api/acceptance/void_refund/refund`
*   **Authentication:** Bearer Token (`Authorization: Bearer ...`)
*   **Key Request Parameters:**
    *   `transaction_id`: String (ID of the transaction to refund)
    *   `amount_cents`: String (Amount to refund in minor units)

### 4.5. Sync (Transaction Inquiry)

*   **Purpose:** To retrieve the status and details of a transaction.
*   **Authentication:** Bearer Token (`Authorization: Bearer ...`)
*   **Endpoints:**
    *   **Primary:** `GET /api/acceptance/transactions/<transaction_id>` (Requires Paymob transaction ID)
    *   **Alternative 1:** `POST /api/ecommerce/orders/transaction_inquiry` with `{ "order_id": "<paymob_order_id>" }`
    *   **Alternative 2:** `POST /api/ecommerce/orders/transaction_inquiry` with `{ "merchant_order_id": "<your_special_reference>" }`
*   **Implementation:** Use the `GET` endpoint if the Paymob transaction ID is available; otherwise, use the `POST` endpoint with the appropriate ID.

## 5. Webhook Handling

*   **Mechanism:** Paymob sends asynchronous `POST` requests with a JSON body to a pre-configured webhook URL ("Transaction Processed Callback") upon status changes (success, failure, void, refund).
*   **Security:** HMAC-SHA512 signature verification is mandatory.
    *   The signature is sent as a query parameter `hmac`.
    *   The HMAC Secret Key is obtained from the Paymob Dashboard and required in connector config.
    *   **Verification Process:**
        1.  Collect all key-value pairs from the JSON body.
        2.  Sort pairs alphabetically by key.
        3.  Concatenate *only the values* in the sorted order.
        4.  Calculate SHA-512 HMAC of the concatenated string using the HMAC Secret Key.
        5.  Compare the calculated digest (hex) with the received `hmac` value.
*   **Key Callback Data (`obj` field):** `id` (transaction ID), `success` (boolean), `pending` (boolean), `is_voided` (boolean), `is_refunded` (boolean), `amount_cents`, `order.id`, `order.merchant_order_id`.
*   **Status Mapping:** The `success` and `pending` flags (and `is_voided`/`is_refunded`) need careful mapping to Hyperswitch statuses (Charged, Failed, Pending, Voided, etc.).

## 6. Key Considerations & Configuration

*   **Amount Unit:** Paymob consistently uses the **minor unit** (cents/Halalas). The connector must ensure amounts are sent correctly (`get_currency_unit` should return `Minor`).
*   **Required Credentials:**
    *   Secret Key (for Intention API `Authorization: Token`)
    *   API Key (for `/api/auth/tokens` to get Bearer token)
    *   Public Key (for checkout redirect URL)
    *   HMAC Secret Key (for webhook validation)
    *   Integration ID(s) (Specific IDs for Card, MADA, etc., configured in Paymob dashboard)
*   **Auth Token Management:** Implement retrieval and caching for the Bearer token used in Capture, Void, Refund, Sync APIs.
*   **IDs:** Distinguish between Paymob Order ID (`order.id` in callbacks), Paymob Transaction ID (`id` in callbacks/responses), Intention ID (`pi_...`), and Merchant Order ID (`special_reference`/`merchant_order_id`). Store the Paymob Transaction ID for future operations (Void, Refund, Sync).

## 7. High-Level Implementation Plan

1.  **Setup:** Create the connector directory (`paymob`) within `crates/hyperswitch_connectors/src/connectors/` by copying and renaming the `connector-template`.
2.  **Transformers (`transformers.rs`):**
    *   Define request structs for Intention, Capture, Void, Refund, Auth Token.
    *   Define response structs for Intention, Capture, Void, Refund, Sync, Auth Token, Error.
    *   Implement `TryFrom<RouterData>` for request structs.
    *   Define `PaymobStatus` enum and implement `From<PaymobStatus> for AttemptStatus`.
    *   Implement `TryFrom<ResponseRouterData>` for response structs.
3.  **Core Implementation (`mod.rs`):**
    *   Implement `ConnectorCommon` (ID, base URL, content type, currency unit, error handling, `get_auth_header` - handle both Token and Bearer).
    *   Implement `ConnectorIntegration` for `Authorize` (call Intention API, return redirect data with client_secret and public_key).
    *   Implement `ConnectorIntegration` for `Capture`.
    *   Implement `ConnectorIntegration` for `Void`.
    *   Implement `ConnectorIntegration` for `RefundExecute`.
    *   Implement `ConnectorIntegration` for `PSync` (using transaction inquiry API).
4.  **Authentication Helper:** Create a utility/service to get/cache the Bearer Token using the API Key.
5.  **Webhook Handler:** Implement the webhook logic (`trait Webhook`), including HMAC validation and status mapping based on the processed callback structure.
6.  **Configuration:** Define necessary fields in `crates/connector_configs/` and ensure they are loaded correctly.
7.  **Testing:** Add comprehensive unit and integration tests, mocking API responses and webhook payloads.
8.  **Registration:** Add `paymob` to the `Connector` enum and register it in the router. 
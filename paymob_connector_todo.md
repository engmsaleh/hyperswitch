# Paymob KSA Connector To-Do List

## Phase 1: Setup & Basic Structure

- [x] Create connector directory: `crates/hyperswitch_connectors/src/connectors/paymob/`
- [x] Copy contents from `connector-template/` into the new `paymob/` directory.
- [x] Rename placeholders (`{{project-name}}`, etc.) in `mod.rs`, `transformers.rs`, `test.rs` to `paymob`.
- [x] Update `ConnectorCommon::id()` in `mod.rs` to return `"paymob"`.
- [x] Update `ConnectorCommon::base_url()` in `mod.rs` to point to Paymob KSA base URL.
- [x] Update `ConnectorCommon::get_currency_unit()` in `mod.rs` to return `Minor`.
- [x] Add `pub mod paymob;` to `crates/hyperswitch_connectors/src/connectors.rs`.
- [x] Add `pub use paymob::Paymob;` to the `pub use self::{...}` block in `crates/hyperswitch_connectors/src/connectors.rs`.
- [x] Add `Paymob` variant to `Connector` enum in `crates/router_env/src/types/storage/enums.rs`.
- [x] Add `Paymob` mapping in `impl TryFrom<&api_models::enums::Connector> for Connector` in `crates/router/src/connector.rs`.
- [x] Add `Paymob` mapping in `impl From<Connector> for api_models::enums::Connector` in `crates/router/src/connector.rs`.
- [x] Add `Paymob` to the `CONNECTOR_REGISTRY` macro call in `crates/router/src/connector.rs`.
- [x] Add basic config section `[paymob]` to `crates/connector_configs/toml/development.toml` (even if just placeholders for keys initially).
- [x] Add `paymob: Option<PaymobConfig>` to `Connectors` struct in `crates/connector_configs/src/connector.rs`.

## Phase 2: Authentication

- [x] Define `PaymobAuthType` enum/struct in `paymob/transformers.rs` to hold `api_key`, `secret_key`, `public_key`, `hmac_secret`.
- [x] Implement `TryFrom<&ConnectorAuthType>` for `PaymobAuthType`.
- [x] Implement `ConnectorCommon::get_auth_header()` in `paymob/mod.rs` to handle both `Token <secret_key>` and `Bearer <auth_token>` based on flow context (requires a way to pass flow context or manage tokens separately).
- [x] **Auth Token Helper:**
    - [x] Define request/response structs for `POST /api/auth/tokens` in `paymob/transformers.rs`.
    - [x] Create a helper function/service (potentially in `paymob/mod.rs` or `paymob/utils.rs`) to call `/api/auth/tokens` using the API Key.
    - [x] Implement caching logic for the retrieved Bearer token (consider using `redis_interface` or an in-memory cache with expiry).

## Phase 3: Core Payment Flow (Authorize/Sale)

- [x] **Transformers (`paymob/transformers.rs`):**
    - [x] Define `PaymobIntentionRequest` struct matching `POST /v1/intention/` body.
    - [x] Define `PaymobIntentionResponse` struct matching `POST /v1/intention/` response.
    - [x] Define `PaymobBillingData`, `PaymobCustomer`, `PaymobItem` structs.
    - [x] Implement `TryFrom<&PaymentsAuthorizeRouterData>` for `PaymobIntentionRequest`.
    - [x] Implement `TryFrom<ResponseRouterData<PaymobIntentionResponse>>` for `PaymentsAuthorizeRouterData` (to extract `client_secret`, `id`, map status, create redirect form).
- [x] **Implementation (`paymob/mod.rs`):**
    - [x] Implement `ConnectorIntegration<Authorize, ...>` methods:
        - [x] `get_url()`: Return `/v1/intention/` path.
        - [x] `get_headers()`: Use `ConnectorCommonExt::build_headers` (ensure it uses Secret Key Token for this flow).
        - [x] `get_request_body()`: Use transformer to create `PaymobIntentionRequest`.
        - [x] `build_request()`: Assemble the `POST` request.
        - [x] `handle_response()`: Use transformer to parse `PaymobIntentionResponse`, extract `client_secret`, build the redirect URL using `public_key` from config, and return `RouterData` with `RedirectionResponse`.

## Phase 4: Other Payment Flows (Capture, Void, Refund, Sync)

- [x] **Transformers (`paymob/transformers.rs`):**
    - [x] Define `PaymobCaptureRequest`, `PaymobVoidRequest`, `PaymobRefundRequest` structs.
    - [x] Define common `PaymobTransactionResponse` struct for Capture/Void/Refund responses.
    - [x] Define `PaymobTransactionInquiryResponse` struct for Sync response.
    - [x] Implement `TryFrom<&PaymentsCaptureRouterData>` for `PaymobCaptureRequest`.
    - [x] Implement `TryFrom<&PaymentsCancelRouterData>` for `PaymobVoidRequest`.
    - [x] Implement `TryFrom<&RefundsRouterData>` for `PaymobRefundRequest`.
    - [x] Implement `TryFrom<ResponseRouterData<PaymobTransactionResponse>>` for `PaymentsCaptureRouterData`.
    - [x] Implement `TryFrom<ResponseRouterData<PaymobTransactionResponse>>` for `PaymentsCancelRouterData`.
    - [x] Implement `TryFrom<ResponseRouterData<PaymobTransactionResponse>>` for `RefundsRouterData`.
    - [x] Implement `TryFrom<ResponseRouterData<PaymobTransactionInquiryResponse>>` for `PaymentsSyncRouterData`.
- [x] **Implementation (`paymob/mod.rs`):**
    - [x] Implement `ConnectorIntegration<Capture, ...>`:
        - [x] Use Auth Token Helper to get Bearer token.
        - [x] Implement methods to call `POST /api/acceptance/capture`.
    - [x] Implement `ConnectorIntegration<Void, ...>`:
        - [x] Use Auth Token Helper to get Bearer token.
        - [x] Implement methods to call `POST /api/acceptance/void_refund/void`.
    - [x] Implement `ConnectorIntegration<RefundExecute, ...>`:
        - [x] Use Auth Token Helper to get Bearer token.
        - [x] Implement methods to call `POST /api/acceptance/void_refund/refund`.
    - [x] Implement `ConnectorIntegration<PSync, ...>`:
        - [x] Use Auth Token Helper to get Bearer token.
        - [x] Implement methods to call `GET /api/acceptance/transactions/<transaction_id>`.

## Phase 5: Webhook Handling

- [x] **Transformers (`paymob/transformers.rs`):**
    - [x] Define `PaymobWebhookPayload` struct based on the "Transaction Processed Callback" JSON structure (`type`, `obj`).
    - [x] Define `PaymobWebhookObject` struct based on the `obj` field content.
- [x] **Implementation (`paymob/mod.rs`):**
    - [x] Implement `trait WebhookHandler` for `Paymob`.
    - [x] Implement `get_webhook_source_verification_algorithm()`.
    - [x] Implement `get_webhook_source_verification_details()` (return HMAC secret key).
    - [ ] Implement `get_webhook_source_verification_message()` -> _**(TODO: Requires core changes for Paymob's specific HMAC message construction)**_
    - [x] Implement `get_webhook_object_reference_id()` (extract transaction ID from payload).
    - [x] Implement `get_webhook_event_type()` (map webhook object state to `WebhookEvent`).
    - [x] Implement `get_webhook_resource_object()` (parse the JSON body into `PaymobWebhookPayload`).
    - [x] Implement `get_webhook_api_response()` -> _(Not explicitly needed with `WebhookHandler` trait)_.
- [ ] **HMAC Verification Logic:**
    - [ ] Implement the sorting, concatenation, and SHA-512 HMAC calculation logic as described in docs. -> _**(TODO: Requires core changes)**_
    - [ ] Integrate this logic into the webhook verification flow (likely within Hyperswitch core webhook processing based on details from `get_webhook_source_verification...` methods).

## Phase 6: Testing & Refinement

- [ ] Add unit tests for transformers (request/response mapping, status mapping).
- [x] Add integration tests (`paymob/test.rs`) covering:
    - [x] Authorize flow (3DS redirect, direct success, failure).
    - [x] Capture flow (full, partial, failure).
    - [x] Void flow (success, failure).
    - [x] Refund flow (full, partial, multiple, failure).
    - [x] Sync flow (payment, refund).
    - [ ] Webhook processing (HMAC validation, various statuses) -> _**(TODO: Blocked by core HMAC changes)**_
- [ ] Perform manual end-to-end testing using Paymob test credentials.
- [ ] Refine error mapping in `ConnectorCommon::build_error_response()`. 
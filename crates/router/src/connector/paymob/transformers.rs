use error_stack::{IntoReport, ResultExt};
use masking::ExposeInterface;
use serde::{Deserialize, Serialize};

use crate::{
    configs::settings,
    connector::utils::{self as conn_utils, PaymentsAuthorizeRequestData, RouterData},
    core::errors::{self, CustomResult},
    headers,
    services::{self, ConnectorIntegration, ConnectorValidation},
    types::{self, api, storage::enums, ErrorResponse, Response},
};

use super::paymob_types::{self as paymob, PaymobAuthRequest, PaymobAuthResponse, PaymobErrorResponse, PaymobOrderRequest, PaymobOrderResponse, PaymobPaymentKeyRequest, PaymobPaymentKeyResponse};

// Auth Struct - Assuming Paymob uses API Key in request body or header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymobAuthType {
    pub api_key: String,
    pub hmac_secret: String,
    pub card_integration_id: String,
    pub wallet_integration_id: String,
    pub acceptance_iframe_id: String,
}

impl TryFrom<&types::ConnectorAuthType> for PaymobAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &types::ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            types::ConnectorAuthType::BodyKey { api_key, key1, .. } => Ok(Self {
                api_key: api_key.to_string(),
                // Assuming key1 holds a JSON string with the other secrets
                hmac_secret: key1.peek().parse_value::<PaymobConfigSecrets>("PaymobConfigSecrets")?.hmac_secret,
                card_integration_id: key1.peek().parse_value::<PaymobConfigSecrets>("PaymobConfigSecrets")?.card_integration_id,
                wallet_integration_id: key1.peek().parse_value::<PaymobConfigSecrets>("PaymobConfigSecrets")?.wallet_integration_id,
                acceptance_iframe_id: key1.peek().parse_value::<PaymobConfigSecrets>("PaymobConfigSecrets")?.acceptance_iframe_id,
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// Helper struct to parse secrets from key1
#[derive(Debug, Deserialize)]
struct PaymobConfigSecrets {
    hmac_secret: String,
    card_integration_id: String,
    wallet_integration_id: String,
    acceptance_iframe_id: String,
}


impl<F, T> TryFrom<types::ResponseRouterData<F, paymob::PaymobAuthResponse, T, types::PaymentsResponseData>>
    for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<F, paymob::PaymobAuthResponse, T, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Store the auth token in metadata or handle as needed
        // This is just a placeholder transformation
        Ok(Self { ..item.router_data })
    }
}

// PaymentsAuthorizeRouterData
impl<F> TryFrom<&types::RouterData<F, types::PaymentsAuthorizeData, types::PaymentsResponseData>>
    for paymob::PaymobAuthRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &types::RouterData<F, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = PaymobAuthType::try_from(&item.connector_auth_type)?;
        Ok(Self { api_key: auth.api_key.into() })
    }
}

impl<F> TryFrom<&types::RouterData<F, types::PaymentsAuthorizeData, types::PaymentsResponseData>>
    for paymob::PaymobOrderRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &types::RouterData<F, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // Extract auth token from metadata (assuming it was stored after auth call)
        let auth_token = item
            .request
            .connector_meta
            .clone()
            .ok_or(errors::ConnectorError::MissingRequiredField { field_name: "auth_token" })?
            .parse_value::<String>("auth_token")
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            auth_token: auth_token.into(),
            delivery_needed: false, // Adjust based on actual requirements
            amount_cents: item.request.amount,
            currency: item.request.currency.to_string(),
            merchant_order_id: Some(item.connector_request_reference_id.clone()),
            items: vec![], // Populate if item details are available
        })
    }
}

impl<F> TryFrom<&types::RouterData<F, types::PaymentsAuthorizeData, types::PaymentsResponseData>>
    for paymob::PaymobPaymentKeyRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &types::RouterData<F, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = PaymobAuthType::try_from(&item.connector_auth_type)?;
        let auth_token = item
            .request
            .connector_meta
            .clone()
            .ok_or(errors::ConnectorError::MissingRequiredField { field_name: "auth_token" })?
            .parse_value::<String>("auth_token")
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let order_id = item
            .request
            .connector_meta
            .clone()
            .ok_or(errors::ConnectorError::MissingRequiredField { field_name: "order_id" })?
            .parse_value::<String>("order_id")
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;

        let billing = item.request.get_billing()?;
        let billing_address = billing
            .address
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField { field_name: "billing.address" })?;

        let integration_id = match item.request.payment_method_data {
            api::PaymentMethodData::Card(_) => auth.card_integration_id,
            api::PaymentMethodData::Wallet(_) => auth.wallet_integration_id,
            _ => return Err(errors::ConnectorError::NotImplemented("Payment method not supported".to_string()).into()),
        };

        Ok(Self {
            auth_token: auth_token.into(),
            amount_cents: item.request.amount,
            expiration: 3600, // Default or configure
            order_id,
            billing_data: paymob::BillingData {
                apartment: billing_address.line1.clone().unwrap_or_else(|| "NA".to_string()).expose(), // Adjust mapping
                email: item.request.email.clone().map(|e| e.expose()).unwrap_or_else(|| "NA".to_string()), // Adjust mapping
                floor: billing_address.line2.clone().unwrap_or_else(|| "NA".to_string()).expose(), // Adjust mapping
                first_name: billing_address.first_name.clone().unwrap_or_else(|| "NA".to_string()).expose(),
                street: billing_address.line3.clone().unwrap_or_else(|| "NA".to_string()).expose(), // Adjust mapping
                building: "NA".to_string(), // Add if available
                phone_number: billing.phone.clone().map(|p| p.number.expose()).unwrap_or_else(|| "NA".to_string()), // Adjust mapping
                shipping_method: "PKG".to_string(), // Default or configure
                postal_code: billing_address.zip.clone().unwrap_or_else(|| "NA".to_string()).expose(),
                city: billing_address.city.clone().unwrap_or_else(|| "NA".to_string()),
                country: billing_address.country.map(|c| c.to_string()).unwrap_or_else(|| "NA".to_string()),
                last_name: billing_address.last_name.clone().unwrap_or_else(|| "NA".to_string()).expose(),
                state: billing_address.state.clone().unwrap_or_else(|| "NA".to_string()).expose(),
            },
            currency: item.request.currency.to_string(),
            integration_id: integration_id.into(),
            lock_order_when_paid: Some("false".to_string()), // Default or configure
        })
    }
}

// PaymentsResponse
impl TryFrom<types::ResponseRouterData<api::Payments, paymob::PaymobPaymentKeyResponse, types::PaymentsAuthorizeData, types::PaymentsResponseData>>
    for types::RouterData<api::Payments, types::PaymentsAuthorizeData, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<api::Payments, paymob::PaymobPaymentKeyResponse, types::PaymentsAuthorizeData, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = PaymobAuthType::try_from(&item.router_data.connector_auth_type)?;
        let payment_key = item.response.token.expose();
        let iframe_id = auth.acceptance_iframe_id;

        // Construct the redirection URL
        // Example for KSA: https://ksa.paymob.com/api/acceptance/iframes/{iframe_id}?payment_token={payment_key}
        // Adjust the base URL based on the region/environment
        let redirection_url = format!(
            "https://ksa.paymob.com/api/acceptance/iframes/{}?payment_token={}",
            iframe_id,
            payment_key
        );

        Ok(item.router_data.set_response(Ok(
            types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::NoResponseId, // Paymob doesn't return a transaction ID here
                redirection_data: Some(services::RedirectForm::Form {
                    endpoint: redirection_url,
                    method: services::Method::Get,
                    form_fields: std::collections::HashMap::new(), // No form fields needed for GET redirect
                }),
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charge_id: None,
            }
        )))
    }
}

// Error Response
impl TryFrom<paymob::PaymobErrorResponse> for ErrorResponse {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: paymob::PaymobErrorResponse) -> Result<Self, Self::Error> {
        // Map Paymob error messages to standard error responses
        // This is a basic mapping, refine based on specific Paymob errors
        let reason = item.detail.or(item.message).or(item.error);
        Ok(Self {
            status_code: reqwest::StatusCode::BAD_REQUEST, // Default, adjust if possible
            code: consts::NO_ERROR_CODE.to_string(), // Default, adjust if possible
            message: consts::NO_ERROR_MESSAGE.to_string(), // Default, adjust if possible
            reason,
            attempt_status: None,
            connector_transaction_id: None,
        })
    }
}

// TODO: Implement transformers for other flows like Sync, Capture, Void, Refund, Webhooks
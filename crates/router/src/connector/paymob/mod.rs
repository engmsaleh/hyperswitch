// Connector implementation for PayMob

pub mod paymob_types;
pub mod transformers;

use std::fmt::Debug;

use common_utils::request::Method;
use error_stack::{IntoReport, ResultExt};
use masking::ExposeInterface;
use serde_json::Value;

use crate::{
    configs::settings,
    connector::utils::{self as conn_utils, PaymentsAuthorizeRequestData, RouterData},
    core::errors::{self, ConnectorError, CustomResult},
    headers,
    services::{
        self,
        connector_integration_interface::ConnectorIntegrationInterface,
        request::{self, Mask, Maskable},
        ConnectorIntegration, ConnectorValidation,
    },
    types::{self, api, storage::enums, ErrorResponse, Response, ResponseRouterData},
};

use paymob_types::{
    PaymobAuthRequest, PaymobAuthResponse, PaymobErrorResponse, PaymobOrderRequest,
    PaymobOrderResponse, PaymobPaymentKeyRequest, PaymobPaymentKeyResponse, PaymobWebhookRequest,
};
use transformers as paymob;

#[derive(Debug, Clone)]
pub struct Paymob;

impl api::Payment for Paymob {}
impl api::PaymentAuthorize for Paymob {}
impl api::PaymentSync for Paymob {}
impl api::PaymentVoid for Paymob {}
impl api::PaymentCapture for Paymob {}
impl api::PaymentSession for Paymob {}
impl api::PaymentMandate for Paymob {}
impl api::ConnectorAccessToken for Paymob {}
impl api::PaymentToken for Paymob {}

impl
    ConnectorIntegration<
        api::PaymentMethodToken,
        types::PaymentMethodTokenizationData,
        types::PaymentsResponseData,
    > for Paymob
{
    // Not Implemented
}

impl ConnectorValidation for Paymob {
    // Implement connector validation logic if required
}

impl ConnectorIntegration<api::Session, types::PaymentsSessionData, types::PaymentsResponseData>
    for Paymob
{
    // Not Implemented
}

impl ConnectorIntegration<api::AccessTokenAuth, types::AccessTokenRequestData, types::AccessToken>
    for Paymob
{
    // Not Implemented
}

// Paymob Authorize flow is multi-step:
// 1. Authentication Request -> Get Auth Token
// 2. Order Registration Request -> Get Order ID
// 3. Payment Key Request -> Get Payment Token (for redirection)

impl ConnectorIntegrationInterface for Paymob {
    fn get_multiple_authorize_steps(
        &self,
        _payment_data: &types::PaymentIntentData,
        _connector_base_url: &str,
    ) -> CustomResult<Option<Vec<services::RequestInfo>>, errors::ConnectorError> {
        // Define the sequence of API calls for the authorize flow
        let auth_request_info = services::RequestInfo {
            connector_method: services::ConnectorMethod::Authentication,
            method: Method::Post,
            url: Some(String::from("https://accept.paymob.com/api/auth/tokens")),
            headers: None,
            body: None, // Body will be added in build_request
        };
        let order_request_info = services::RequestInfo {
            connector_method: services::ConnectorMethod::OrderRegistration,
            method: Method::Post,
            url: Some(String::from(
                "https://accept.paymob.com/api/ecommerce/orders",
            )),
            headers: None,
            body: None, // Body will be added in build_request
        };
        let payment_key_request_info = services::RequestInfo {
            connector_method: services::ConnectorMethod::PaymentKeyGeneration,
            method: Method::Post,
            url: Some(String::from(
                "https://accept.paymob.com/api/acceptance/payment_keys",
            )),
            headers: None,
            body: None, // Body will be added in build_request
        };

        Ok(Some(vec![
            auth_request_info,
            order_request_info,
            payment_key_request_info,
        ]))
    }
}

impl ConnectorIntegration<api::Authorize, types::PaymentsAuthorizeData, types::PaymentsResponseData>
    for Paymob
{
    fn get_headers(
        &self,
        _req: &types::PaymentsAuthorizeRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![(
            headers::CONTENT_TYPE.to_string(),
            "application/json".into(),
        )])
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    // URL is determined by get_multiple_authorize_steps
    fn get_url(
        &self,
        _req: &types::PaymentsAuthorizeRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented(
            "get_url should not be called for multi-step flow",
        )
        .into())
    }

    fn get_request_body(
        &self,
        req: &types::PaymentsAuthorizeRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<types::RequestBody>, errors::ConnectorError> {
        let connector_req_body = match req.connector_meta.clone().map(|v| v.peek().clone()) {
            Some(Value::String(s)) if s == "Authentication" => {
                let req_obj = paymob::PaymobAuthRequest::try_from(req)?;
                types::RequestBody::log_and_get_request_body(&req_obj, masking::Maskable::Mask)
                    .change_context(errors::ConnectorError::RequestEncodingFailed)?
            }
            Some(Value::String(s)) if s == "OrderRegistration" => {
                let req_obj = paymob::PaymobOrderRequest::try_from(req)?;
                types::RequestBody::log_and_get_request_body(&req_obj, masking::Maskable::Mask)
                    .change_context(errors::ConnectorError::RequestEncodingFailed)?
            }
            Some(Value::String(s)) if s == "PaymentKeyGeneration" => {
                let req_obj = paymob::PaymobPaymentKeyRequest::try_from(req)?;
                types::RequestBody::log_and_get_request_body(&req_obj, masking::Maskable::Mask)
                    .change_context(errors::ConnectorError::RequestEncodingFailed)?
            }
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_meta indicating step",
                }
                .into())
            }
        };
        Ok(Some(connector_req_body))
    }

    fn build_request(
        &self,
        req: &types::PaymentsAuthorizeRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        // The actual URL is determined by the step in the multi-step flow
        // This function might need adjustment based on how the multi-step execution is handled
        let url = match req.connector_meta.clone().map(|v| v.peek().clone()) {
            Some(Value::String(s)) if s == "Authentication" => {
                "https://accept.paymob.com/api/auth/tokens"
            }
            Some(Value::String(s)) if s == "OrderRegistration" => {
                "https://accept.paymob.com/api/ecommerce/orders"
            }
            Some(Value::String(s)) if s == "PaymentKeyGeneration" => {
                "https://accept.paymob.com/api/acceptance/payment_keys"
            }
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "connector_meta indicating step url",
                }
                .into())
            }
        };

        Ok(Some(
            services::RequestBuilder::new()
                .method(services::Method::Post)
                .url(url)
                .attach_default_headers()
                .headers(types::PaymentsAuthorizeType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsAuthorizeType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &types::PaymentsAuthorizeRouterData,
        res: Response,
    ) -> CustomResult<types::PaymentsAuthorizeRouterData, errors::ConnectorError> {
        let response: serde_json::Value = res
            .response
            .parse_struct("Paymob Response")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        match data.connector_meta.clone().map(|v| v.peek().clone()) {
            Some(Value::String(s)) if s == "Authentication" => {
                let auth_response: PaymobAuthResponse = serde_json::from_value(response)
                    .into_report()
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                // Store auth_token in metadata for the next step
                let updated_data = data
                    .clone()
                    .add_connector_meta_key("auth_token", auth_response.token.expose());
                Ok(updated_data)
            }
            Some(Value::String(s)) if s == "OrderRegistration" => {
                let order_response: PaymobOrderResponse = serde_json::from_value(response)
                    .into_report()
                    .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                // Store order_id in metadata for the next step
                let updated_data = data
                    .clone()
                    .add_connector_meta_key("order_id", order_response.id.to_string());
                Ok(updated_data)
            }
            Some(Value::String(s)) if s == "PaymentKeyGeneration" => {
                let payment_key_response: PaymobPaymentKeyResponse =
                    serde_json::from_value(response)
                        .into_report()
                        .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
                // This is the final step, build the redirection response using the transformer
                // The transformer will construct the redirection URL
                types::RouterData::try_from(types::ResponseRouterData {
                    response: payment_key_response,
                    data: data.clone(),
                    http_code: res.status_code,
                })
            }
            _ => Err(errors::ConnectorError::ResponseHandlingFailed.into()),
        }
    }

    fn get_error_response(
        &self,
        res: Response,
        // error_context: Option<ErrorContext<'_>>,
    ) -> CustomResult<types::ErrorResponse, errors::ConnectorError> {
        let response: PaymobErrorResponse = res
            .response
            .parse_struct("PaymobErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        ErrorResponse::try_from(response)
    }
}

impl ConnectorIntegration<api::PSync, types::PaymentsSyncData, types::PaymentsResponseData>
    for Paymob
{
    // TODO: Implement PSync
    fn get_headers(
        &self,
        _req: &types::PaymentsSyncRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("PSync Headers").into())
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        _req: &types::PaymentsSyncRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("PSync URL").into())
    }

    fn build_request(
        &self,
        _req: &types::PaymentsSyncRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("PSync Build Request").into())
    }

    fn handle_response(
        &self,
        _data: &types::PaymentsSyncRouterData,
        _res: Response,
    ) -> CustomResult<types::PaymentsSyncRouterData, errors::ConnectorError>
    where
        types::PaymentsResponseData: Clone,
    {
        Err(errors::ConnectorError::NotImplemented("PSync Handle Response").into())
    }

    fn get_error_response(
        &self,
        res: Response,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res)
    }
}

impl ConnectorIntegration<api::Capture, types::PaymentsCaptureData, types::PaymentsResponseData>
    for Paymob
{
    // TODO: Implement Capture
    fn get_headers(
        &self,
        _req: &types::PaymentsCaptureRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Capture Headers").into())
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        _req: &types::PaymentsCaptureRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Capture URL").into())
    }

    fn get_request_body(
        &self,
        _req: &types::PaymentsCaptureRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<types::RequestBody>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Capture Request Body").into())
    }

    fn build_request(
        &self,
        _req: &types::PaymentsCaptureRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Capture Build Request").into())
    }

    fn handle_response(
        &self,
        _data: &types::PaymentsCaptureRouterData,
        _res: Response,
    ) -> CustomResult<types::PaymentsCaptureRouterData, errors::ConnectorError>
    where
        types::PaymentsCaptureData: Clone,
        types::PaymentsResponseData: Clone,
    {
        Err(errors::ConnectorError::NotImplemented("Capture Handle Response").into())
    }

    fn get_error_response(
        &self,
        res: Response,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res)
    }
}

impl ConnectorIntegration<api::Void, types::PaymentsCancelData, types::PaymentsResponseData>
    for Paymob
{
    // TODO: Implement Void
    fn get_headers(
        &self,
        _req: &types::PaymentsCancelRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Void Headers").into())
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        _req: &types::PaymentsCancelRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Void URL").into())
    }

    fn get_request_body(
        &self,
        _req: &types::PaymentsCancelRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<types::RequestBody>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Void Request Body").into())
    }

    fn build_request(
        &self,
        _req: &types::PaymentsCancelRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Void Build Request").into())
    }

    fn handle_response(
        &self,
        _data: &types::PaymentsCancelRouterData,
        _res: Response,
    ) -> CustomResult<types::PaymentsCancelRouterData, errors::ConnectorError>
    where
        types::PaymentsCancelData: Clone,
        types::PaymentsResponseData: Clone,
    {
        Err(errors::ConnectorError::NotImplemented("Void Handle Response").into())
    }

    fn get_error_response(
        &self,
        res: Response,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res)
    }
}

impl api::Refund for Paymob {}
impl api::RefundExecute for Paymob {}
impl api::RefundSync for Paymob {}

impl ConnectorIntegration<api::Execute, types::RefundsData, types::RefundsResponseData> for Paymob {
    // TODO: Implement RefundExecute
    fn get_headers(
        &self,
        _req: &types::RefundsRouterData<api::Execute>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RefundExecute Headers").into())
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        _req: &types::RefundsRouterData<api::Execute>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RefundExecute URL").into())
    }

    fn get_request_body(
        &self,
        _req: &types::RefundsRouterData<api::Execute>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<types::RequestBody>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RefundExecute Request Body").into())
    }

    fn build_request(
        &self,
        _req: &types::RefundsRouterData<api::Execute>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RefundExecute Build Request").into())
    }

    fn handle_response(
        &self,
        _data: &types::RefundsRouterData<api::Execute>,
        _res: Response,
    ) -> CustomResult<types::RefundsRouterData<api::Execute>, errors::ConnectorError>
    where
        api::Execute: Clone,
        types::RefundsData: Clone,
        types::RefundsResponseData: Clone,
    {
        Err(errors::ConnectorError::NotImplemented("RefundExecute Handle Response").into())
    }

    fn get_error_response(
        &self,
        res: Response,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res)
    }
}

impl ConnectorIntegration<api::RSync, types::RefundsData, types::RefundsResponseData> for Paymob {
    // TODO: Implement RefundSync
    fn get_headers(
        &self,
        _req: &types::RefundsRouterData<api::RSync>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RefundSync Headers").into())
    }

    fn get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn get_url(
        &self,
        _req: &types::RefundsRouterData<api::RSync>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RefundSync URL").into())
    }

    fn build_request(
        &self,
        _req: &types::RefundsRouterData<api::RSync>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("RefundSync Build Request").into())
    }

    fn handle_response(
        &self,
        _data: &types::RefundsRouterData<api::RSync>,
        _res: Response,
    ) -> CustomResult<types::RefundsRouterData<api::RSync>, errors::ConnectorError>
    where
        api::RSync: Clone,
        types::RefundsData: Clone,
        types::RefundsResponseData: Clone,
    {
        Err(errors::ConnectorError::NotImplemented("RefundSync Handle Response").into())
    }

    fn get_error_response(
        &self,
        res: Response,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res)
    }
}

#[async_trait::async_trait]
impl api::IncomingWebhook for Paymob {
    fn get_webhook_object_reference_id(
        &self,
        request: &api::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let details: PaymobWebhookRequest = request
            .body
            .parse_struct("PaymobWebhookRequest")
            .change_context(ConnectorError::WebhookReferenceIdNotFound)?;
        Ok(api::webhooks::ObjectReferenceId::TransactionId(
            api::webhooks::TransactionObjectId::ConnectorTransactionId(details.obj.id.to_string()),
        ))
    }

    fn get_webhook_event_type(
        &self,
        request: &api::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api::IncomingWebhookEvent, errors::ConnectorError> {
        let details: PaymobWebhookRequest = request
            .body
            .parse_struct("PaymobWebhookRequest")
            .change_context(ConnectorError::WebhookEventTypeNotFound)?;
        // Map Paymob's transaction type and status to Hyperswitch events
        // This is a simplified mapping
        match details.transaction_type.as_str() {
            "TRANSACTION" => {
                if details.obj.success {
                    if details.obj.is_auth {
                        Ok(api::IncomingWebhookEvent::PaymentIntentAuthorizationSuccess)
                    } else if details.obj.is_capture {
                        Ok(api::IncomingWebhookEvent::PaymentIntentCaptureSuccess)
                    } else {
                        Ok(api::IncomingWebhookEvent::PaymentIntentSuccess)
                    }
                } else if details.obj.is_voided || details.obj.is_void {
                    Ok(api::IncomingWebhookEvent::PaymentIntentCancelled)
                } else if details.obj.is_refunded || details.obj.is_refund {
                    Ok(api::IncomingWebhookEvent::RefundSuccess) // Assuming success if refunded
                } else {
                    Ok(api::IncomingWebhookEvent::PaymentIntentFailure)
                }
            }
            "TOKEN" => Ok(api::IncomingWebhookEvent::PaymentMethodCreated), // Or another relevant event
            _ => Err(ConnectorError::WebhookEventTypeNotFound.into()),
        }
    }

    fn get_webhook_resource_object(
        &self,
        request: &api::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        let details: PaymobWebhookRequest = request
            .body
            .parse_struct("PaymobWebhookResourceObject")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)?;
        Ok(Box::new(details.obj))
    }

    // TODO: Implement webhook signature/HMAC verification
    fn verify_webhook_source(
        &self,
        _request: &api::IncomingWebhookRequestDetails<'_>,
        _merchant_id: &str,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
        _connector_account_details: &common_utils::types::ConnectorAccountDetails,
    ) -> CustomResult<bool, errors::ConnectorError> {
        // Paymob uses HMAC verification. Need to implement this.
        // See: https://developers.paymob.com/docs/accept-standard-redirect#transaction-response-callback-hmac-calculation
        Ok(true) // Placeholder - MUST implement actual verification
    }
}

impl Paymob {
    // Helper to build generic error response
    fn build_error_response(&self, res: Response) -> CustomResult<ErrorResponse, ConnectorError> {
        let response: PaymobErrorResponse = res
            .response
            .parse_struct("Paymob ErrorResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        ErrorResponse::try_from(response)
    }
}

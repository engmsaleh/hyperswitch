pub mod transformers;

use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, StringMinorUnit, StringMinorUnitForConnector},
};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{Authorize, Capture, PSync, PaymentMethodToken, Session, SetupMandate, Void},
        refunds::{Execute, RSync},
    },
    router_request_types::{
        AccessTokenRequestData, PaymentMethodTokenizationData, PaymentsAuthorizeData,
        PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData, PaymentsSyncData,
        RefundsData, SetupMandateRequestData,
    },
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{
        PaymentsAuthorizeRouterData, PaymentsCaptureRouterData, PaymentsSyncRouterData,
        RefundSyncRouterData, RefundsRouterData,
    },
};
use hyperswitch_interfaces::{
    api::{
        self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorSpecifications,
        ConnectorValidation,
    },
    configs::Connectors,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::{self, Response},
    webhooks,
};
use masking::{ExposeInterface, Mask};
use transformers as paymob;

use crate::{constants::headers, types::ResponseRouterData, utils};

#[derive(Clone)]
pub struct Paymob {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMinorUnit> + Sync),
}

impl Paymob {
    fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMinorUnitForConnector,
        }
    }
}

impl api::Payment for Paymob {}
impl api::PaymentSession for Paymob {}
impl api::ConnectorAccessToken for Paymob {}
impl api::MandateSetup for Paymob {}
impl api::PaymentAuthorize for Paymob {}
impl api::PaymentSync for Paymob {}
impl api::PaymentCapture for Paymob {}
impl api::PaymentVoid for Paymob {}
impl api::Refund for Paymob {}
impl api::RefundExecute for Paymob {}
impl api::RefundSync for Paymob {}
impl api::PaymentToken for Paymob {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Paymob
{
    // Not Implemented (R)
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Paymob
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
}

impl ConnectorCommon for Paymob {
    fn id(&self) -> &'static str {
        "paymob"
    }

    // PayMob processes amounts in cents (minor unit).
    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.paymob.base_url.as_ref()
    }

    // This header is primarily for the initial authentication request.
    // Subsequent requests use the obtained auth_token.
    fn get_auth_header(
        &self,
        _auth_type: &ConnectorAuthType, // Parameter might not be directly used as auth is multi-step
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        // PayMob's main authorization involves obtaining a token first.
        // This function might be less relevant for subsequent steps which use the token.
        // Returning an empty vec or handling specific auth types might be needed.
        // For now, let's assume this is *not* used for the main payment flow headers.
        Ok(vec![])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: paymob::PaymobErrorResponse = res
            .response
            .parse_struct("PaymobErrorResponse")
            // Handle cases where PayMob might return different error structures
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        // Map PayMob error fields to the generic ErrorResponse
        Ok(ErrorResponse {
            status_code: res.status_code,
            // Use 'detail' or 'message' based on availability and relevance
            code: response.detail.clone().unwrap_or_else(|| "NO_ERROR_CODE".to_string()),
            message: response.message.clone().unwrap_or_else(|| response.detail.clone().unwrap_or_else(|| "NO_ERROR_MESSAGE".to_string())),
            reason: response.message.or(response.detail),
            attempt_status: None, // Determine based on error context if possible
            connector_transaction_id: None,
        })
    }
}

impl ConnectorValidation for Paymob {
    //TODO: implement functions when support enabled
}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Paymob {
    //TODO: implement sessions flow
}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Paymob {
    fn get_url(
        &self,
        _req: &AccessTokenRequestData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // URL for PayMob authentication endpoint
        Ok(format!("{}/auth/tokens", self.base_url(connectors)))
    }

    fn get_headers(
        &self,
        _req: &AccessTokenRequestData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        // Standard JSON content type header
        Ok(vec![(headers::CONTENT_TYPE.to_string(), "application/json".into())])
    }

    fn get_request_body(
        &self,
        req: &AccessTokenRequestData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        // Create the authentication request using the API key
        let connector_req = paymob::PaymobAuthRequest::try_from(&req.connector_auth_type)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &AccessTokenRequestData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        // Build the POST request for authentication
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::AccessTokenType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::AccessTokenType::get_headers(self, req, connectors)?)
                .set_body(types::AccessTokenType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        _data: &AccessTokenRequestData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<AccessToken, errors::ConnectorError>
    where
        AccessTokenRequestData: Clone,
    {
        // Parse the authentication response to extract the token
        let response: paymob::PaymobAuthResponse = res
            .response
            .parse_struct("PaymobAuthResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        // Return the token and default expiry (PayMob doesn't provide expiry)
        Ok(AccessToken {
            token: response.token,
            expires: 3600, // Default expiry, PayMob token validity is not specified clearly
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Use the common error handling defined in ConnectorCommon
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Paymob {}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Paymob {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        // Headers are simple JSON content type for all steps
        Ok(vec![(headers::CONTENT_TYPE.to_string(), "application/json".into())])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Determine URL based on whether order_id exists (indicating Payment Key step)
-         if req.request.connector_meta.is_some() { // Assuming order_id is stored in connector_meta
+         if let Some(metadata) = &req.request.connector_meta {
+             if metadata.peek().contains_key("payment_key") {
+                 // URL for Pay endpoint
+                 Ok(format!("{}/acceptance/payments/pay", self.base_url(connectors)))
+             } else if metadata.peek().contains_key("order_id") {
+                 // URL for Payment Key Generation endpoint
+                 Ok(format!("{}/acceptance/payment_keys", self.base_url(connectors)))
+             } else {
+                 // Fallback or error? Should not happen in normal flow.
+                 Ok(format!("{}/ecommerce/orders", self.base_url(connectors)))
+             }
+         } else {
              // URL for Payment Key Generation endpoint
-             Ok(format!("{}/acceptance/payment_keys", self.base_url(connectors)))
-         } else {
              // URL for the Order Registration endpoint
              Ok(format!("{}/ecommerce/orders", self.base_url(connectors)))
          }
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;

        // Retrieve the auth token obtained from the AccessTokenAuth flow
        let auth_token = req
            .access_token
            .as_ref()
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?
            .token
            .clone();

        let connector_router_data = paymob::PaymobRouterData::from((amount, req));
  
          // Determine request body based on whether order_id exists
-         if let Some(metadata) = &req.request.connector_meta {
+         if let Some(metadata) = &req.request.connector_meta {
+             if metadata.peek().contains_key("payment_key") {
+                 // --- Create Pay Request --- //
+                 let payment_key_val = metadata.peek().get("payment_key").ok_or_else(|| {
+                     report!(errors::ConnectorError::MissingRequiredField {
+                         field_name: "payment_key in connector_meta"
+                     })
+                 })?;
+                 let payment_key = Secret::new(payment_key_val.as_str().ok_or_else(|| {
+                     report!(errors::ConnectorError::RequestEncodingFailed)
+                         .attach_printable("Invalid payment_key format in metadata")
+                 })?.to_string());
+
+                 let connector_req = paymob::PaymobPayRequest::try_from((&connector_router_data, payment_key))?;
+                 Ok(RequestContent::Json(Box::new(connector_req)))
+
+             } else if metadata.peek().contains_key("order_id") {
              // Assuming order_id is stored as a string in metadata
              let order_id_val = metadata.peek().get("order_id").ok_or_else(|| {
                  report!(errors::ConnectorError::MissingRequiredField {
                    field_name: "order_id in connector_meta"
                })
            })?;
            let order_id = order_id_val.as_u64().ok_or_else(|| {
                report!(errors::ConnectorError::RequestEncodingFailed)
                    .attach_printable("Invalid order_id format in metadata")
            })?;

            // TODO: Get Integration ID from connector metadata or config
            let integration_id = Secret::new("dummy_integration_id".to_string()); // Placeholder

            // Create Payment Key Request
            let connector_req = paymob::PaymobPaymentKeyRequest::try_from((
                &connector_router_data,
                auth_token,
                order_id,
                integration_id,
            ))?;
            Ok(RequestContent::Json(Box::new(connector_req)))
        } else {
            // Create Order Registration Request
            let connector_req =
                paymob::PaymobOrderRequest::try_from((&connector_router_data, auth_token))?;
            Ok(RequestContent::Json(Box::new(connector_req)))
        }
    }

    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        // Build the request dynamically based on the step (Order or Payment Key)
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsAuthorizeType::get_headers(self, req, connectors)?)
                .set_body(types::PaymentsAuthorizeType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError>
    where
        PaymentsAuthorizeData: Clone,
    {
        // Handle response based on which step was performed
-         if data.request.connector_meta.is_some() {
+         if let Some(metadata) = &data.request.connector_meta {
+             if metadata.peek().contains_key("payment_key") {
+                 // --- Handle Pay Response --- //
+                 // PayMob's /pay endpoint response is complex and might require redirection or confirmation.
+                 // It often returns an iframe URL or transaction details.
+                 // For simplicity, let's assume it returns the final transaction status directly
+                 // or we need to call the transaction inquiry endpoint immediately after.
+                 // We'll parse into the generic PaymobPaymentsResponse for now.
+                 let response: paymob::PaymobPaymentsResponse = res
+                     .response
+                     .parse_struct("PaymobPaymentsResponse")
+                     .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
+
+                 event_builder.map(|i| i.set_response_body(&response));
+                 router_env::logger::info!(connector_response=?response);
+
+                 // Convert PayMob status to RouterData
+                 RouterData::try_from(ResponseRouterData {
+                     response,
+                     data: data.clone(),
+                     http_code: res.status_code,
+                 })
+                 .change_context(errors::ConnectorError::ResponseHandlingFailed)
+
+             } else if metadata.peek().contains_key("order_id") {
              // --- Handle Payment Key Response --- //
              let response: paymob::PaymobPaymentKeyResponse = res
                  .response
                  .parse_struct("PaymobPaymentKeyResponse")
                  .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);

            // TODO: Store response.token (payment_key) in metadata for the next step (Pay).
            // TODO: Trigger the Pay request - How?
            // Returning AuthenticationPending, indicating the Pay step is needed.
            let mut connector_meta = data.request.connector_meta.clone().unwrap_or_default();
            connector_meta
                .peek_mut()
                .insert("payment_key".to_string(), response.token.expose().into());

            Ok(PaymentsAuthorizeRouterData {
                status: common_enums::AttemptStatus::AuthenticationPending, // Indicate Pay step needed
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::NoResponseId, // No final transaction ID yet
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: Some(connector_meta), // Pass updated metadata
                    network_txn_id: None,
                    connector_response_reference_id: data.connector_request_reference_id.clone(),
                    incremental_authorization_allowed: None,
                    charges: None,
                }),
                ..data.clone()
            })
        } else {
            // --- Handle Order Registration Response --- //
            let response: paymob::PaymobOrderResponse = res
                .response
                .parse_struct("PaymobOrderResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);

            // Store order_id in metadata to trigger the Payment Key step next.
            let connector_meta = serde_json::json!({ "order_id": response.id });

            Ok(PaymentsAuthorizeRouterData {
                status: common_enums::AttemptStatus::AuthenticationPending, // Indicate Payment Key step needed
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::NoResponseId, // No final transaction ID yet
                    redirection_data: None,
                    mandate_reference: None,
                    connector_metadata: Some(connector_meta), // Pass order_id for next step
                    network_txn_id: None,
                    connector_response_reference_id: Some(response.id.to_string()), // Use order_id
                    incremental_authorization_allowed: None,
                    charges: None,
                }),
                ..data.clone()
            })
        }
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Paymob {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        // Transaction inquiry likely needs the auth token
        let mut headers = vec![(headers::CONTENT_TYPE.to_string(), "application/json".into())];
        // Assuming token is needed and available
        let access_token = req.access_token.as_ref().ok_or(errors::ConnectorError::FailedToObtainAuthType)?.token.clone();
        headers.push((headers::AUTHORIZATION.to_string(), format!("Bearer {}", access_token.expose()).into_masked()));
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // URL for PayMob Transaction Inquiry endpoint
        // Needs the transaction ID appended later in build_request
        Ok(format!("{}/acceptance/transactions", self.base_url(_connectors)))
    }

    fn get_request_body(
        &self,
        _req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        // GET request, no body needed
        Ok(RequestContent::Empty)
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        // Need the PayMob transaction ID from the original payment attempt
        let transaction_id = req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;
        
        // Build GET request for transaction inquiry
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                // Append transaction ID to the URL
                .url(&format!("{}/{}", types::PaymentsSyncType::get_url(self, req, connectors)?, transaction_id))
                .attach_default_headers()
                .headers(types::PaymentsSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError>
    where
        PaymentsSyncData: Clone,
    {
        // Parse the transaction inquiry response
        // Assuming the inquiry response structure is similar to PaymobPaymentsResponse
        // This might need adjustment based on actual PayMob API docs for transaction inquiry.
        let response: paymob::PaymobPaymentsResponse = res
            .response
            .parse_struct("PaymobPaymentsResponse") 
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Paymob {
    // Not supported by PayMob API directly, use Refund instead.
}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Paymob {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        // Refund endpoint likely needs the auth token
        let mut headers = vec![(headers::CONTENT_TYPE.to_string(), "application/json".into())];
        // Assuming token is needed and available
        let access_token = req.access_token.as_ref().ok_or(errors::ConnectorError::FailedToObtainAuthType)?.token.clone();
        headers.push((headers::AUTHORIZATION.to_string(), format!("Bearer {}", access_token.expose()).into_masked()));
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // URL for PayMob Refund endpoint
        Ok(format!("{}/acceptance/void_refund/refund", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_refund_amount,
            req.request.currency,
        )?;
        let connector_router_data = paymob::PaymobRouterData::from((amount, req));
        let connector_req = paymob::PaymobRefundRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::RefundExecuteType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundExecuteType::get_headers(self, req, connectors)?)
                .set_body(types::RefundExecuteType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError>
    where
        Execute: Clone,
    {
        let response: paymob::RefundResponse = res
            .response
            .parse_struct("Paymob RefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Paymob {
    fn get_headers(
        &self,
        req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        // Refund Sync might use transaction inquiry, needing auth token
        let mut headers = vec![(headers::CONTENT_TYPE.to_string(), "application/json".into())];
        // Assuming token is needed and available
        let access_token = req.access_token.as_ref().ok_or(errors::ConnectorError::FailedToObtainAuthType)?.token.clone();
        headers.push((headers::AUTHORIZATION.to_string(), format!("Bearer {}", access_token.expose()).into_masked()));
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // PayMob doesn't seem to have a specific Refund Sync endpoint.
        // Use the Transaction Inquiry endpoint, appending the refund's connector_refund_id (which should be PayMob's transaction ID for the refund)
        Ok(format!("{}/acceptance/transactions", self.base_url(_connectors)))
    }

    fn get_request_body(
        &self,
        _req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        // GET request, no body
        Ok(RequestContent::Empty)
    }

    fn build_request(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        // Need the PayMob transaction ID for the refund
        let refund_transaction_id = req.request.get_connector_refund_id()?;

        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&format!("{}/{}", types::RefundSyncType::get_url(self, req, connectors)?, refund_transaction_id))
                .attach_default_headers()
                .headers(types::RefundSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError>
    where
        RSync: Clone,
    {
        // Parse the transaction inquiry response for the refund
        // Assuming the inquiry response structure is similar to RefundResponse
        // This might need adjustment based on actual PayMob API docs.
        let response: paymob::RefundResponse = res
            .response
            .parse_struct("Paymob RefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(RefundsResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(errors::ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Paymob {
    fn get_webhook_object_reference_id(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }

    fn get_webhook_event_type(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }

    fn get_webhook_resource_object(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }
}

impl ConnectorSpecifications for Paymob {}

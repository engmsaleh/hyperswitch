use common_enums::enums;
use serde::{Deserialize, Serialize};
use masking::Secret;
use common_utils::types::{StringMinorUnit};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::PaymentsAuthorizeRequestData,
};

//TODO: Fill the struct with respective fields
pub struct PaymobRouterData<T> {
    pub amount: StringMinorUnit, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

impl<T>
    From<(
        StringMinorUnit,
        T,
    )> for PaymobRouterData<T>
{
    fn from(
        (amount, item): (
            StringMinorUnit,
            T,
        ),
    ) -> Self {
         //Todo :  use utils to convert the amount to the type of amount that a connector accepts
        Self {
            amount,
            router_data: item,
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct PaymobPaymentsRequest {
    amount: StringMinorUnit,
    card: PaymobCard
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct PaymobCard {
    number: cards::CardNumber,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    cvc: Secret<String>,
    complete: bool,
}

impl TryFrom<&PaymobRouterData<&PaymentsAuthorizeRouterData>> for PaymobPaymentsRequest  {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaymobRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self,Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                let card = PaymobCard {
                    number: req_card.card_number,
                    expiry_month: req_card.card_exp_month,
                    expiry_year: req_card.card_exp_year,
                    cvc: req_card.card_cvc,
                    complete: item.router_data.request.is_auto_capture()?,
                };
                Ok(Self {
                    amount: item.amount.clone(),
                    card,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        }
    }
}

//TODO: Fill the struct with respective fields
// Auth Struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymobAuthType {
    pub api_key: Secret<String>,
    pub secret_key: Secret<String>,
    pub public_key: Secret<String>,
    pub hmac_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PaymobAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey { 
                api_key, 
                key1,
                api_secret,
                key2
             } => Ok(Self {
                api_key: api_key.clone(),
                secret_key: api_secret.clone(), 
                public_key: key1.clone(), 
                hmac_secret: key2.clone(), 
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// PaymentsResponse
//TODO: Append the remaining status flags from Paymob docs (success, pending etc.)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PaymobPaymentStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<PaymobPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: PaymobPaymentStatus) -> Self {
        match item {
            PaymobPaymentStatus::Succeeded => Self::Charged, // Assuming Succeeded means charged
            PaymobPaymentStatus::Failed => Self::Failure,
            PaymobPaymentStatus::Processing => Self::Pending, // Assuming Processing maps to Pending/Authorizing initially
            // TODO: Map other Paymob statuses (e.g., from webhook: success, pending, is_voided, is_refunded)
        }
    }
}

//TODO: Fill the struct with respective fields from Paymob API (e.g., Intention response, Capture response)
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaymobPaymentsResponse {
    status: PaymobPaymentStatus,
    id: String,
    // Add other fields like client_secret etc.
}

impl<F,T> TryFrom<ResponseRouterData<F, PaymobPaymentsResponse, T, PaymentsResponseData>> for RouterData<F, T, PaymentsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<F, PaymobPaymentsResponse, T, PaymentsResponseData>) -> Result<Self,Self::Error> {
        // TODO: Handle redirection construction for Authorize flow
        // TODO: Potentially map status based on multiple fields (e.g., `success`, `pending` from webhook)
        Ok(Self {
            status: common_enums::AttemptStatus::from(item.response.status),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: Box::new(None), // Needs to be populated for Authorize
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None, // Consider mapping from Paymob's merchant_order_id or transaction id
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

//TODO: Fill the struct with respective fields for Paymob refund request
// REFUND :
// Type definition for RefundRequest
#[derive(Debug, Serialize)]
pub struct PaymobRefundRequest {
    transaction_id: String, // The ID of the original transaction to refund
    amount_cents: StringMinorUnit, // Amount to refund
}

impl<F> TryFrom<&PaymobRouterData<&RefundsRouterData<F>>> for PaymobRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaymobRouterData<&RefundsRouterData<F>>) -> Result<Self,Self::Error> {
        Ok(Self {
            transaction_id: item.router_data.request.connector_transaction_id.clone(),
            amount_cents: item.amount.to_owned(),
        })
    }
}

// Type definition for Refund Response
// TODO: Map Paymob refund status (likely from webhook/sync response)
#[allow(dead_code)]
#[derive(Debug, Serialize, Default, Deserialize, Clone)]
pub enum RefundStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Succeeded => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::Processing => Self::Pending,
        }
    }
}

//TODO: Fill the struct with respective fields from Paymob refund API response
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    id: String, // ID of the refund transaction itself
    status: RefundStatus
    // Add parent_transaction ID field maybe?
}

impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>>
    for RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, RefundResponse>> for RefundsRouterData<RSync>
{
     type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: RefundsResponseRouterData<RSync, RefundResponse>) -> Result<Self,Self::Error> {
        // TODO: Adjust mapping based on Sync response structure if different from Execute response
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
     }
 }

//TODO: Fill the struct with respective fields from Paymob error response
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct PaymobErrorResponse {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}

// Auth Token Request
#[derive(Debug, Serialize)]
pub struct PaymobAuthTokenRequest {
    pub api_key: String,
}

// Auth Token Response Profile
#[derive(Debug, Deserialize)]
pub struct PaymobProfile {
    pub id: u64,
    pub user: PaymobUser,
    pub created_at: String, // Consider using a DateTime type
    pub active: bool,
    pub profile_type: String,
    pub phones: Vec<String>,
    pub company_emails: Vec<String>,
    pub company_name: String,
    pub state: String,
    pub country: String,
    pub city: String,
    pub postal_code: String,
    pub street: String,
    pub email_notification: bool,
    pub order_retrieval_endpoint: Option<String>,
    pub delivery_update_endpoint: Option<String>,
    pub logo_url: Option<String>,
    pub is_mobadra: bool,
    pub sector: String,
    pub activation_method: u8,
    // Assuming exp is a Unix timestamp
    pub exp: i64, 
}

// Auth Token Response User
#[derive(Debug, Deserialize)]
pub struct PaymobUser {
    pub id: u64,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub date_joined: String, // Consider using a DateTime type
    pub email: String,
    pub is_active: bool,
    pub is_staff: bool,
    pub is_superuser: bool,
    // Add groups and user_permissions if needed (likely Vec<...>) 
}

// Auth Token Response
#[derive(Debug, Deserialize)]
pub struct PaymobAuthTokenResponse {
    pub profile: PaymobProfile,
    pub token: String,
}

// PaymentsRequest Structs
#[derive(Debug, Serialize)]
pub struct PaymobItem {
    name: String,
    amount_cents: StringMinorUnit,
    description: String,
    quantity: i64,
}

#[derive(Debug, Serialize)]
pub struct PaymobBillingData {
    apartment: String, 
    email: String, 
    floor: String, 
    first_name: String, 
    street: String, 
    building: String, 
    phone_number: String,
    shipping_method: Option<String>, // Assuming optional
    postal_code: String, 
    city: String, 
    country: String, 
    last_name: String, 
    state: String,
}

#[derive(Debug, Serialize)]
pub struct PaymobIntentionRequest {
    amount_cents: StringMinorUnit,
    currency: String,
    payment_methods: Vec<u64>, // Placeholder: Need Paymob's specific IDs
    items: Vec<PaymobItem>,
    billing_data: PaymobBillingData,
    customer: Option<PaymobCustomer>, // Assuming optional
    // Add other fields like merchant_order_id, metadata etc. if needed
}

#[derive(Debug, Serialize)] // Added for customer field in IntentionRequest
pub struct PaymobCustomer {
    // Define customer fields if Paymob supports passing customer objects
    // e.g., id, email, name etc.
}


// PaymentsResponse Structs
#[derive(Debug, Deserialize)]
pub struct PaymobIntentionResponse {
    id: u64,
    client_secret: String,
    amount_cents: i64, 
    currency: String,
    status: String, // Map this to internal status
    // Add other relevant response fields
}

impl TryFrom<&PaymentsAuthorizeRouterData> for PaymobIntentionRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(req: &PaymentsAuthorizeRouterData) -> Result<Self, Self::Error> {
        let billing_address = req.get_billing()?;
        let billing_address_details = billing_address.address.as_ref().ok_or(errors::ConnectorError::MissingRequiredField { field_name: "billing.address" })?;
        let phone_details = billing_address.phone.as_ref().ok_or(errors::ConnectorError::MissingRequiredField { field_name: "billing.phone" })?;
        let (first_name, last_name) = req.request.get_billing_full_name()?.get_first_and_last_name()?;

        // TODO: Map req.get_allowed_payment_methods() to Paymob's integer IDs for payment_methods field.
        // This requires knowing Paymob's specific IDs (e.g., Card ID = ?). For now, using card ID 26 as placeholder based on some docs.
        let payment_methods = vec![26]; // Placeholder for Card

        // TODO: Confirm item structure. If req.request.order_details is empty, create a default item?
        let items = match &req.request.order_details {
            Some(order_details) if !order_details.is_empty() => order_details
                .iter()
                .map(|item| {
                     // Paymob expects amount in cents as StringMinorUnit per item.
                     // Order details might not have this. Using total amount / quantity as a rough estimate.
                    let amount_cents_per_item = StringMinorUnit::from(
                        req.request.minor_amount.get() / item.quantity as i64
                    );
                    Ok(PaymobItem {
                        name: item.product_name.clone(),
                        amount_cents: amount_cents_per_item, // Needs verification
                        description: item.product_name.clone(), // Use product name as description?
                        quantity: item.quantity.into(),
                    })
                })
                .collect::<Result<Vec<_>, Self::Error>>()?,
            _ => vec![PaymobItem { // Default item if order_details is empty/None
                name: req.get_description()?.unwrap_or("Payment").to_string(),
                amount_cents: req.request.minor_amount.clone(),
                description: req.get_description()?.unwrap_or("Payment").to_string(),
                quantity: 1,
            }],
        };

        let billing_data = PaymobBillingData {
            // Using "NA" or defaults for potentially missing fields like apartment, floor, building
            apartment: billing_address_details.line2.clone().unwrap_or("NA".to_string()),
            email: req.get_email()?.expose(),
            floor: billing_address_details.line3.clone().unwrap_or("NA".to_string()),
            first_name,
            street: billing_address_details.line1.clone().ok_or(errors::ConnectorError::MissingRequiredField { field_name: "billing.address.line1" })?, 
            building: "NA".to_string(), // Paymob requires building, using NA
            phone_number: phone_details.number.clone().ok_or(errors::ConnectorError::MissingRequiredField { field_name: "billing.phone.number" })?,
            shipping_method: None, // Assuming not applicable here
            postal_code: billing_address_details.zip.clone().ok_or(errors::ConnectorError::MissingRequiredField { field_name: "billing.address.zip" })?,
            city: billing_address_details.city.clone().ok_or(errors::ConnectorError::MissingRequiredField { field_name: "billing.address.city" })?,
            country: billing_address_details.country.map(|c| c.to_string()).ok_or(errors::ConnectorError::MissingRequiredField { field_name: "billing.address.country" })?,
            last_name,
            state: billing_address_details.state.clone().ok_or(errors::ConnectorError::MissingRequiredField { field_name: "billing.address.state" })?,
        };

        // TODO: Add customer details if Paymob supports/requires it in Intention API
        let customer = None; 

        Ok(Self {
            amount_cents: req.request.minor_amount.clone(),
            currency: req.request.currency.to_string(),
            payment_methods,
            items,
            billing_data,
            customer,
            // TODO: Add merchant_order_id: Some(req.attempt_id.clone()), ?
            // TODO: Add metadata: req.request.metadata, ?
        })
    }
}

// Mapping Paymob intention status to internal status
impl From<String> for common_enums::AttemptStatus {
    fn from(item: String) -> Self {
        // TODO: Verify Paymob intention statuses (e.g., "pending", "succeeded"?)
        match item.as_str() {
            "succeeded" => Self::Charged, // Assuming intention 'succeeded' means authorized/charged directly
            "pending" => Self::AuthenticationPending, // Assuming 'pending' requires redirection
            "failed" => Self::Failure,
            _ => Self::Pending, // Default fallback
        }
    }
}

impl TryFrom<ResponseRouterData<PaymobIntentionResponse>>
    for PaymentsAuthorizeRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaymobIntentionResponse>,
    ) -> Result<Self, Self::Error> {
        let redirection_data = {
            let auth = PaymobAuthType::try_from(&item.data.connector_auth_type)?;
            let iframe_id = auth.public_key; // Public key acts as iframe ID
            let payment_token = item.response.client_secret.clone();
            let redirection_url = format!(
                "https://accept.paymob.com/api/acceptance/iframes/{}?payment_token={}",
                iframe_id,
                payment_token
            );

            Some(hyperswitch_domain_models::router_response_types::RedirectForm::Iframe { 
                iframe_url: redirection_url,
                payment_method_data: None, // No data needed within iframe call itself
            })
        };

        Ok(Self {
            status: common_enums::AttemptStatus::from(item.response.status.clone()),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.to_string()),
                redirection_data: redirection_data.map(Box::new), 
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id.to_string()),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// Capture Request
#[derive(Debug, Serialize)]
pub struct PaymobCaptureRequest {
    transaction_id: String, // The ID from the intention/authorize response
    amount_cents: StringMinorUnit,
}

// Common Response for Capture/Void/Refund
#[derive(Debug, Deserialize, Clone)]
pub struct PaymobTransactionResponse {
    id: u64, // ID of the specific transaction (capture, void, refund)
    pending: bool,
    amount_cents: i64,
    success: bool,
    is_auth: bool,
    is_capture: bool,
    is_standalone_payment: bool,
    is_voided: bool,
    is_refunded: bool,
    is_3d_secure: bool,
    integration_id: u64,
    profile_id: u64,
    has_parent_transaction: bool,
    order: PaymobOrderInfo,
    created_at: String, // Consider DateTime
    transaction_processed_callback_responses: Vec<serde_json::Value>, // Adjust type if structure is known
    currency: String,
    source_data: PaymobSourceData,
    api_source: String,
    terminal_id: Option<u64>,
    merchant_commission: i64,
    is_void: bool,
    is_refund: bool,
    error_occured: bool, // Note spelling "occured"
    is_settled: bool,
    bill_reference: Option<u64>,
    merchant_staff_tag: Option<String>,
    owner: u64,
    parent_transaction: Option<u64>, // ID of the original auth transaction
    // Potentially add error fields if they appear here
    #[serde(default)] // Add default for fields that might be missing
    data: PaymobTransactionData, 
}

// Sub-structs for PaymobTransactionResponse
#[derive(Debug, Deserialize, Clone)]
pub struct PaymobOrderInfo {
    id: u64,
    created_at: String, // Consider DateTime
    delivery_needed: bool,
    merchant: PaymobMerchantInfo,
    collector: Option<serde_json::Value>, // Type unknown
    amount_cents: i64,
    shipping_data: Option<PaymobShippingData>,
    currency: String,
    is_payment_locked: bool,
    is_return: bool,
    is_cancel: bool,
    is_returned: bool,
    is_canceled: bool,
    merchant_order_id: Option<String>,
    wallet_notification: Option<serde_json::Value>, // Type unknown
    paid_amount_cents: i64,
    notify_user_with_email: bool,
    items: Vec<PaymobOrderItem>,
    order_url: String,
    commission_fees: i64,
    delivery_fees_cents: i64,
    delivery_vat_cents: i64,
    payment_method: String,
    merchant_staff_tag: Option<String>,
    api_source: String,
    token: Option<String>,
    // data: Option<serde_json::Value>, // Seems recursive/ambiguous with parent data field
}

#[derive(Debug, Deserialize, Clone)]
pub struct PaymobMerchantInfo {
    id: u64,
    created_at: String, // Consider DateTime
    phones: Vec<String>,
    company_emails: Vec<String>,
    company_name: String,
    state: String,
    country: String,
    city: String,
    postal_code: String,
    street: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PaymobShippingData {
    id: u64,
    first_name: String,
    last_name: String,
    street: String,
    building: String,
    floor: String,
    apartment: String,
    city: String,
    state: String,
    country: String,
    email: String,
    phone_number: String,
    postal_code: String,
    extra_description: Option<String>,
    shipping_method: Option<String>,
    order_id: u64,
    order: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PaymobOrderItem {
    name: String,
    description: String,
    amount_cents: i64,
    quantity: i64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PaymobSourceData {
    pan: String, // e.g., "2346" for card last 4 digits
    sub_type: String, // e.g., "MasterCard"
    #[serde(rename = "type")]
    source_type: String, // e.g., "card"
}

// Using default for potentially missing fields in response
#[derive(Debug, Deserialize, Clone, Default)] 
pub struct PaymobTransactionData {
    rrn: Option<String>,
    #[serde(default)]
    klass: Option<String>, // Rename if needed, 'klass' is unusual
    gateway_integration_pk: Option<u64>,
    #[serde(default)]
    order_info: Option<String>, // Type might be incorrect, often contains order details
    #[serde(default)]
    refunded_amount_cents: i64, 
    avs_result_code: Option<String>,
    captured_amount: Option<f64>, // Check type, might be cents
    cvv_result_code: Option<String>,
    #[serde(default)]
    authorised_amount_cents: i64, 
    message: Option<String>, // Error message?
    receipt_no: Option<String>,
    secure_hash: Option<String>,
    merchant_txn_ref: Option<String>,
    txn_response_code: Option<String>,
    acq_response_code: Option<String>,
    #[serde(default)]
    authorised_amount: f64, // Check type
    command: Option<String>,
    #[serde(default)]
    amount: i64, // Check type
    version: Option<String>,
    #[serde(default)]
    amount_cents: i64,
    migs_result: Option<String>,
    migs_transaction: Option<PaymobMigsTransaction>,
    migs_order: Option<PaymobMigsOrder>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PaymobMigsTransaction {
    acquirer_id: Option<String>,
    acquirer_transaction_id: Option<String>,
    amount: Option<i64>,
    authorization_code: Option<String>,
    batch_number: Option<String>,
    card_scheme: Option<String>,
    card_type: Option<String>,
    currency: Option<String>,
    receipt: Option<String>,
    stan: Option<String>,
    #[serde(rename = "type")]
    transaction_type: Option<String>, // e.g., "PAYMENT"
}

#[derive(Debug, Deserialize, Clone)]
pub struct PaymobMigsOrder {
    amount: Option<i64>,
    chargeback: Option<PaymobChargebackInfo>,
    creation_time: Option<String>, // Consider DateTime
    currency: Option<String>,
    id: Option<String>,
    status: Option<String>, // e.g., "CAPTURED"
    total_authorized_amount: Option<i64>,
    total_captured_amount: Option<i64>,
    total_refunded_amount: Option<i64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PaymobChargebackInfo {
    amount: Option<i64>,
    currency: Option<String>,
}

impl TryFrom<&PaymentsCaptureRouterData> for PaymobCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &PaymentsCaptureRouterData) -> Result<Self, Self::Error> {
        Ok(Self {
            transaction_id: item.request.connector_transaction_id.clone(),
            amount_cents: item.request.minor_amount_to_capture.clone(),
        })
    }
}

// Mapping Paymob transaction status to internal status for Capture, Void, Sync
impl From<&PaymobTransactionResponse> for common_enums::AttemptStatus {
    fn from(item: &PaymobTransactionResponse) -> Self {
        if item.success {
            if item.is_capture {
                Self::Charged
            } else if item.is_auth {
                Self::Authorized
            } else if item.is_voided || item.is_void { // Check both void flags
                Self::Voided
            } else {
                // Success is true, but not clearly Auth, Capture, or Void.
                // If is_standalone_payment is true, it's likely Charged.
                if item.is_standalone_payment {
                     Self::Charged
                } else {
                     Self::Pending // Default to Pending if success=true but state unclear
                }
            }
        } else if item.error_occured { // Note spelling "occured"
             // Determine failure context if possible
             if item.is_voided || item.is_void {
                 Self::VoidFailed
             } else if item.is_auth { // If error occurred during an auth attempt
                 Self::AuthorizationFailed
             } else {
                 // General failure for capture, standalone, or unknown context
                 Self::Failure
             }
        } else if item.pending {
            Self::Pending
        } else {
            // Fallback for ambiguous non-success, non-error, non-pending states
            Self::Pending
        }
    }
}

impl TryFrom<ResponseRouterData<PaymobTransactionResponse>>
    for PaymentsCaptureRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaymobTransactionResponse>,
    ) -> Result<Self, Self::Error> {

        Ok(Self {
            status: common_enums::AttemptStatus::from(&item.response), // Use consolidated From impl
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.to_string()),
                redirection_data: None, // No redirection for capture
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.data.rrn.clone(), // Use rrn as network_txn_id?
                connector_response_reference_id: Some(item.response.id.to_string()), // Use capture id as reference
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// Void Request
#[derive(Debug, Serialize)]
pub struct PaymobVoidRequest {
    transaction_id: String, // The ID of the original transaction to void
}

impl TryFrom<&PaymentsCancelRouterData> for PaymobVoidRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &PaymentsCancelRouterData) -> Result<Self, Self::Error> {
        Ok(Self {
            // Assuming the connector_transaction_id in the cancel request
            // refers to the original transaction to be voided.
            transaction_id: item.request.connector_transaction_id.clone(),
        })
    }
}

impl TryFrom<ResponseRouterData<PaymobTransactionResponse>>
    for PaymentsCancelRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaymobTransactionResponse>,
    ) -> Result<Self, Self::Error> {

        Ok(Self {
            status: common_enums::AttemptStatus::from(&item.response), // Use consolidated From impl
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.to_string()),
                redirection_data: None, // No redirection for void
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.data.rrn.clone(),
                connector_response_reference_id: Some(item.response.id.to_string()),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// Mapping Paymob transaction status to internal status for Refund
impl From<&PaymobTransactionResponse> for enums::RefundStatus {
    fn from(item: &PaymobTransactionResponse) -> Self {
        if item.success {
            if item.is_refunded || item.is_refund { // Check both flags
                Self::Success
            } else {
                 Self::Pending // If success is true but not marked as refunded?
            }
        } else if item.pending {
            Self::Pending
        } else if item.error_occured { // Note spelling "occured"
            Self::Failure
        } else {
            Self::Pending // Default fallback
        }
        // TODO: Refine status mapping based on more detailed Paymob documentation or testing.
    }
}

// Type definition for Refund Response - Using PaymobTransactionResponse

impl TryFrom<RefundsResponseRouterData<Execute, PaymobTransactionResponse>>
    for RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, PaymobTransactionResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(&item.response),
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, PaymobTransactionResponse>> for RefundsRouterData<RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: RefundsResponseRouterData<RSync, PaymobTransactionResponse>) -> Result<Self,Self::Error> {
         Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(&item.response),
            }),
            ..item.data
        })
    }
}

// Sync Request - No specific request body needed, just transaction ID in URL

impl TryFrom<ResponseRouterData<PaymobTransactionResponse>>
    for PaymentsSyncRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<PaymobTransactionResponse>,
    ) -> Result<Self, Self::Error> {
        let response = 
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.to_string()),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: item.response.data.rrn.clone(),
                connector_response_reference_id: Some(item.response.id.to_string()),
                incremental_authorization_allowed: None, // Check if Paymob supports this
                charges: None, // Add charges if applicable and available in response
            });

        Ok(Self {
            status: common_enums::AttemptStatus::from(&item.response), // Use consolidated From impl
            response,
             amount: item.response.amount_cents.into(), // Map amount from response
            mandate_id: None, // Map if applicable
            error_code: None, // Map error code if sync fails
            error_message: None, // Map error message if sync fails
            ..item.data
        })
    }
}

// Webhook Structs
#[derive(Debug, Serialize, Deserialize)]
pub struct PaymobWebhookPayload {
    #[serde(rename = "type")]
    pub webhook_type: String, // Type of the event (e.g., "TRANSACTION")
    pub obj: PaymobWebhookObject,
}

// Assuming the webhook object structure is similar to the transaction response
#[derive(Debug, Serialize, Deserialize)]
pub struct PaymobWebhookObject {
    pub id: u64, // Transaction ID
    pub pending: bool,
    pub amount_cents: u64,
    pub success: bool,
    pub is_auth: bool,
    pub is_capture: bool,
    pub is_standalone_payment: bool,
    pub is_voided: bool,
    pub is_refunded: bool,
    pub is_3d_secure: bool,
    pub integration_id: u64,
    pub profile_id: u64,
    pub has_parent_transaction: bool,
    pub order: PaymobWebhookOrder,
    pub created_at: String, // ISO 8601 format
    pub transaction_processed_callback_responses: Option<Value>, // Can be complex, using Value for now
    pub currency: String,
    pub source_data: PaymobSourceData,
    pub api_source: String,
    pub terminal_id: Option<u64>,
    pub merchant_commission: u64,
    // Fields from the second example
    pub is_void: Option<bool>,
    pub is_refund: Option<bool>,
    pub error_occured: Option<bool>, // Renamed from error_occured
    pub refunded_amount_cents: Option<u64>,
    pub captured_amount: Option<u64>,
    pub updated_at: Option<String>, // ISO 8601 format
    pub is_settled: Option<bool>,
    pub bill_status: Option<String>,
    pub is_bill: Option<bool>,
    pub owner: Option<u64>,
    pub parent_transaction: Option<u64>, // Assuming it's the ID
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymobWebhookOrder {
    pub id: u64,
    // Add other potentially relevant order fields if needed
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymobSourceData {
    #[serde(rename = "type")]
    pub source_type: String, // e.g., "card"
    pub sub_type: String, // e.g., "MasterCard"
    pub pan: String, // Card BIN
    // Add other source_data fields if needed
}

// Error Structs
// ... existing code ...

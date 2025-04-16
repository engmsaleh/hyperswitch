use common_enums::enums;
use common_utils::types::StringMinorUnit;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use masking::Secret;
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::PaymentsAuthorizeRequestData,
};

// Auth Struct
// Defines the structure for PayMob authentication credentials.
pub struct PaymobAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PaymobAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            // Extracts API key from HeaderKey authentication type.
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            // Returns an error if the authentication type is not supported.
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// PayMob Authentication Request
// Represents the request body for obtaining an authentication token from PayMob.
#[derive(Debug, Serialize)]
pub struct PaymobAuthRequest {
    api_key: Secret<String>,
}

// Creates a PaymobAuthRequest from the connector's authentication type.
impl TryFrom<&ConnectorAuthType> for PaymobAuthRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        // Converts the generic ConnectorAuthType to the specific PaymobAuthType.
        let auth: PaymobAuthType = auth_type.try_into()?;
        // Creates the request payload with the API key.
        Ok(Self { api_key: auth.api_key })
    }
}

// PayMob Authentication Response
// Represents the response received after a successful authentication request.
#[derive(Debug, Deserialize)]
pub struct PaymobAuthResponse {
    token: Secret<String>,
    // profile: PaymobProfile, // Contains merchant profile details, might be useful later.
}

// PayMob Order Registration Request
// Represents the request body for creating an order with PayMob.
#[derive(Debug, Serialize)]
pub struct PaymobOrderRequest {
    auth_token: Secret<String>, // Token obtained from Authentication Request
    delivery_needed: bool,      // Typically false for digital goods
    amount_cents: StringMinorUnit,
    currency: common_enums::Currency,
    merchant_order_id: Option<String>, // Optional: Connector request reference ID
    items: Vec<PaymobItem>,            // Although optional, often good practice to include
}

// Represents a single item in a Paymob order.
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct PaymobItem {
    name: String,
    amount_cents: StringMinorUnit,
    description: String,
    quantity: String, // PayMob expects quantity as a string
}

// Creates a PaymobOrderRequest from Hyperswitch router data and the auth token.
impl TryFrom<(&PaymobRouterData<&PaymentsAuthorizeRouterData>, Secret<String>)> for PaymobOrderRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, auth_token): (&PaymobRouterData<&PaymentsAuthorizeRouterData>, Secret<String>),
    ) -> Result<Self, Self::Error> {
        // Basic item creation, can be enhanced to use actual order details if available
        let default_item = PaymobItem {
            name: item.router_data.get_description()?.unwrap_or("Item".to_string()),
            amount_cents: item.amount.clone(),
            description: "Payment".to_string(),
            quantity: "1".to_string(),
        };

        Ok(Self {
            auth_token,
            delivery_needed: item.router_data.request.shipping.is_some(), // Set true if shipping info is present
            amount_cents: item.amount.clone(),
            currency: item.router_data.request.currency,
            merchant_order_id: Some(item.router_data.connector_request_reference_id.clone()),
            items: vec![default_item], // Use default item for now
        })
    }
}

// PayMob Order Registration Response
// Represents the response received after successfully registering an order.
#[derive(Debug, Deserialize)]
pub struct PaymobOrderResponse {
    id: u64, // PayMob's order ID
    // ... other fields like created_at, shipping_data, etc.
}

 //TODO: Implement Payment Key Request/Response
// PayMob Payment Key Request
// Represents the request body for obtaining a payment key from PayMob.
#[derive(Debug, Serialize)]
pub struct PaymobPaymentKeyRequest {
    auth_token: Secret<String>, // Token obtained from Authentication Request
    amount_cents: StringMinorUnit,
    expiration: u32, // Recommended: 3600 seconds (1 hour)
    order_id: String, // ID obtained from Order Registration Response
    billing_data: PaymobBillingData,
    currency: common_enums::Currency,
    integration_id: Secret<String>, // PayMob's integration ID for the payment method
    // lock_order_when_paid: bool, // Optional, defaults to false
}

// Represents the billing data required for the payment key request.
#[derive(Debug, Serialize)]
pub struct PaymobBillingData {
    apartment: String,
    email: masking::Secret<String, common_utils::pii::Email>,
    floor: String,
    first_name: masking::Secret<String>,
    street: masking::Secret<String>,
    building: String,
    phone_number: masking::Secret<String>,
    shipping_method: String, // Not always needed, can default
    postal_code: masking::Secret<String>,
    city: String,
    country: String,
    last_name: masking::Secret<String>,
    state: String,
}

// Creates a PaymobPaymentKeyRequest from router data, auth token, order ID, and integration ID.
impl TryFrom<(
    &PaymobRouterData<&PaymentsAuthorizeRouterData>,
    Secret<String>,
    u64,
    Secret<String>,
)> for PaymobPaymentKeyRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        (item, auth_token, order_id, integration_id): (
            &PaymobRouterData<&PaymentsAuthorizeRouterData>,
            Secret<String>,
            u64,
            Secret<String>,
        ),
    ) -> Result<Self, Self::Error> {
        let billing_address = item
            .router_data
            .get_billing()?;
        let billing_details = billing_address.address.as_ref().ok_or(
            errors::ConnectorError::MissingRequiredField { field_name: "billing_address" }
        )?;

        let billing_data = PaymobBillingData {
            apartment: "NA".to_string(), // Default if not available
            email: item.router_data.request.email.clone().ok_or(
                errors::ConnectorError::MissingRequiredField { field_name: "email" }
            )?,
            floor: "NA".to_string(), // Default if not available
            first_name: billing_details.get_first_name()?.clone(),
            street: billing_details.get_line1()?.clone(),
            building: "NA".to_string(), // Default if not available
            phone_number: billing_address.phone.as_ref().ok_or(
                errors::ConnectorError::MissingRequiredField { field_name: "phone" }
            )?.phone_number.clone(),
            shipping_method: "NA".to_string(), // Default
            postal_code: billing_details.get_zip()?.clone(),
            city: billing_details.get_city()?.clone(),
            country: billing_details.get_country()?.to_string().to_uppercase(), // PayMob expects uppercase country code
            last_name: billing_details.get_last_name()?.clone(),
            state: billing_details.get_state()?.clone(),
        };

        Ok(Self {
            auth_token,
            amount_cents: item.amount.clone(),
            expiration: 3600,
            order_id: order_id.to_string(),
            billing_data,
            currency: item.router_data.request.currency,
            integration_id,
        })
    }
}

// PayMob Payment Key Response
// Represents the response received after requesting a payment key.
#[derive(Debug, Deserialize)]
pub struct PaymobPaymentKeyResponse {
    token: Secret<String>, // This is the payment key (client token)
    
    //TODO: Implement Pay Request/Response
 // PayMob Pay Request (Card Payment)
 // Represents the request body for executing a card payment with PayMob.
 #[derive(Debug, Serialize)]
 pub struct PaymobPayRequest {
     source: PaymobPaymentSource,
     payment_token: Secret<String>, // The payment key obtained from Payment Key Response
 }
 
 // Represents the payment source details, currently only Card.
 #[derive(Debug, Serialize)]
 pub struct PaymobPaymentSource {
  identifier: Secret<String>, // Card number
     subtype: String, // Always "CARD"
     // cvv: Secret<String>, // PayMob might require CVV here depending on integration type
 }
 
 // Creates a PaymobPayRequest from router data and the payment key.
 impl TryFrom<(&PaymobRouterData<&PaymentsAuthorizeRouterData>, Secret<String>)> for PaymobPayRequest {
     type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
         (item, payment_key): (&PaymobRouterData<&PaymentsAuthorizeRouterData>, Secret<String>),
     ) -> Result<Self, Self::Error> {
         match item.router_data.request.payment_method_data.clone() {
             PaymentMethodData::Card(card) => {
                 let source = PaymobPaymentSource {
                     identifier: card.card_number,
                   subtype: "CARD".to_string(),
                     // cvv: card.card_cvc, // Include if needed
                 };
                Ok(Self {
                     source,
                     payment_token: payment_key,
                 })
             }
             _ => Err(errors::ConnectorError::NotImplemented(
                 "Only card payments are supported by PayMob connector".to_string(),
             )
             .into()),
         }
    }
 }
 
 // PayMob Pay Response is handled by the existing PaymobPaymentsResponse structure
 // as the final status is determined from the transaction details endpoint or webhook.
    
   // Generic RouterData wrapper for PayMob
    pub struct PaymobRouterData<T> {
        pub amount: StringMinorUnit, // The type of amount that a connector accepts.
        pub router_data: T,
    }
    
    impl<T> From<(StringMinorUnit, T)> for PaymobRouterData<T> {
        fn from((amount, item): (StringMinorUnit, T)) -> Self {
            Self {
                amount,
                router_data: item,
            }
        }
    }
    
    // PaymentsResponse
    // Represents the status of a payment attempt from PayMob.
    #[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")] // Assuming PayMob uses this case for status
    pub enum PaymobPaymentStatus {
        Success, // Check PayMob docs for actual success status
        Failed, // Check PayMob docs for actual failure status
        #[default]
        Pending, // Check PayMob docs for actual pending/processing status
    }
    
    // Converts PayMob payment status to Hyperswitch attempt status.
    impl From<PaymobPaymentStatus> for common_enums::AttemptStatus {
        fn from(item: PaymobPaymentStatus) -> Self {
            match item {
                // Maps PayMob 'Success' to Hyperswitch 'Charged'.
                PaymobPaymentStatus::Success => Self::Charged,
                // Maps PayMob 'Failed' to Hyperswitch 'Failure'.
                PaymobPaymentStatus::Failed => Self::Failure,
                // Maps PayMob 'Pending' to Hyperswitch 'Pending' or 'Authorizing'.
                PaymobPaymentStatus::Pending => Self::Pending, // Or Authorizing, depending on context
            }
        }
   }
    
    // Represents the overall payment response from PayMob (needs refinement based on actual API).
    #[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct PaymobPaymentsResponse {
        // Fields depend heavily on the specific PayMob endpoint response (/payments/pay?)
        id: String, // Transaction ID from PayMob
        pending: bool,
        success: bool,
        // ... other fields like amount_cents, currency, order, source_data, etc.
    }
    
    // Transforms PayMob's payment response into Hyperswitch's generic RouterData.
    impl<F, T> TryFrom<ResponseRouterData<F, PaymobPaymentsResponse, T, PaymentsResponseData>>
        for RouterData<F, T, PaymentsResponseData>
    {
        type Error = error_stack::Report<errors::ConnectorError>;
        fn try_from(
            item: ResponseRouterData<F, PaymobPaymentsResponse, T, PaymentsResponseData>,
        ) -> Result<Self, Self::Error> {
            // Determine the status based on response fields (needs PayMob API details)
            let status = if item.response.success {
                common_enums::AttemptStatus::Charged
            } else if item.response.pending {
                common_enums::AttemptStatus::Pending
            } else {
                common_enums::AttemptStatus::Failure
            };
    
            // Construct the response, mapping PayMob fields to Hyperswitch fields.
            Ok(Self {
                status,
                response: Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                    redirection_data: Box::new(None), // Populate if redirection is needed
                    mandate_reference: Box::new(None),
                    connector_metadata: None, // Populate with extra data if needed
                    network_txn_id: None,
                    connector_response_reference_id: Some(item.response.id), // Or another relevant ID
                    incremental_authorization_allowed: None,
                    charges: None,
                }),
                ..item.data
            })
        }
    }
    
    // REFUND :
    // Type definition for RefundRequest
    // Represents the request body for initiating a refund with PayMob.
    #[derive(Default, Debug, Serialize)]
    pub struct PaymobRefundRequest {
        transaction_id: String, // PayMob's transaction ID to refund
        amount: StringMinorUnit, // Amount to refund (in minor units)
    }
    
    // Creates a PaymobRefundRequest from Hyperswitch's refund router data.
    impl<F> TryFrom<&PaymobRouterData<&RefundsRouterData<F>>> for PaymobRefundRequest {
        type Error = error_stack::Report<errors::ConnectorError>;
        fn try_from(item: &PaymobRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
            Ok(Self {
                // Extracts the connector transaction ID from the original payment.
                transaction_id: item.router_data.request.connector_transaction_id.clone(),
                // Uses the requested refund amount.
                amount: item.amount.to_owned(),
            })
        }
    }
    
    // Type definition for Refund Response
    // Represents the status of a refund attempt from PayMob.
    #[allow(dead_code)]
    #[derive(Debug, Serialize, Default, Deserialize, Clone)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")] // Assuming PayMob uses this case
    pub enum RefundStatus {
        Success, // Check PayMob docs for actual success status
        Failed, // Check PayMob docs for actual failure status
        #[default]
        Pending, // Check PayMob docs for actual pending status
    }
    
    // Converts PayMob refund status to Hyperswitch refund status.
    impl From<RefundStatus> for enums::RefundStatus {
        fn from(item: RefundStatus) -> Self {
            match item {
                RefundStatus::Success => Self::Success,
                RefundStatus::Failed => Self::Failure,
                RefundStatus::Pending => Self::Pending,
            }
        }
    }
    
    // Represents the refund response from PayMob.
    #[derive(Default, Debug, Clone, Serialize, Deserialize)]
    pub struct RefundResponse {
        id: String, // PayMob's ID for the refund transaction
        // status: RefundStatus, // Status might be part of the response or inferred
        // ... other potential fields like refund_amount, transaction_id, etc.
    }
    
    // Transforms PayMob's refund response into Hyperswitch's generic RouterData for Execute flow.
    impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>> for RefundsRouterData<Execute> {
        type Error = error_stack::Report<errors::ConnectorError>;
        fn try_from(
            item: RefundsResponseRouterData<Execute, RefundResponse>,
        ) -> Result<Self, Self::Error> {
            // Determine refund status based on PayMob response (needs API details)
            let refund_status = enums::RefundStatus::Pending; // Default or map from item.response.status
    
            Ok(Self {
                response: Ok(RefundsResponseData {
                    connector_refund_id: item.response.id.to_string(),
                    refund_status,
                }),
                ..item.data
            })
        }
    }
    
    // Transforms PayMob's refund response into Hyperswitch's generic RouterData for Sync flow.
    impl TryFrom<RefundsResponseRouterData<RSync, RefundResponse>> for RefundsRouterData<RSync> {
        type Error = error_stack::Report<errors::ConnectorError>;
        fn try_from(
            item: RefundsResponseRouterData<RSync, RefundResponse>,
        ) -> Result<Self, Self::Error> {
            // Determine refund status based on PayMob response (needs API details)
            let refund_status = enums::RefundStatus::Pending; // Default or map from item.response.status
   
            Ok(Self {
                response: Ok(RefundsResponseData {
                    connector_refund_id: item.response.id.to_string(),
                    refund_status,
                }),
                ..item.data
           })
        }
    }
    
    // Error Response
    // Represents the error structure returned by PayMob API.
    #[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct PaymobErrorResponse {
        // Fields depend on PayMob's error format
        message: Option<String>,
        detail: Option<String>,
        // code: Option<String>, // PayMob might return specific error codes
    }

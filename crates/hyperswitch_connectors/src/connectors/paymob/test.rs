#![allow(clippy::expect_used)]
use futures::FutureExt; // Required for .then
use hyperswitch_domain_models::router_data::{ConnectorAuthType, PaymentMethodToken, RouterData};
use hyperswitch_domain_models::router_request_types::{PaymentsAuthorizeData, PaymentsSyncData, RefundsData, PaymentsCancelData, PaymentsCaptureData, BrowserInformation};
use hyperswitch_domain_models::router_response_types::{PaymentsResponseData, RefundsResponseData, RedirectForm};
use hyperswitch_domain_models::types as hyperswitch_types;
use hyperswitch_interfaces::api::{self as hyperswitch_api, Connector}; 
use hyperswitch_interfaces::connector_integration::ConnectorIntegration;
use hyperswitch_interfaces::errors;
use masking::{Secret, PeekInterface};

use crate::{
    connector::paymob::Paymob,
    types::{self, ResponseId, api, storage::enums},
    connector::utils as connector_utils,
    utils::{self, ConnectorActions}
};
// Removed transformer import as it's not directly used in tests anymore
// use crate::connectors::paymob::transformers as paymob_transformers;

// Removed wiremock imports

use hyperswitch_domain_models::router_data::PaymentAddress; 
use std::marker::PhantomData;

#[derive(Clone, Copy)]
struct PaymobTest;
impl ConnectorActions for PaymobTest {}
impl utils::Connector for PaymobTest {
    fn get_data(&self) -> hyperswitch_api::ConnectorData {
        hyperswitch_api::ConnectorData {
            connector: Box::new(Paymob::new()),
            connector_name: types::Connector::Paymob,
            get_token: types::api::GetToken::Connector,
            merchant_connector_id: Some("MID_PAYMOB_TEST".to_string()), // Example MID
        }
    }

    // Using MultiAuthKey for Paymob, assuming test_utils provides these
    fn get_auth_token(&self) -> ConnectorAuthType {
        utils::to_connector_auth_type(
            test_utils::connector_auth::ConnectorAuthentication::new()
                .paymob
                .expect("Missing connector authentication configuration for Paymob")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "paymob".to_string()
    }
}

static CONNECTOR: PaymobTest = PaymobTest {};

// Default payment info provider
fn get_default_payment_info() -> Option<utils::PaymentInfo> {
    Some(utils::PaymentInfo {
        email: Some(masking::Secret::new("test@example.com".to_string())),
        // Add other relevant PaymentInfo fields if needed
        ..Default::default()
    })
}

// Provides PaymentsAuthorizeData for a 3DS flow
fn payment_method_details_3ds() -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data: types::api::PaymentMethodData::Card(types::api::Card {
            card_number: Secret::new("4242424242424242".to_string()), // Use a standard test card number
            card_exp_month: Secret::new("12".to_string()),
            card_exp_year: Secret::new("2025".to_string()),
            card_cvc: Secret::new("123".to_string()),
            ..utils::CCardType::default().0
        }),
        amount: 1000, // 10.00 EGP
        currency: enums::Currency::EGP,
        confirm: true,
        capture_method: Some(enums::CaptureMethod::Automatic), 
        authentication_type: Some(enums::AuthenticationType::ThreeDs),
        browser_info: Some(BrowserInformation { // Populated BrowserInfo
            accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string(),
            color_depth: Some(24),
            java_enabled: Some(false),
            java_script_enabled: Some(true),
            language: Some("en-US".to_string()),
            screen_height: Some(1080),
            screen_width: Some(1920),
            time_zone: Some(0),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36".to_string()),
            ip_address: None, // IP usually comes from request context
        }),
        return_url: Some("https://hyperswitch.io/redirect".to_string()),
        ..utils::PaymentAuthorizeType::default().0 // Use default for the rest
    })
}

// Provides PaymentsAuthorizeData for a non-3DS flow (manual capture usually)
fn payment_method_details_manual_capture() -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data: types::api::PaymentMethodData::Card(types::api::Card {
            card_number: Secret::new("4242424242424242".to_string()),
            card_exp_month: Secret::new("12".to_string()),
            card_exp_year: Secret::new("2025".to_string()),
            card_cvc: Secret::new("123".to_string()),
            ..utils::CCardType::default().0
        }),
        amount: 1000, // 10.00 EGP
        currency: enums::Currency::EGP,
        confirm: true,
        capture_method: Some(enums::CaptureMethod::Manual), 
        authentication_type: Some(enums::AuthenticationType::NoThreeDs),
        return_url: Some("https://hyperswitch.io/redirect".to_string()),
        ..utils::PaymentAuthorizeType::default().0 // Use default for the rest
    })
}

// Provides PaymentsAuthorizeData for a non-3DS flow (auto capture usually)
fn payment_method_details_auto_capture() -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data: types::api::PaymentMethodData::Card(types::api::Card {
            card_number: Secret::new("4242424242424242".to_string()),
            card_exp_month: Secret::new("12".to_string()),
            card_exp_year: Secret::new("2025".to_string()),
            card_cvc: Secret::new("123".to_string()),
            ..utils::CCardType::default().0
        }),
        amount: 1000, // 10.00 EGP
        currency: enums::Currency::EGP,
        confirm: true,
        capture_method: Some(enums::CaptureMethod::Automatic), 
        authentication_type: Some(enums::AuthenticationType::NoThreeDs),
        return_url: Some("https://hyperswitch.io/redirect".to_string()),
        ..utils::PaymentAuthorizeType::default().0 // Use default for the rest
    })
}

// Test for Authorize flow resulting in redirection (3DS)
#[actix_web::test]
async fn should_authorize_payment_with_redirect() {
    let payment_details = payment_method_details_3ds();
    let payment_info = get_default_payment_info();

    let response = CONNECTOR
        .authorize_payment(payment_details.clone(), payment_info)
        .await
        .expect("Authorize payment response");

    assert_eq!(response.status, enums::AttemptStatus::AuthenticationPending, "Status should be AuthenticationPending for redirect flow");

    match response.response {
        Ok(PaymentsResponseData::TransactionResponse { 
            resource_id, 
            redirection_data, 
            .. // Ignore other fields
        }) => {
            assert!(matches!(resource_id, ResponseId::ConnectorTransactionId(_)), "Missing ConnectorTransactionId");
            assert!(redirection_data.is_some(), "Redirection data should be present");

            if let Some(redirect_form) = redirection_data {
                assert!(matches!(*redirect_form, RedirectForm::Iframe { .. }), "Redirection data should be an Iframe");
                if let RedirectForm::Iframe { iframe_url, .. } = *redirect_form {
                    assert!(iframe_url.starts_with("https://accept.paymob.com/api/acceptance/iframes/"), "Unexpected iframe URL prefix");
                    let auth = CONNECTOR.get_auth_token();
                    if let ConnectorAuthType::MultiAuthKey { key1, .. } = auth {
                         assert!(iframe_url.contains(key1.peek()), "Iframe URL missing iframe ID (public key)");
                    }
                    assert!(iframe_url.contains("payment_token="), "Iframe URL missing payment_token param");
                } 
            } else {
                panic!("Redirection data was None");
            }
        },
        Ok(_) => panic!("Unexpected successful response type"),
        Err(err) => panic!("Authorize call failed: {:?}", err),
    }
}

// Test for Authorize flow resulting in direct Authorization (Manual Capture)
#[actix_web::test]
async fn should_only_authorize_payment() {
    let response = CONNECTOR
        .authorize_payment(payment_method_details_manual_capture(), get_default_payment_info())
        .await
        .expect("Authorize payment response");

    assert_eq!(response.status, enums::AttemptStatus::Authorized, "Status should be Authorized"); 
    if let Ok(PaymentsResponseData::TransactionResponse { redirection_data, resource_id, .. }) = response.response {
        assert!(redirection_data.is_none(), "Redirection data should NOT be present for direct authorization");
        assert!(matches!(resource_id, ResponseId::ConnectorTransactionId(_)), "Missing ConnectorTransactionId");
    } else {
         panic!("Response was not Ok(TransactionResponse): {:?}", response.response)
    }
}

// Captures a payment previously authorized (Manual Capture flow)
#[actix_web::test]
async fn should_capture_authorized_payment() {
     // Authorize first
     let auth_response = CONNECTOR
        .authorize_payment(payment_method_details_manual_capture(), get_default_payment_info())
        .await
        .expect("Authorize payment failed");
     assert_eq!(auth_response.status, enums::AttemptStatus::Authorized);
     let connector_txn_id = utils::get_connector_transaction_id(auth_response.response)
                             .expect("Missing connector_transaction_id from auth response");

    // Capture
    let response = CONNECTOR
        .capture_payment(connector_txn_id, None, get_default_payment_info()) // Capture full amount
        .await
        .expect("Capture payment response");

    assert_eq!(response.status, enums::AttemptStatus::Charged, "Capture status mismatch");
    if let Ok(PaymentsResponseData::TransactionResponse { resource_id, .. }) = response.response {
        // Capture should ideally return its own transaction ID
        assert!(matches!(resource_id, ResponseId::ConnectorTransactionId(_)), "Missing ConnectorTransactionId for Capture");
    } else {
        panic!("Capture Response was not Ok(TransactionResponse): {:?}", response.response)
    }
}

// Partially captures a payment previously authorized (Manual Capture flow)
#[actix_web::test]
async fn should_partially_capture_authorized_payment() {
    // Authorize first (amount 1000)
     let auth_response = CONNECTOR
        .authorize_payment(payment_method_details_manual_capture(), get_default_payment_info())
        .await
        .expect("Authorize payment failed");
     assert_eq!(auth_response.status, enums::AttemptStatus::Authorized);
     let connector_txn_id = utils::get_connector_transaction_id(auth_response.response)
                             .expect("Missing connector_transaction_id from auth response");

    // Capture partial amount (500)
    let capture_data = Some(types::PaymentsCaptureData {
        amount_to_capture: 500, 
        ..utils::PaymentCaptureType::default().0
    });
    let response = CONNECTOR
        .capture_payment(connector_txn_id, capture_data, get_default_payment_info())
        .await
        .expect("Capture payment response");

    assert_eq!(response.status, enums::AttemptStatus::Charged, "Partial Capture status mismatch");
     if let Ok(PaymentsResponseData::TransactionResponse { resource_id, .. }) = response.response {
        assert!(matches!(resource_id, ResponseId::ConnectorTransactionId(_)), "Missing ConnectorTransactionId for Capture");
    } else {
        panic!("Capture Response was not Ok(TransactionResponse): {:?}", response.response)
    }
}

// Synchronizes an authorized payment (Manual Capture flow)
#[actix_web::test]
async fn should_sync_authorized_payment() {
    let authorize_response = CONNECTOR
        .authorize_payment(payment_method_details_manual_capture(), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    let txn_id = utils::get_connector_transaction_id(authorize_response.response)
                    .expect("Missing connector transaction ID");

    let response = CONNECTOR
        .psync_retry_till_status_matches(
            enums::AttemptStatus::Authorized, // Expect Authorized status after sync
            Some(types::PaymentsSyncData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(
                    txn_id.clone(),
                ),
                 capture_method: Some(enums::CaptureMethod::Manual), // Specify context
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::Authorized, "Synced status mismatch");
}

// Voids a previously authorized payment (Manual Capture flow)
#[actix_web::test]
async fn should_void_authorized_payment() {
    // Authorize first
     let auth_response = CONNECTOR
        .authorize_payment(payment_method_details_manual_capture(), get_default_payment_info())
        .await
        .expect("Authorize payment failed");
     assert_eq!(auth_response.status, enums::AttemptStatus::Authorized);
     let connector_txn_id = utils::get_connector_transaction_id(auth_response.response)
                             .expect("Missing connector_transaction_id from auth response");

    // Void
    let response = CONNECTOR
        .void_payment(
            connector_txn_id, 
            Some(types::PaymentsCancelData {
                cancellation_reason: Some("requested_by_customer".to_string()),
                ..Default::default()
            }), 
            get_default_payment_info()
        )
        .await
        .expect("Void payment response");

    assert_eq!(response.status, enums::AttemptStatus::Voided, "Void status mismatch");
     if let Ok(PaymentsResponseData::TransactionResponse { resource_id, .. }) = response.response {
        // Void should ideally return its own transaction ID
        assert!(matches!(resource_id, ResponseId::ConnectorTransactionId(_)), "Missing ConnectorTransactionId for Void");
    } else {
        panic!("Void Response was not Ok(TransactionResponse): {:?}", response.response)
    }
}

// Refunds a payment captured manually
#[actix_web::test]
async fn should_refund_manually_captured_payment() {
    // Authorize and Capture first
    let capture_response = CONNECTOR
        .authorize_and_capture_payment(payment_method_details_manual_capture(), None, get_default_payment_info())
        .await
        .expect("Capture payment response");
    assert_eq!(capture_response.status, enums::AttemptStatus::Charged);
    let connector_txn_id = utils::get_connector_transaction_id(capture_response.response)
                            .expect("Missing connector transaction ID from capture");

    // Refund
    let response = CONNECTOR
        .refund_payment(connector_txn_id, None, get_default_payment_info()) // Full refund
        .await
        .expect("Refund failed");

    let refund_response = response.response.expect("Missing refund response object");
    assert_eq!(refund_response.refund_status, enums::RefundStatus::Success, "Refund status mismatch");
    assert!(refund_response.connector_refund_id.is_some(), "Missing connector_refund_id");
}

// Partially refunds a payment captured manually
#[actix_web::test]
async fn should_partially_refund_manually_captured_payment() {
    // Authorize and Capture first (amount 1000)
    let capture_response = CONNECTOR
        .authorize_and_capture_payment(payment_method_details_manual_capture(), None, get_default_payment_info())
        .await
        .expect("Capture payment response");
    assert_eq!(capture_response.status, enums::AttemptStatus::Charged);
    let connector_txn_id = utils::get_connector_transaction_id(capture_response.response)
                            .expect("Missing connector transaction ID from capture");

    // Refund partial amount (500)
    let refund_data = Some(types::RefundsData {
        refund_amount: 500,
        ..utils::PaymentRefundType::default().0
    });
    let response = CONNECTOR
        .refund_payment(connector_txn_id, refund_data, get_default_payment_info())
        .await
        .expect("Refund failed");

    let refund_response = response.response.expect("Missing refund response object");
    assert_eq!(refund_response.refund_status, enums::RefundStatus::Success, "Partial Refund status mismatch");
    assert!(refund_response.connector_refund_id.is_some(), "Missing connector_refund_id for partial refund");
}

// Synchronizes a refund from a manually captured payment
#[actix_web::test]
async fn should_sync_manually_captured_refund() {
    // Authorize, Capture, and Refund first
    let refund_response_result = CONNECTOR
        .authorize_and_capture_payment(payment_method_details_manual_capture(), None, get_default_payment_info())
        .then(|capture_res| async {
             let capture_response = capture_res.expect("Capture failed");
             let connector_txn_id = utils::get_connector_transaction_id(capture_response.response)
                                     .expect("Missing connector transaction ID from capture");
             CONNECTOR.refund_payment(connector_txn_id, None, get_default_payment_info()).await
        })
        .await;
        
    let refund_response = refund_response_result.expect("Refund failed");
    let refund_id = refund_response.response.expect("Missing refund response object").connector_refund_id.expect("Missing connector refund ID");

    // Sync Refund
    let response = CONNECTOR
        .rsync_retry_till_status_matches(
            enums::RefundStatus::Success, // Expect Success after sync
            refund_id,
            None,
            get_default_payment_info(),
        )
        .await
        .expect("Rsync failed");

    assert_eq!(
        response.response.expect("Missing sync response").refund_status,
        enums::RefundStatus::Success,
        "Synced Refund status mismatch"
    );
}

// Creates a payment using the automatic capture flow (Non 3DS).
#[actix_web::test]
async fn should_make_payment_auto_capture() { // Renamed for clarity
    let response = CONNECTOR.make_payment(payment_method_details_auto_capture(), get_default_payment_info()).await.expect("Make payment failed");
    assert_eq!(response.status, enums::AttemptStatus::Charged, "Auto capture status mismatch");
    if let Ok(PaymentsResponseData::TransactionResponse { redirection_data, resource_id, .. }) = response.response {
        assert!(redirection_data.is_none(), "Redirection data should NOT be present for auto capture");
        assert!(matches!(resource_id, ResponseId::ConnectorTransactionId(_)), "Missing ConnectorTransactionId");
    } else {
         panic!("Response was not Ok(TransactionResponse): {:?}", response.response)
    }
}

// Synchronizes a payment using the automatic capture flow (Non 3DS).
#[actix_web::test]
async fn should_sync_auto_captured_payment() {
    let authorize_response = CONNECTOR.make_payment(payment_method_details_auto_capture(), get_default_payment_info()).await.expect("Make payment failed");
    assert_eq!(authorize_response.status, enums::AttemptStatus::Charged);
    let txn_id = utils::get_connector_transaction_id(authorize_response.response).expect("Missing connector transaction id");

    let response = CONNECTOR
        .psync_retry_till_status_matches(
            enums::AttemptStatus::Charged, // Expect Charged status after sync
            Some(types::PaymentsSyncData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(
                    txn_id.clone(),
                ),
                capture_method: Some(enums::CaptureMethod::Automatic),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::Charged, "Synced status mismatch");
}

// Refunds a payment using the automatic capture flow (Non 3DS).
#[actix_web::test]
async fn should_refund_auto_captured_payment() {
    // Make Payment first
    let payment_response = CONNECTOR.make_payment(payment_method_details_auto_capture(), get_default_payment_info()).await.expect("Make payment failed");
    let connector_txn_id = utils::get_connector_transaction_id(payment_response.response).expect("Missing connector transaction ID");

    // Refund
    let response = CONNECTOR
        .refund_payment(connector_txn_id, None, get_default_payment_info())
        .await
        .expect("Refund failed");

    let refund_response = response.response.expect("Missing refund response object");
    assert_eq!(refund_response.refund_status, enums::RefundStatus::Success, "Refund status mismatch");
    assert!(refund_response.connector_refund_id.is_some(), "Missing connector_refund_id");
}

// Partially refunds a payment using the automatic capture flow (Non 3DS).
#[actix_web::test]
async fn should_partially_refund_succeeded_payment() {
    // Make Payment first (amount 1000)
    let payment_response = CONNECTOR.make_payment(payment_method_details_auto_capture(), get_default_payment_info()).await.expect("Make payment failed");
    let connector_txn_id = utils::get_connector_transaction_id(payment_response.response).expect("Missing connector transaction ID");

    // Refund partial amount (500)
    let refund_data = Some(types::RefundsData {
        refund_amount: 500,
        ..utils::PaymentRefundType::default().0
    });
    let response = CONNECTOR
        .refund_payment(connector_txn_id, refund_data, get_default_payment_info())
        .await
        .expect("Refund failed");

    let refund_response = response.response.expect("Missing refund response object");
    assert_eq!(refund_response.refund_status, enums::RefundStatus::Success, "Partial Refund status mismatch");
    assert!(refund_response.connector_refund_id.is_some(), "Missing connector_refund_id for partial refund");
}

// Creates multiple refunds against a payment using the automatic capture flow (Non 3DS).
// This test implicitly uses the CONNECTOR.make_payment_and_multiple_refund helper
#[actix_web::test]
async fn should_refund_succeeded_payment_multiple_times() {
    // Use helper for multiple refunds
    CONNECTOR
        .make_payment_and_multiple_refund(
            payment_method_details_auto_capture(), // Use auto-capture details
            vec![
                 Some(types::RefundsData { // Refund 1: 300
                    refund_amount: 300,
                    ..utils::PaymentRefundType::default().0
                }),
                Some(types::RefundsData { // Refund 2: 200
                    refund_amount: 200,
                    ..utils::PaymentRefundType::default().0
                }),
            ],
            get_default_payment_info(),
        )
        .await;
    // Assertions are handled within the helper function typically
}

// Synchronizes a refund using the automatic capture flow (Non 3DS).
#[actix_web::test]
async fn should_sync_refund() {
    // Make Payment and Refund first
    let refund_response_result = CONNECTOR
        .make_payment(payment_method_details_auto_capture(), get_default_payment_info())
        .then(|payment_res| async {
             let payment_response = payment_res.expect("Make payment failed");
             let connector_txn_id = utils::get_connector_transaction_id(payment_response.response)
                                     .expect("Missing connector transaction ID");
             CONNECTOR.refund_payment(connector_txn_id, None, get_default_payment_info()).await
        })
        .await;

    let refund_response = refund_response_result.expect("Refund failed");
    let refund_id = refund_response.response.expect("Missing refund response object").connector_refund_id.expect("Missing connector refund ID");

    // Sync Refund
    let response = CONNECTOR
        .rsync_retry_till_status_matches(
            enums::RefundStatus::Success, // Expect Success after sync
            refund_id,
            None,
            get_default_payment_info(),
        )
        .await
        .expect("Rsync failed");

    assert_eq!(
        response.response.expect("Missing sync response").refund_status,
        enums::RefundStatus::Success,
         "Synced Refund status mismatch"
    );
}

// Cards Negative scenarios
// Creates a payment with incorrect CVC.
#[actix_web::test]
async fn should_fail_payment_for_incorrect_cvc() {
    let response = CONNECTOR
        .make_payment(
            Some(types::PaymentsAuthorizeData {
                payment_method_data: types::api::PaymentMethodData::Card(api::Card {
                    card_cvc: Secret::new("000"), // Incorrect CVC
                    ..utils::CCardType::default().0
                }),
                amount: 1000, currency: enums::Currency::EGP, confirm: true,
                capture_method: Some(enums::CaptureMethod::Automatic), 
                authentication_type: Some(enums::AuthenticationType::NoThreeDs),
                 ..utils::PaymentAuthorizeType::default().0
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Request failed unexpectedly");
    // Assertions depend heavily on Paymob's specific error for invalid CVC
    // and the implementation of `build_error_response`. Placeholder for now.
    assert!(response.response.is_err(), "Expected payment to fail for incorrect CVC");
    // let error = response.response.unwrap_err();
    // assert_eq!(error.reason, Some("Invalid CVC".to_string())); // Example assertion based on Paymob docs
    // assert_eq!(error.code, "PAYMOB_INVALID_CVC"); // Example expected code
}

// Creates a payment with incorrect expiry month.
#[actix_web::test]
async fn should_fail_payment_for_invalid_exp_month() {
     let response = CONNECTOR
        .make_payment(
            Some(types::PaymentsAuthorizeData {
                payment_method_data: types::api::PaymentMethodData::Card(api::Card {
                    card_exp_month: Secret::new("99"), // Incorrect Month
                     ..utils::CCardType::default().0
                }),
                 amount: 1000, currency: enums::Currency::EGP, confirm: true,
                 capture_method: Some(enums::CaptureMethod::Automatic), 
                authentication_type: Some(enums::AuthenticationType::NoThreeDs),
                ..utils::PaymentAuthorizeType::default().0
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Request failed unexpectedly");
    assert!(response.response.is_err(), "Expected payment to fail for invalid expiry month");
    // let error = response.response.unwrap_err();
    // assert_eq!(error.reason, Some("Invalid Expiry Month".to_string())); // Example assertion
}

// Creates a payment with incorrect expiry year.
#[actix_web::test]
async fn should_fail_payment_for_incorrect_expiry_year() {
     let response = CONNECTOR
        .make_payment(
            Some(types::PaymentsAuthorizeData {
                payment_method_data: types::api::PaymentMethodData::Card(api::Card {
                    card_exp_year: Secret::new("2000"), // Incorrect Year
                     ..utils::CCardType::default().0
                }),
                 amount: 1000, currency: enums::Currency::EGP, confirm: true,
                 capture_method: Some(enums::CaptureMethod::Automatic), 
                authentication_type: Some(enums::AuthenticationType::NoThreeDs),
                ..utils::PaymentAuthorizeType::default().0
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Request failed unexpectedly");
    assert!(response.response.is_err(), "Expected payment to fail for invalid expiry year");
    // let error = response.response.unwrap_err();
    // assert_eq!(error.reason, Some("Invalid Expiry Year".to_string())); // Example assertion
}

// Voids a payment using automatic capture flow (Non 3DS).
#[actix_web::test]
async fn should_fail_void_payment_for_auto_capture() {
    // Make Payment (which captures automatically)
    let authorize_response = CONNECTOR.make_payment(payment_method_details_auto_capture(), get_default_payment_info()).await.expect("Make payment failed");
    assert_eq!(authorize_response.status, enums::AttemptStatus::Charged);
    let txn_id = utils::get_connector_transaction_id(authorize_response.response).expect("Missing connector transaction id");

    // Attempt to Void
    let void_response = CONNECTOR
        .void_payment(txn_id.clone(), None, get_default_payment_info())
        .await
        .expect("Void request failed unexpectedly");
    // Paymob likely rejects voiding a captured transaction. Assert error.
    assert!(void_response.response.is_err(), "Expected void to fail for captured payment");
    // let error = void_response.response.unwrap_err();
    // assert_eq!(error.code, "PAYMOB_VOID_CAPTURED_ERROR"); // Example assertion: Replace with actual Paymob error mapping
    // assert_eq!(error.reason, Some("Cannot void a captured transaction".to_string())); // Example reason
}

// Captures a payment using invalid connector payment id.
#[actix_web::test]
async fn should_fail_capture_for_invalid_payment() {
    let capture_response = CONNECTOR
        .capture_payment("invalid_txn_id_123".to_string(), None, get_default_payment_info())
        .await
        .expect("Capture request failed unexpectedly");
    // Paymob should reject capturing a non-existent transaction. Assert error.
    assert!(capture_response.response.is_err(), "Expected capture to fail for invalid ID");
    // let error = capture_response.response.unwrap_err();
    // assert_eq!(error.code, "PAYMOB_INVALID_TRANSACTION_ID"); // Example assertion: Replace with actual Paymob error mapping
     // assert_eq!(error.reason, Some("Transaction not found".to_string())); // Example reason
}

// Refunds a payment with refund amount higher than payment amount.
#[actix_web::test]
async fn should_fail_for_refund_amount_higher_than_payment_amount() {
    // Make Payment (amount 1000)
    let payment_response = CONNECTOR.make_payment(payment_method_details_auto_capture(), get_default_payment_info()).await.expect("Make payment failed");
    let connector_txn_id = utils::get_connector_transaction_id(payment_response.response).expect("Missing connector transaction ID");

    // Attempt to refund more (1500)
    let refund_data = Some(types::RefundsData {
        refund_amount: 1500,
        ..utils::PaymentRefundType::default().0
    });
    let response = CONNECTOR
        .refund_payment(connector_txn_id, refund_data, get_default_payment_info())
        .await
        .expect("Refund request failed unexpectedly");
    // Paymob should reject refunding more than captured. Assert error.
     assert!(response.response.is_err(), "Expected refund to fail for excessive amount");
    // let error = response.response.unwrap_err();
    // assert_eq!(error.code, "PAYMOB_REFUND_AMOUNT_EXCEEDED"); // Example assertion: Replace with actual Paymob error mapping
    // assert_eq!(error.reason, Some("Refund amount exceeds transaction amount".to_string())); // Example reason
}

// Connector dependent test cases goes here

// [#478]: add unit tests for non 3DS, wallets & webhooks in connector tests

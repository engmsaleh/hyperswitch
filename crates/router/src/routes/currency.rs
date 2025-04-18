use actix_web::{web, HttpRequest, HttpResponse};
use router_env::Flow;

use crate::{
    core::{api_locking, currency},
    routes::AppState,
    services::{api, authentication as auth},
};

#[cfg(feature = "v1")]
pub async fn retrieve_forex(state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let flow = Flow::RetrieveForexFlow;
    Box::pin(api::server_wrap(
        flow,
        state,
        &req,
        (),
        |state, _auth: auth::AuthenticationData, _, _| currency::retrieve_forex(state),
        auth::auth_type(
            &auth::HeaderAuth(auth::ApiKeyAuth {
                is_connected_allowed: false,
                is_platform_allowed: false,
            }),
            &auth::DashboardNoPermissionAuth,
            req.headers(),
        ),
        api_locking::LockAction::NotApplicable,
    ))
    .await
}

#[cfg(feature = "v1")]
pub async fn convert_forex(
    state: web::Data<AppState>,
    req: HttpRequest,
    params: web::Query<api_models::currency::CurrencyConversionParams>,
) -> HttpResponse {
    let flow = Flow::RetrieveForexFlow;
    let amount = params.amount;
    let to_currency = &params.to_currency;
    let from_currency = &params.from_currency;
    Box::pin(api::server_wrap(
        flow,
        state.clone(),
        &req,
        (),
        |state, _: auth::AuthenticationData, _, _| {
            currency::convert_forex(
                state,
                amount.get_amount_as_i64(),
                to_currency.to_string(),
                from_currency.to_string(),
            )
        },
        auth::auth_type(
            &auth::HeaderAuth(auth::ApiKeyAuth {
                is_connected_allowed: false,
                is_platform_allowed: false,
            }),
            &auth::DashboardNoPermissionAuth,
            req.headers(),
        ),
        api_locking::LockAction::NotApplicable,
    ))
    .await
}

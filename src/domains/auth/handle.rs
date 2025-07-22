use std::sync::Arc;

use axum::{
    extract::Query,
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use tracing::instrument;
use validator::Validate;

use crate::{
    app::AppState,
    domains::auth::{
        model::{AuthResponse, GoogleTokenRequest},
        query::{
            ForgotPasswordRequestDto, LoginUserDto, RegisterUserDto, ResetPasswordRequestDto,
            Response, UserLoginResponseDto, VerifyEmailQueryDto,
        },
    },
    infrastructure::mail::mails::{send_verification_email, send_welcome_email},
    utils::{create_auth_cookie, validate_dto},
    Error, Result,
};

pub fn auth_houtes() -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/verify-email", get(verify_email))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
        .route("/google/callback", post(auth_google))
}

#[instrument(name = "register_user", skip(app_state, new_user))]
pub async fn register(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(new_user): Json<RegisterUserDto>,
) -> Result<impl IntoResponse> {
    app_state
        .recaptcha_service
        .verify_catptcha_token(&new_user.recaptcha_token, "register_user")
        .await?;

    validate_dto(&new_user)?;

    let user = app_state.auth_service.register(new_user).await?;

    let token = user.verification_token.ok_or(Error::BadRequest {
        message: "Invalid data!".to_string(),
    })?;

    send_verification_email(&user.email, &user.name, &token).await?;

    Ok((
        StatusCode::CREATED,
        Json(Response {
            status: "success",
            message: "Registration successful! Please check your email to verify your account."
                .to_string(),
        }),
    ))
}

#[instrument(name = "login_user", skip(app_state, user))]
pub async fn login(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(user): Json<LoginUserDto>,
) -> Result<impl IntoResponse> {
    let _recaptcha_result = app_state
        .recaptcha_service
        .verify_catptcha_token(&user.recaptcha_token, "login_user")
        .await?;

    user.validate().map_err(|_| Error::BadRequest {
        message: "Invalid data".to_string(),
    })?;

    let login_result = app_state
        .auth_service
        .login(&user.email, &user.password_hash, user.auth_provider)
        .await?;

    let token = &login_result.token;

    let cookie = create_auth_cookie(token, &app_state.config)?;

    let mut response = Json(UserLoginResponseDto {
        status: "success".to_string(),
        token: token.to_owned(),
        message: "Login successfully!".into(),
    })
    .into_response();

    response
        .headers_mut()
        .insert(SET_COOKIE, cookie.to_string().parse().unwrap());

    Ok((StatusCode::OK, response))
}

#[instrument(name = "verify_email", skip(app_state, params))]
pub async fn verify_email(
    Query(params): Query<VerifyEmailQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse> {
    params.validate().map_err(|_| Error::BadRequest {
        message: "Invalid data".into(),
    })?;

    let token = app_state.auth_service.verify_email(params.token).await?;

    let cookie = create_auth_cookie(&token, &app_state.config)?;

    let mut headers = HeaderMap::new();
    headers.append(SET_COOKIE, cookie.to_string().parse().unwrap());

    Ok((
        StatusCode::OK,
        headers,
        Json(Response {
            status: "success",
            message: "Email verified successfully!".to_string(),
        }),
    ))
}

#[instrument(name = "forgot_password", skip(app_state, email))]
pub async fn forgot_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(email): Json<ForgotPasswordRequestDto>,
) -> Result<impl IntoResponse> {
    email.validate().map_err(|_| Error::BadRequest {
        message: "Invalid data".into(),
    })?;

    app_state.auth_service.forgot_password(email.email).await?;

    Ok((
        StatusCode::OK,
        Json(Response {
            message: "Password reset link has been sent to your email.".to_string(),
            status: "success",
        }),
    ))
}

#[instrument(name = "reset_password", skip(app_state, body))]
pub async fn reset_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<ResetPasswordRequestDto>,
) -> Result<impl IntoResponse> {
    body.validate().map_err(|_| Error::BadRequest {
        message: "Invalid data".into(),
    })?;

    app_state
        .auth_service
        .reset_password(body.token, body.new_password)
        .await?;

    Ok((
        StatusCode::OK,
        Json(Response {
            message: "Password has been successfully reset.".to_string(),
            status: "success",
        }),
    ))
}

#[instrument(name = "auth_google", skip(app_state, payload))]
pub async fn auth_google(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(payload): Json<GoogleTokenRequest>,
) -> Result<impl IntoResponse> {
    match app_state
        .auth_service
        .handle_google_login(&payload.token)
        .await
    {
        Ok(user) => {
            send_welcome_email(&user.email, &user.name).await?;
            Ok((
                StatusCode::OK,
                Json(AuthResponse {
                    jwt_token: Some(user.token),
                    message: "Login successful!".to_string(),
                    success: true,
                }),
            ))
        }
        Err(_) => Err(Error::GoogleLogin {
            response: AuthResponse {
                success: false,
                message: "Login failed. You probably already have an account with this e-mail!"
                    .to_string(),
                jwt_token: None,
            },
        }),
    }
}

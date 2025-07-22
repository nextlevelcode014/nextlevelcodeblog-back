use reqwest::Client;
use std::collections::HashMap;

use crate::{domains::recaptcha::model::RecaptchaResponse, Error, Result};

use tracing::error;

#[derive(Clone, Default)]
pub struct RecaptchaService {
    client: Client,
    secret_key: String,
}

impl RecaptchaService {
    pub fn new() -> Self {
        let secret_key =
            std::env::var("RECAPTCHA_SECRET_KEY").expect("RECAPTCHA_SECRET_KEY must be set");

        Self {
            client: Client::new(),
            secret_key,
        }
    }

    pub async fn verify_catptcha_token(
        &self,
        token: &str,
        expected_action: &str,
    ) -> Result<RecaptchaResponse> {
        let mut params = HashMap::new();
        params.insert("secret", self.secret_key.as_str());
        params.insert("response", token);

        let response = self
            .client
            .post("https://www.google.com/recaptcha/api/siteverify")
            .form(&params)
            .send()
            .await
            .map_err(|_| Error::RecaptchaValidation)?;

        let recaptcha_response: RecaptchaResponse = response
            .json()
            .await
            .map_err(|_| Error::RecaptchaValidation)?;

        if !recaptcha_response.success {
            error!("Recaptcha Response");
            return Err(Error::RecaptchaValidation);
        }

        if recaptcha_response.action != expected_action {
            error!("Recaptcha Action");
            return Err(Error::RecaptchaValidation);
        }

        if recaptcha_response.score < 0.5 {
            error!("Recaptcha Score");
            return Err(Error::RecaptchaValidation);
        }

        Ok(recaptcha_response)
    }
}

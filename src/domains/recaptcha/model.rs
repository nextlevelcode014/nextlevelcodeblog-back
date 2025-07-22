use serde::Deserialize;

#[derive(Deserialize)]
pub struct RecaptchaResponse {
    pub success: bool,
    pub score: f32,
    pub action: String,
    pub challenge_ts: String,
    pub hostname: String,
    #[serde(rename = "errorCodes")]
    pub error_codes: Option<Vec<String>>,
}

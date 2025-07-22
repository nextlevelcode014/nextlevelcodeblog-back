use serde::{Deserialize, Serialize};
fn string_to_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    match s.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(serde::de::Error::custom("invalid boolean string")),
    }
}

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.filter(|s| !s.trim().is_empty()))
}
#[derive(Debug, Deserialize)]
pub struct GoogleTokenRequest {
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleUserInfo {
    pub sub: String,
    pub email: String,
    #[serde(deserialize_with = "string_to_bool")]
    pub email_verified: bool,
    pub name: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub picture: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleUserInfoReturn {
    pub email: String,
    pub name: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub jwt_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GoogleUserInfoClaims {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
    #[serde(rename = "email_verified")]
    pub email_verified: bool,
    pub aud: String,
    pub iss: String,
    pub exp: usize,
    pub iat: usize,
}

use std::env::{self, var};

use tracing::warn;

use crate::{Error, Result};

use super::sendmail::send_email;

pub async fn send_verification_email(to_email: &str, username: &str, token: &str) -> Result<()> {
    let subject = "Email Verification";
    let template_path = include_str!("templates/Verification-email.html");
    let base_url = &format!(
        "{}/confirm-auth/verify-email",
        env::var("FRONT_URL").unwrap_or_else(|_| {
            warn!("FRONT_URL not set, using default value");
            "http://localhost:3000".to_string()
        })
    );
    let verification_link = create_verification_link(base_url, token);
    let env_login_url = var("FRONT_URL").unwrap_or_else(|_| {
        warn!("FRONT_URL not set, using default value");
        "http://localhost:3000".to_string()
    });
    let login_url = format!("{}/login", env_login_url);

    let placeholders = vec![
        ("{{username}}", username),
        ("{{verification_link}}", &verification_link),
        ("{{login_url}}", &login_url),
    ];
    let max_attemps = 3;

    for attemps in 1..=max_attemps {
        match send_email(to_email, subject, template_path, &placeholders).await {
            Ok(_) => return Ok(()),
            Err(err) if attemps < max_attemps => {
                warn!("Attemp {} failed: {:?}. Retrying...", attemps, err);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await
            }
            Err(err) => return Err(err),
        }
    }

    Err(Error::InternalServerError)
}

fn create_verification_link(base_url: &str, token: &str) -> String {
    format!("{}?token={}", base_url, token)
}

pub async fn send_welcome_email(to_email: &str, username: &str) -> Result<()> {
    let subject = "Welcome to Application";
    let template_path = include_str!("templates/Welcome-email.html");
    let x_url = "x.com/next_level_code";
    let github_url = "https://github.com/m4rc3l04ugu2t0";
    let placeholders = vec![
        ("{{username}}", username),
        ("{{x_url}}", x_url),
        ("{{github_url}}", github_url),
    ];

    send_email(to_email, subject, template_path, &placeholders).await
}

pub async fn send_forgot_password_email(
    to_email: &str,
    reset_link: &str,
    username: &str,
) -> Result<()> {
    let subject = "Rest your Password";
    let template_path = include_str!("templates/RestPassword-email.html");
    let placeholders = [("{{username}}", username), ("{{reset_link}}", reset_link)];

    send_email(to_email, subject, template_path, &placeholders).await
}

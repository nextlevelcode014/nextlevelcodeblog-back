use crate::{Error, Result};
use lettre::{
    message::{header, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::env::var;
use tracing::{error, info};

pub async fn send_email(
    to: &str,
    subject: &str,
    html_template: &'static str,
    placeholders: &[(&str, &str)],
) -> Result<()> {
    let smtp_username = var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let smtp_password = var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
    let smtp_server = var("SMTP_SERVER").expect("SMTP_SERVER must be set");
    let smtp_port: u16 = var("SMTP_PORT")
        .expect("SMPT_PORT must be set")
        .parse()
        .unwrap();

    let mut html_template = html_template.to_string();

    for (k, v) in placeholders {
        html_template = html_template.replace(k, v);
    }

    let email = Message::builder()
        .from(smtp_username.parse().unwrap())
        .to(to.parse().unwrap())
        .subject(subject)
        .header(header::ContentType::TEXT_HTML)
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_HTML)
                .body(html_template),
        )
        .map_err(|e| {
            error!("Failed to send email: {:?}", e);
            Error::email_error("Failed to send email.")
        })?;

    let creds = Credentials::new(smtp_username.clone(), smtp_password.clone());
    let mailer = SmtpTransport::starttls_relay(&smtp_server)
        .unwrap()
        .credentials(creds)
        .port(smtp_port)
        .build();

    let result = mailer.send(&email);

    match result {
        Ok(_) => info!("Email sent successfully!"),
        Err(e) => {
            error!("Failed to send email: {:?}", e);
            return Err(Error::email_error("Failed to send email."));
        }
    }

    Ok(())
}

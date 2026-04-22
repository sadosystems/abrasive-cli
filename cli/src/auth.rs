//! GitHub OAuth device flow + token cache.
//!
//! On first use the CLI runs the device flow: it asks GitHub for a
//! short user code, prints it along with a URL, and polls until the
//! user authorizes in their browser. The resulting token is saved to
//! ~/.config/abrasive/token and reused on subsequent invocations.
//!
//! The token is a real per-user GitHub token; the daemon validates it
//! against the GitHub API on every connection (see daemon/src/auth.rs).

use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::errors::AuthError;

const ABRASIVE_WEB_URL: &str = "https://abrasive.build";
const TOKEN_PREFIX: &str = "abrasive_";

/// Public OAuth App client_id for the "Claviger" GitHub OAuth App.
/// Not a secret — it identifies the app to GitHub. Device flow does
/// not use a client secret.
const GITHUB_CLIENT_ID: &str = "Ov23liPnfnBs67h2r1vz";

/// Scopes the daemon needs to verify org membership.
const SCOPES: &str = "read:org";

const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Deserialize)]
struct DeviceCodeResp {
    device_code: String,
    user_code: String,
    verification_uri: String,
    interval: u64,
}

/// Returns the saved token if one exists. Does NOT run the device flow.
pub fn saved_token() -> Option<String> {
    read_saved_token()
}

/// Always runs the device flow, replacing any saved token.
pub fn login() -> Result<String, AuthError> {
    let token = device_flow()?;
    if let Err(e) = write_saved_token(&token) {
        eprintln!("[auth] warning: {e}");
    }
    Ok(token)
}

fn device_flow() -> Result<String, AuthError> {
    let agent = ureq::agent();
    let resp = request_device_code(&agent)?;
    print_user_instructions(&resp);
    poll_for_token(&agent, &resp)
}

fn request_device_code(agent: &ureq::Agent) -> Result<DeviceCodeResp, AuthError> {
    agent
        .post(DEVICE_CODE_URL)
        .set("Accept", "application/json")
        .send_form(&[("client_id", GITHUB_CLIENT_ID), ("scope", SCOPES)])
        .map_err(AuthError::DeviceCodeRequest)?
        .into_json()
        .map_err(AuthError::DeviceCodeParse)
}

fn print_user_instructions(resp: &DeviceCodeResp) {
    eprintln!(
        "\n\
         To authenticate, visit:\n\
         \x20   {}\n\
         And enter the code:\n\
         \x20   {}\n\n\
         Waiting for authorization...",
        resp.verification_uri, resp.user_code,
    );
    let _ = std::io::stderr().flush();
}

fn poll_for_token(agent: &ureq::Agent, resp: &DeviceCodeResp) -> Result<String, AuthError> {
    let mut interval = Duration::from_secs(resp.interval.max(1));
    loop {
        thread::sleep(interval);
        let json = poll_once(agent, &resp.device_code)?;
        if let Some(t) = json.get("access_token").and_then(|v| v.as_str()) {
            eprintln!("[auth] success");
            break Ok(t.to_string());
        }
        handle_poll_error(json, &mut interval)?;
    }
}

fn poll_once(agent: &ureq::Agent, device_code: &str) -> Result<Value, AuthError> {
    agent
        .post(ACCESS_TOKEN_URL)
        .set("Accept", "application/json")
        .send_form(&[
            ("client_id", GITHUB_CLIENT_ID),
            ("device_code", device_code),
            ("grant_type", DEVICE_CODE_GRANT_TYPE),
        ])
        .map_err(AuthError::TokenPoll)?
        .into_json()
        .map_err(AuthError::TokenPollParse)
}

fn handle_poll_error(json: Value, interval: &mut Duration) -> Result<(), AuthError> {
    let err_str = json
        .get("error")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or(AuthError::UnexpectedResponse(json))?;

    match err_str.as_str() {
        "authorization_pending" => Ok(()),
        "slow_down" => {
            *interval += Duration::from_secs(5);
            Ok(())
        }
        "expired_token" => Err(AuthError::DeviceCodeExpired),
        "access_denied" => Err(AuthError::AuthorizationDenied),
        _ => Err(AuthError::GitHub(err_str)),
    }
}

fn token_path() -> Option<PathBuf> {
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("abrasive").join("token"))
}

fn read_saved_token() -> Option<String> {
    let path = token_path()?;
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn write_saved_token(token: &str) -> Result<(), AuthError> {
    let path = token_path().ok_or(AuthError::NoHome)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(AuthError::WriteToken)?;
    }
    fs::write(&path, token).map_err(AuthError::WriteToken)?;
    chmod_600(&path);
    Ok(())
}

#[cfg(unix)]
fn chmod_600(path: &std::path::Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn chmod_600(_path: &std::path::Path) {}

/// Prompt the user to paste a token from the dashboard, then save it
/// to ~/.config/abrasive/credentials.toml.
pub fn paste_login() -> Result<String, AuthError> {
    eprintln!(
        "please paste the token found on {}/me below",
        ABRASIVE_WEB_URL
    );
    let _ = io::stderr().flush();

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(AuthError::ReadStdin)?;

    let token = line.trim();
    if token.is_empty() {
        return Err(AuthError::EmptyToken);
    }
    if !token.starts_with(TOKEN_PREFIX) {
        return Err(AuthError::InvalidToken);
    }

    write_credentials(token)?;
    eprintln!("       Login token for `abrasive` saved");
    Ok(token.to_string())
}

/// Returns the abrasive API token saved by `paste_login`, if any.
pub fn saved_api_token() -> Option<String> {
    let path = credentials_path()?;
    let raw = fs::read_to_string(&path).ok()?;
    let parsed: toml::Value = toml::from_str(&raw).ok()?;
    parsed
        .get("abrasive")?
        .get("token")?
        .as_str()
        .map(String::from)
}

fn credentials_path() -> Option<PathBuf> {
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("abrasive").join("credentials.toml"))
}

fn write_credentials(token: &str) -> Result<(), AuthError> {
    let path = credentials_path().ok_or(AuthError::NoHome)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(AuthError::WriteToken)?;
    }
    let content = format!("[abrasive]\ntoken = \"{}\"\n", token);
    fs::write(&path, content).map_err(AuthError::WriteToken)?;
    chmod_600(&path);
    Ok(())
}

use std::process::ExitCode;

#[derive(Debug)]
pub struct CliError {
    pub kind: CliErrorKind,
    pub exit_code: ExitCode,
}

#[derive(Debug, thiserror::Error)]
pub enum CliErrorKind {
    #[error("failed to connect to build servers: {0}")]
    Connect(std::io::Error),

    #[error("build server IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid response from build server: {0}")]
    Protocol(#[from] abrasive_protocol::DecodeError),

    #[error("server closed connection before build finished")]
    Disconnected,

    #[error("invalid path, path contains non-UTF-8 characters {0}")]
    InvalidPath(String),

    #[error("cannot read abrasive.toml")]
    NoToml,

    #[error("invalid path, path contains non-UTF-8 characters {0}")]
    InvalidToml(String),

    #[error("cannot determine current directory: {0}")]
    NoCwd(std::io::Error),

    #[error("cargo not found: {0}")]
    CargoNotFound(std::io::Error),

    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no saved token, run `abrasive-cli auth` first")]
    NoSavedToken,

    #[error("no HOME or XDG_CONFIG_HOME set")]
    NoHome,

    #[error("could not write token file: {0}")]
    WriteToken(#[source] std::io::Error),

    #[error("device code request failed: {0}")]
    DeviceCodeRequest(#[source] ureq::Error),

    #[error("device code response parse failed: {0}")]
    DeviceCodeParse(#[source] std::io::Error),

    #[error("token poll failed: {0}")]
    TokenPoll(#[source] ureq::Error),

    #[error("token poll parse failed: {0}")]
    TokenPollParse(#[source] std::io::Error),

    #[error("device code expired before authorization; run `abrasive-cli auth` again")]
    DeviceCodeExpired,

    #[error("authorization denied by user")]
    AuthorizationDenied,

    #[error("github device flow error: {0}")]
    GitHub(String),

    #[error("unexpected token response from github: {0}")]
    UnexpectedResponse(serde_json::Value),
}

pub type CliResult<T> = Result<T, CliError>;

impl CliError {
    pub fn connect(e: std::io::Error) -> Self {
        Self {
            kind: CliErrorKind::Connect(e),
            exit_code: ExitCode::FAILURE,
        }
    }

    pub fn disconnected() -> Self {
        Self {
            kind: CliErrorKind::Disconnected,
            exit_code: ExitCode::FAILURE,
        }
    }

    pub fn invalid_path(msg: String) -> Self {
        Self {
            kind: CliErrorKind::InvalidPath(msg),
            exit_code: ExitCode::FAILURE,
        }
    }

    pub fn no_toml() -> Self {
        Self {
            kind: CliErrorKind::NoToml,
            exit_code: ExitCode::FAILURE,
        }
    }

    pub fn no_cwd(e: std::io::Error) -> Self {
        Self {
            kind: CliErrorKind::NoCwd(e),
            exit_code: ExitCode::FAILURE,
        }
    }

    pub fn cargo_not_found(e: std::io::Error) -> Self {
        // command not found
        Self {
            kind: CliErrorKind::CargoNotFound(e),
            exit_code: ExitCode::from(127),
        }
    }

    pub fn exit(&self) -> ExitCode {
        eprintln!("{}", self.kind);
        self.exit_code
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.kind)
    }
}

impl std::error::Error for CliError {}

impl From<CliErrorKind> for CliError {
    fn from(kind: CliErrorKind) -> Self {
        Self {
            kind,
            exit_code: ExitCode::FAILURE,
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliErrorKind::Io(e).into()
    }
}

impl From<abrasive_protocol::DecodeError> for CliError {
    fn from(e: abrasive_protocol::DecodeError) -> Self {
        CliErrorKind::Protocol(e).into()
    }
}

impl From<AuthError> for CliError {
    fn from(e: AuthError) -> Self {
        CliErrorKind::Auth(e).into()
    }
}

impl From<toml::de::Error> for CliError {
    fn from(e: toml::de::Error) -> Self {
        CliErrorKind::InvalidToml(e.to_string()).into()
    }
}

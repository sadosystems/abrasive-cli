/// This is the entry point fot the abrasive CLI
///
use abrasive::agent;
use abrasive::auth;
use abrasive::errors::{self, CliError, CliResult};
use abrasive::platform::host_triple;
use abrasive::tls;
use abrasive_protocol::{BuildRequest, FileEntry, Manifest, Message};
use clap::builder::styling::{AnsiColor, Styles};
use clap::{CommandFactory, Parser, Subcommand};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::Deserialize;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::sync_channel;
use std::thread;
use std::time::Duration;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command as Cmd, ExitCode, Stdio},
};

const IP: &str = "157.180.55.180";
const PORT: u16 = 8400;
const REMOTE_COMMANDS: &[&str] = &[
    "build", "run", "test", "bench", "check", "clippy", "doc", "nop", "clean",
];
const ABRASIVE_COMMANDS: &[&str] = &[
    "setup",
    "auth",
    "--version",
    "-V",
    "--help",
    "-h",
    "workspace",
    "-w",
    "tip",
    "-t",
];

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().bold())
    .usage(AnsiColor::Yellow.on_default().bold())
    .literal(AnsiColor::Yellow.on_default().bold())
    .placeholder(AnsiColor::Yellow.on_default());

#[derive(Parser)]
#[command(name = "abrasive", disable_version_flag = true, disable_help_flag = true, trailing_var_arg = true, styles = STYLES)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Args to forward to cargo
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cargo_args: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize abrasive for this project
    Setup,
    /// Authenticate with the build server
    Auth,
    /// Print abrasive and cargo versions
    #[command(name = "--version", aliases = ["-V"])]
    Version,
    /// Get help for abrasive and cargo
    #[command(name = "--help", aliases = ["-h"])]
    Help,
    /// Print the workspace info
    #[command(name = "workspace", aliases = ["-w"])]
    Workspace,
    /// Vanity, print a fortune cookie like thing.
    /// I am just adding this as a dummy change to test the server
    /// auto reloading.
    #[command(name = "tip", aliases = ["-t"])]
    Tip,
}

/// Print the Abrasive help first, followed by the cargo help
fn print_help() {
    println!("ABRASIVE {}\n", env!("CARGO_PKG_VERSION"));
    let _ = Cli::command().color(clap::ColorChoice::Always).print_help();
    println!("\n");
    let _ = Cmd::new("cargo").arg("--help").status();
}

/// Print the Abrasive workspace info
fn print_workspace(ctx: &Option<WorkspaceContext>) -> CliResult<()> {
    match ctx {
        // todo impl display on workspace ctx
        Some(ctx) => println!("{:?}, {:?}", ctx.root_dir, ctx.subdir), 
        None => println!(
            "This is not an abrasive workspace. Abrasive commands run from here will pass through to cargo"
        ),
    }
    Ok(())
}

/// Vanity, print a tip from the server
fn print_tip() -> CliResult<()> {
    let token = auth::saved_token().ok_or(errors::AuthError::NoSavedToken)?;

    let mut stream = open_connection(&token)?;
    send_frame(&mut stream, &Message::TipRequest)?;

    match recv_frame(&mut stream)? {
        Message::Tip(the_tip) => {
            println!("{}", the_tip);
            Ok(())
        },
        other => {
            eprintln!("[tip] unexpected tip request response: {other:?}");
            Err(CliError::disconnected())?
        }
    }
}

/// Print the Abrasive help first, followed by the cargo help
fn print_version() {
    println!("abrasive {}", env!("CARGO_PKG_VERSION"));
    let _ = Cmd::new("cargo").arg("--version").status();
}

fn remote_setup(ctx: &Option<WorkspaceContext>) -> CliResult<()> {
    if ctx.is_some() {
        eprintln!("Setup failed, abrasive.toml already exists");
        return Ok(());
    }
    let cwd = env::current_dir().map_err(CliError::no_cwd)?;
    let scope = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| CliError::invalid_path(cwd.display().to_string()))?
        .to_string();
    let toml_path = cwd.join("abrasive.toml");
    let content = format!("[remote]\nhost = \"{IP}\"\nteam = \"public\"\nscope = \"{scope}\"\n");
    fs::write(&toml_path, &content)?;
    eprintln!("created abrasive.toml (team=public, scope={scope})");
    let ctx = WorkspaceContext::from_paths(&toml_path, &cwd)?;

    // this is a bit of a dumb hack, the reason we send this nop command to the remote
    // is that was just the easiest way in the moment to send a do nothing command to
    // the remote (which I want to do as a bit of a hack here to warm the remote. mostly
    // to sync the source)
    try_remote(&ctx, vec!["nop".to_string()])?;
    Ok(())
}

fn login() -> CliResult<()> {
    auth::paste_login()?;
    Ok(())
}

fn build_manifest(root: &Path) -> Vec<FileEntry> {
    let paths = walk_files(root);
    paths
        .par_iter()
        .filter_map(|p| {
            let rel = p.strip_prefix(root).ok()?.to_string_lossy().to_string();
            let data = fs::read(p).ok()?;
            let hash = *blake3::hash(&data).as_bytes();
            Some(FileEntry { path: rel, hash })
        })
        .collect()
}

fn walk_files(root: &Path) -> Vec<PathBuf> {
    WalkBuilder::new(root)
        .git_ignore(true)
        .git_exclude(true)
        .filter_entry(|e| e.file_name() != ".git")
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map_or(false, |ft| ft.is_file()))
        .map(|e| e.into_path())
        .collect()
}

/// Cheap "did anything change?" probe sent before the full manifest.
/// Hashes (relative path, mtime, size) for every file — no file
/// contents read. Daemon caches the last accepted fingerprint per slot
/// and short-circuits the manifest+sync flow on a match.
fn fingerprint(root: &Path) -> [u8; 32] {
    let mut entries: Vec<(String, u64, u64)> = walk_files(root)
        .into_iter()
        .filter_map(|p| stat_entry(&p, root))
        .collect();
    entries.sort();
    let mut hasher = blake3::Hasher::new();
    for (path, mtime, size) in entries {
        hasher.update(path.as_bytes());
        hasher.update(&mtime.to_le_bytes());
        hasher.update(&size.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn stat_entry(p: &Path, root: &Path) -> Option<(String, u64, u64)> {
    let rel = p.strip_prefix(root).ok()?.to_string_lossy().to_string();
    let meta = fs::metadata(p).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((rel, mtime, meta.len()))
}

enum Conn {
    Ws(tls::WsConn),
    Agent(UnixStream),
}

impl Conn {
    fn send_raw(&mut self, data: Vec<u8>) -> io::Result<()> {
        match self {
            Conn::Ws(ws) => ws
                .send(tungstenite::Message::Binary(data))
                .map_err(ws_to_io),
            Conn::Agent(s) => agent::write_msg(s, &data),
        }
    }

    fn recv_raw(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Conn::Ws(ws) => loop {
                match ws.read().map_err(ws_to_io)? {
                    tungstenite::Message::Binary(data) => break Ok(data),
                    tungstenite::Message::Close(_) => {
                        break Err(io::Error::new(io::ErrorKind::ConnectionReset, "closed"));
                    }
                    _ => continue,
                }
            },
            Conn::Agent(s) => agent::read_msg(s),
        }
    }
}

fn ws_to_io(e: tungstenite::Error) -> io::Error {
    match e {
        tungstenite::Error::Io(io) => io,
        other => io::Error::new(io::ErrorKind::Other, other.to_string()),
    }
}

fn send_frame(conn: &mut Conn, msg: &Message) -> CliResult<()> {
    conn.send_raw(abrasive_protocol::serialize(msg))?;
    Ok(())
}

fn recv_frame(conn: &mut Conn) -> CliResult<Message> {
    let data = conn.recv_raw()?;
    Ok(abrasive_protocol::deserialize(&data)?)
}

enum SyncOutcome {
    Ready(Vec<String>),
    SlotsBusy,
}

fn start_sync(stream: &mut Conn, root: &Path, team: &str, scope: &str) -> CliResult<SyncOutcome> {
    let manifest = build_and_log_manifest(root, team, scope);
    send_frame(stream, &Message::Manifest(manifest))?;
    match recv_frame(stream)? {
        Message::NeedFiles(paths) => Ok(SyncOutcome::Ready(paths)),
        Message::SlotsBusy => Ok(SyncOutcome::SlotsBusy),
        other => {
            eprintln!("[sync] unexpected message: {other:?}");
            Err(CliError::disconnected())
        }
    }
}

fn build_and_log_manifest(root: &Path, team: &str, scope: &str) -> Manifest {
    eprintln!("[sync] scanning files...");
    let files = build_manifest(root);
    let files_gz = Manifest::encode_files(&files);
    eprintln!(
        "[sync] manifest: {} entries, {} bytes gzipped",
        files.len(),
        files_gz.len()
    );
    Manifest {
        team: team.to_string(),
        scope: scope.to_string(),
        files_gz,
    }
}

fn stream_files(stream: &mut Conn, root: &Path, needed: Vec<String>) -> CliResult<()> {
    eprintln!("[sync] sending {} files", needed.len());
    let (tx, rx) = sync_channel::<(String, Vec<u8>)>(32);
    let root_buf = root.to_path_buf();
    let producer = thread::spawn(move || {
        needed.par_iter().for_each_with(tx, |tx, path| {
            if let Ok(contents) = fs::read(root_buf.join(path)) {
                let _ = tx.send((path.clone(), contents));
            }
        });
    });
    for (path, contents) in rx {
        send_frame(stream, &Message::FileData { path, contents })?;
    }
    let _ = producer.join();
    send_frame(stream, &Message::SyncDone)
}

fn wait_for_sync_ack(stream: &mut Conn) -> CliResult<()> {
    match recv_frame(stream)? {
        Message::SyncAck => {
            eprintln!("[sync] done");
            Ok(())
        }
        _ => Err(CliError::disconnected()),
    }
}

enum BuildOutcome {
    Done(ExitCode),
    SlotsBusy,
}

fn try_remote(ctx: &WorkspaceContext, cargo_args: Vec<String>) -> CliResult<ExitCode> {
    // Only whitelisted cargo commands run remotely; everything else
    // (e.g. `clean`, `update`, `add`) falls through to local cargo.
    if !should_go_remote(&cargo_args) {
        return forward_args_to_local();
    }
    let token = auth::saved_token().ok_or(errors::AuthError::NoSavedToken)?;
    poll_for_build(ctx, cargo_args, &token)
}

fn poll_for_build(
    ctx: &WorkspaceContext,
    cargo_args: Vec<String>,
    token: &str,
) -> CliResult<ExitCode> {
    loop {
        match attempt_build(ctx, &cargo_args, token)? {
            BuildOutcome::Done(code) => break Ok(code),
            BuildOutcome::SlotsBusy => {
                eprintln!("[abrasive] all build slots on the server are busy, retrying in 2s...");
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn attempt_build(
    ctx: &WorkspaceContext,
    cargo_args: &[String],
    token: &str,
) -> CliResult<BuildOutcome> {
    let mut stream = open_connection(token)?;
    let team = &ctx.config.remote.team;
    let scope = &ctx.config.remote.scope;
    match send_probe(&mut stream, ctx, cargo_args)? {
        ProbeResult::SlotsBusy => Ok(BuildOutcome::SlotsBusy),
        ProbeResult::Accepted => {
            eprintln!("[sync] fingerprint matched, skipping manifest");
            stream_build_output(&mut stream).map(BuildOutcome::Done)
        }
        ProbeResult::Miss => match start_sync(&mut stream, &ctx.root_dir, team, scope)? {
            SyncOutcome::SlotsBusy => Ok(BuildOutcome::SlotsBusy),
            SyncOutcome::Ready(needed) => {
                stream_files(&mut stream, &ctx.root_dir, needed)?;
                wait_for_sync_ack(&mut stream)?;
                stream_build_output(&mut stream).map(BuildOutcome::Done)
            }
        },
    }
}

enum ProbeResult {
    Accepted,
    Miss,
    SlotsBusy,
}

fn send_probe(
    stream: &mut Conn,
    ctx: &WorkspaceContext,
    cargo_args: &[String],
) -> CliResult<ProbeResult> {
    let fp = fingerprint(&ctx.root_dir);
    let request = BuildRequest {
        cargo_args: cargo_args.to_vec(),
        subdir: ctx.subdir.clone(),
        host_platform: host_triple(),
        team: ctx.config.remote.team.clone(),
        scope: ctx.config.remote.scope.clone(),
    };
    send_frame(
        stream,
        &Message::Probe {
            fingerprint: fp,
            request,
        },
    )?;
    match recv_frame(stream)? {
        Message::ProbeAccepted => Ok(ProbeResult::Accepted),
        Message::ProbeMiss => Ok(ProbeResult::Miss),
        Message::SlotsBusy => Ok(ProbeResult::SlotsBusy),
        other => {
            eprintln!("[sync] unexpected probe response: {other:?}");
            Err(CliError::disconnected())
        }
    }
}

fn open_connection(token: &str) -> CliResult<Conn> {
    if let Ok(stream) = UnixStream::connect(agent::socket_path()) {
        eprintln!("[conn] via agent");
        return Ok(Conn::Agent(stream));
    }
    eprintln!("[conn] via remote");
    let addr: SocketAddr = format!("{}:{}", IP, PORT).parse().unwrap();
    let tcp =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(CliError::connect)?;
    tcp.set_read_timeout(Some(Duration::from_secs(300)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
    Ok(Conn::Ws(
        tls::connect(tcp, token).map_err(CliError::connect)?,
    ))
}

fn resolve_agent_bin() -> Option<PathBuf> {
    if let Some(p) = env::var_os("ABRASIVE_AGENT_BIN") {
        return Some(PathBuf::from(p));
    }
    let exe = env::current_exe().ok()?;
    Some(exe.parent()?.join("abrasive-agent"))
}

/// This is sort of just a performance hack. The idea is we can avoid
/// the Websocket handshake time if we leave open the websocket in
/// another process, and next time we wanna talk to the remote we pipe
/// our message to that long lived process (here called abrasive-agent)
/// and it forwards the message to the remote. this speed does matter
/// for cache hits (since they are so fast 100ms-1s makes a big diff)
fn spawn_agent_for_next_time() {
    if UnixStream::connect(agent::socket_path()).is_ok() {
        return;
    }
    let Some(agent_bin) = resolve_agent_bin() else {
        return;
    };
    let Ok(child) = Cmd::new(agent_bin)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    std::mem::forget(child);
}

fn stream_build_output(stream: &mut Conn) -> CliResult<ExitCode> {
    loop {
        match recv_frame(stream)? {
            Message::BuildStdout(data) => {
                io::stderr().write_all(b"[REMOTE] ")?;
                io::stdout().write_all(&data)?;
            }
            Message::BuildStderr(data) => {
                io::stderr().write_all(b"[REMOTE] ")?;
                io::stderr().write_all(&data)?;
            }
            Message::BuildFinished { exit_code } => break Ok(ExitCode::from(exit_code)),
            _ => {}
        }
    }
}

#[derive(Deserialize)]
struct AbrasiveConfig {
    remote: RemoteConfig,
}

#[derive(Deserialize)]
struct RemoteConfig {
    #[allow(dead_code)]
    host: String,
    team: String,
    scope: String,
}

struct WorkspaceContext {
    root_dir: PathBuf,
    /// None if abrasive is called from the workspace root
    subdir: Option<String>,
    config: AbrasiveConfig,
}

impl WorkspaceContext {
    fn from_paths(config_path: &Path, called_from: &Path) -> CliResult<Self> {
        let root_dir = config_path
            .parent()
            .expect("abrasive.toml must have a parent directory")
            .to_path_buf();

        let subdir = relative_subdir(&root_dir, called_from)?;

        let config = fs::read_to_string(config_path).map_err(|_| CliError::no_toml())?;
        let config: AbrasiveConfig = toml::from_str(&config)?;

        Ok(Self {
            root_dir,
            subdir,
            config,
        })
    }
}

/// Helper function to get, for example, "c/d" from ("a/b", "a/b/c/d")
fn relative_subdir(project_root: &Path, called_from: &Path) -> CliResult<Option<String>> {
    let rel = match called_from.strip_prefix(project_root) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel,
        _ => return Ok(None),
    };
    let s = rel
        .to_str()
        .ok_or_else(|| CliError::invalid_path(rel.display().to_string()))?;
    Ok(Some(s.to_string()))
}

fn get_workspace() -> CliResult<Option<WorkspaceContext>> {
    let cwd = env::current_dir().map_err(CliError::no_cwd)?;
    match find_abrasive_toml(&cwd) {
        Some(config) => Ok(Some(WorkspaceContext::from_paths(&config, &cwd)?)),
        None => Ok(None),
    }
}

/// Walk up from start looking for abrasive.toml. Returns the full
/// path to abrasive.toml (including the "abrasive.toml" part)
fn find_abrasive_toml(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join("abrasive.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        // mutate dir into parent dir. If there is no parent dir
        // just return None.
        if !dir.pop() {
            return None;
        }
    }
}

fn forward_args_to_local() -> CliResult<ExitCode> {
    // Transparent on unix, probably close enough on windows
    let args: Vec<String> = env::args().skip(1).collect();
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Cmd::new("cargo").args(&args).exec();
        // only reaches here if exec failed
        Err(CliError::cargo_not_found(err))
    }

    #[cfg(not(unix))]
    {
        let status = Cmd::new("cargo")
            .args(&args)
            .status()
            .map_err(CliError::cargo_not_found)?;
        Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
    }
}

fn should_go_remote(args: &[String]) -> bool {
    args.first()
        .map_or(false, |cmd| REMOTE_COMMANDS.contains(&cmd.as_str()))
}

fn is_abrasive_command() -> bool {
    env::args()
        .nth(1)
        .map_or(true, |arg| ABRASIVE_COMMANDS.contains(&arg.as_str()))
}

fn dispatch_abrasive_command(
    command: Option<Command>,
    ctx: &Option<WorkspaceContext>,
) -> CliResult<ExitCode> {
    match command {
        None => print_help(),
        Some(thing) => match thing {
            Command::Setup => remote_setup(ctx)?,
            Command::Auth => login()?,
            Command::Version => print_version(),
            Command::Help => print_help(),
            Command::Workspace => print_workspace(ctx)?,
            Command::Tip => print_tip()?,
        },
    }
    Ok(ExitCode::SUCCESS)
}

fn run() -> CliResult<ExitCode> {
    spawn_agent_for_next_time();
    let ctx = get_workspace()?;

    if is_abrasive_command() {
        let cli = Cli::parse();
        return dispatch_abrasive_command(cli.command, &ctx);
    }

    // Make sure we are actually in an abrasive workspace
    let ctx = match ctx {
        None => return forward_args_to_local(),
        Some(ctx) => ctx,
    };

    let cli = Cli::parse();
    match cli.command {
        None => return try_remote(&ctx, cli.cargo_args),
        _ => unreachable!(), // note to self, consider factoring this out
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => e.exit(),
    }
}

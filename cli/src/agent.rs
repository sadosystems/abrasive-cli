use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub fn socket_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        PathBuf::from(dir).join("abrasive-agent.sock")
    } else {
        let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
        PathBuf::from(format!("/tmp/abrasive-agent-{user}.sock"))
    }
}

pub fn write_msg(stream: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    stream.write_all(&(data.len() as u32).to_be_bytes())?;
    stream.write_all(data)
}

pub fn read_msg(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Every CLI-to-agent connection starts with one of these. `StartProxy`
/// means "all subsequent bytes belong to a daemon session, forward them".
/// The other variants are agent-local RPC calls that never hit the wire.
#[derive(Debug, Serialize, Deserialize)]
pub enum AgentRequest {
    StartProxy,
    GetLastSync { scope: String },
    SetLastSync { scope: String, state: LastSyncState },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AgentResponse {
    Ok,
    LastSync(Option<LastSyncState>),
}

/// What the agent remembers about the last successful sync for a given
/// scope — enough for the next build to compute a precise diff of files
/// that probably need re-syncing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastSyncState {
    pub fingerprint: [u8; 32],
    pub files: HashMap<String, [u8; 32]>,
}

pub fn send_request(stream: &mut UnixStream, req: &AgentRequest) -> io::Result<()> {
    let bytes = bincode::serialize(req).map_err(io_from_bincode)?;
    write_msg(stream, &bytes)
}

pub fn recv_request(stream: &mut UnixStream) -> io::Result<AgentRequest> {
    let bytes = read_msg(stream)?;
    bincode::deserialize(&bytes).map_err(io_from_bincode)
}

pub fn send_response(stream: &mut UnixStream, resp: &AgentResponse) -> io::Result<()> {
    let bytes = bincode::serialize(resp).map_err(io_from_bincode)?;
    write_msg(stream, &bytes)
}

pub fn recv_response(stream: &mut UnixStream) -> io::Result<AgentResponse> {
    let bytes = read_msg(stream)?;
    bincode::deserialize(&bytes).map_err(io_from_bincode)
}

fn io_from_bincode(e: Box<bincode::ErrorKind>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

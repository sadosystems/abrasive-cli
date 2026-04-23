use abrasive::{agent, auth, tags, tls};
use abrasive_protocol::Message;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;
use std::{fs, process};
use tungstenite::Message as WsMessage;

const IP: &str = "157.180.55.180";
const PORT: u16 = 8400;

fn main() {
    let token = auth::saved_token().unwrap_or_else(|| {
        eprintln!("run `abrasive auth` first");
        process::exit(1);
    });
    let path = agent::socket_path();
    let _ = fs::remove_file(&path);
    let mut ws: Option<tls::WsConn> = match connect(&token) {
        Ok(conn) => {
            eprintln!("{} connected to daemon", tags::LOCAL);
            Some(conn)
        }
        Err(e) => {
            eprintln!("{} initial connection failed: {e}", tags::LOCAL);
            None
        }
    };
    let listener = UnixListener::bind(&path).expect("failed to bind agent socket");
    eprintln!("{} listening on {}", tags::LOCAL, path.display());
    for client in listener.incoming().flatten() {
        if let Err(e) = handle(client, &token, &mut ws) {
            eprintln!("{} session error: {e}", tags::LOCAL);
            ws = None;
        }
    }
}

fn handle(mut client: UnixStream, token: &str, ws: &mut Option<tls::WsConn>) -> io::Result<()> {
    if ws.is_none() {
        *ws = Some(connect(token)?);
        eprintln!("{} connected to daemon", tags::LOCAL);
    }
    proxy(&mut client, ws.as_mut().unwrap())
}

fn connect(token: &str) -> io::Result<tls::WsConn> {
    let addr: SocketAddr = format!("{IP}:{PORT}").parse().unwrap();
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    tcp.set_read_timeout(Some(Duration::from_secs(300)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
    tls::connect(tcp, token)
}

fn proxy(client: &mut UnixStream, ws: &mut tls::WsConn) -> io::Result<()> {
    let mut session_started = false;
    loop {
        // Client → WS: forward until we need a daemon response
        loop {
            let data = match agent::read_msg(client) {
                Ok(data) => data,
                // A client that hangs up before sending anything is a probe
                // (e.g. from CLI's `spawn_agent_for_next_time`). The ws is
                // still clean — just end this no-op session. But once we've
                // forwarded anything, a client EOF leaves the daemon mid-
                // protocol and the ws MUST be torn down to unblock it.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && !session_started => {
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            ws.send(WsMessage::Binary(data.clone())).map_err(ws_to_io)?;
            session_started = true;
            if decode(&data)?.ends_client_turn() {
                break;
            }
        }
        // WS → Client: forward until client needs to send again or session ends.
        loop {
            let data = read_ws_binary(ws)?;
            agent::write_msg(client, &data)?;
            let msg = decode(&data)?;
            if msg.ends_session() {
                return Ok(());
            }
            if msg.yields_to_client() {
                break;
            }
        }
    }
}

fn read_ws_binary(ws: &mut tls::WsConn) -> io::Result<Vec<u8>> {
    loop {
        match ws.read().map_err(ws_to_io)? {
            WsMessage::Binary(data) => break Ok(data),
            WsMessage::Close(_) => {
                break Err(io::Error::new(io::ErrorKind::ConnectionReset, "ws closed"));
            }
            _ => continue,
        }
    }
}

fn ws_to_io(e: tungstenite::Error) -> io::Error {
    match e {
        tungstenite::Error::Io(io) => io,
        other => io::Error::new(io::ErrorKind::Other, other.to_string()),
    }
}

fn decode(data: &[u8]) -> io::Result<Message> {
    abrasive_protocol::deserialize(data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

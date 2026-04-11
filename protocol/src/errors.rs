#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct DecodeError(pub(crate) Box<bincode::ErrorKind>);

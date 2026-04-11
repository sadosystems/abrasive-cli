use abrasive_protocol::{Abi, Arch, Os, PlatformTriple};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("unsupported architecture");

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
compile_error!("unsupported OS");

#[cfg(not(any(
    target_env = "gnu",
    target_env = "musl",
    target_env = "msvc",
    target_os = "macos"
)))]
compile_error!("unsupported ABI");

pub fn host_triple() -> PlatformTriple {
    let arch = if cfg!(target_arch = "x86_64") {
        Arch::X86_64
    } else if cfg!(target_arch = "aarch64") {
        Arch::Aarch64
    } else {
        unreachable!()
    };

    let os = if cfg!(target_os = "windows") {
        Os::Windows
    } else if cfg!(target_os = "linux") {
        Os::Linux
    } else if cfg!(target_os = "macos") {
        Os::Mac
    } else {
        unreachable!()
    };

    let abi = if cfg!(target_env = "gnu") {
        Abi::Gnu
    } else if cfg!(target_env = "musl") {
        Abi::Musl
    } else if cfg!(target_env = "msvc") {
        Abi::Msvc
    } else if cfg!(target_os = "macos") {
        Abi::Gnu
    } else {
        unreachable!()
    };

    PlatformTriple { arch, os, abi }
}

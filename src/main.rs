use std::convert::TryInto;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule
};

use reqwest::tls::Version;
use std::io::prelude::*;

use structopt::StructOpt;
use eyre::WrapErr;
use eyre::ErrReport;
use std::io::BufWriter;


#[derive(Debug, StructOpt)]
struct Config {
    /// The fully qualified URL with an https scheme to download from
    #[structopt(short, long, env)]
    from: reqwest::Url,
    /// The file system path, including a file name, for where to write the file to
    #[structopt(short, long, env)]
    to: std::path::PathBuf,
    /// Minimum tls version, one of `v1.2` or `v1.3`
    #[structopt(long, env, default_value = "v1.2", parse(try_from_str = min_tls_version))]
    min_tls: Version,
    /// Maximum number of bytes to write to disk before aborting
    #[structopt(long, env, default_value = "1GB", parse(try_from_str = bytefmt::parse))]
    max_size: u64,
    /// [UNSAFE] Indicates that you want to run without the default sandbox
    #[structopt(long)]
    no_sandbox: bool,
}

fn min_tls_version(tls_version: &str) -> Result<Version, ErrReport> {
   match tls_version {
        "v1.2" => Ok(Version::TLS_1_2),
        "v1.3" => Ok(Version::TLS_1_3),
        invalid => eyre::bail!("Minimum TLS version must be `v1.2` or `v1.3`, not {}", invalid),
   }
}

static APP_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
);


// Sandboxing for linux only
#[cfg(not(target_os = "linux"))]
fn sandbox() -> Result<(), ErrReport> {
  Ok(())
}

// todo: socketpair AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK
// mprotect - no exec
#[cfg(target_os = "linux")]
fn sandbox() -> Result<(), ErrReport> {
let filter: BpfProgram = SeccompFilter::new(
    vec![
        (libc::SYS_accept4, vec![]),
	
(libc::SYS_fsopen, vec![]),
(libc::SYS_fspick, vec![]),
(libc::SYS_fstat, vec![]),
(libc::SYS_fstatfs, vec![]),
(libc::SYS_fsync, vec![]),
(libc::SYS_futex, vec![]),
(libc::SYS_openat, vec![]),
(libc::SYS_statx, vec![]),
(libc::SYS_lseek, vec![]),
(libc::SYS_read, vec![]),
(libc::SYS_close, vec![]),
(libc::SYS_brk, vec![]),
(libc::SYS_write, vec![]),
(libc::SYS_getrandom, vec![]),
(libc::SYS_socket, vec![]),
(libc::SYS_bind, vec![]),
(libc::SYS_epoll_ctl, vec![]),
(libc::SYS_sendto, vec![]),
(libc::SYS_recvfrom, vec![]),
(libc::SYS_fcntl, vec![]),
(libc::SYS_socket, vec![]),
(libc::SYS_connect, vec![]),
(libc::SYS_getsockopt, vec![]),
(libc::SYS_setsockopt, vec![]),
(libc::SYS_writev, vec![]),
(libc::SYS_getpeername, vec![]),
(libc::SYS_sched_yield, vec![]),
(libc::SYS_sigaltstack, vec![]),
(libc::SYS_munmap, vec![]),
(libc::SYS_exit_group, vec![]),

    ]
    .into_iter()
    .collect(),
    SeccompAction::KillProcess,
    SeccompAction::Allow,
    std::env::consts::ARCH.try_into().unwrap(),
).unwrap().try_into().unwrap();
seccompiler::apply_filter(&filter).unwrap();

  Ok(())
}

#[tracing::instrument]
#[tokio::main]
async fn main() -> Result<(), ErrReport> {
    color_eyre::install()?;
    tracing_subscriber::fmt::init();

    let config = Config::from_args();
    tracing::debug!(config=?config);
    let url = config.from;

    if config.to.is_dir() {
        eyre::bail!("Argument 'to' must specify a path for dlfile to write out to");
    }

    // TODO: Validate that the path is either absolute
    //	     or that it contains no `../`
    let mut output_file = BufWriter::new(std::fs::File::create(&config.to)
	.wrap_err("Could not open file")?);

    if url.scheme() != "https" {
        eyre::bail!("dlfile only downloads files via https. Scheme was: {}", url.scheme());
    }

    if !config.no_sandbox {
        sandbox()?;
    }

    let client = reqwest::Client::builder()
        .user_agent(APP_USER_AGENT)
        .gzip(true)
        .no_brotli()
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(3))
	.min_tls_version(config.min_tls)
        .use_rustls_tls()
	.https_only(true)
	.build()
        .wrap_err("Invalid configuration for client - this is a bug!")?;

    let mut response = client.get(url).send().await
	.wrap_err("Client failed to `get` url")?;

    tracing::debug!(
	message="response", 
	response=?response
    );

    let mut current_byte_count = 0;
    while let Some(chunk) = response.chunk().await? {
        current_byte_count += chunk.len() as u64;
        if current_byte_count >= config.max_size {
            eyre::bail!("Attempted to write too many bytes. Max: {} , Attempted: {}", config.max_size, current_byte_count);
        }
	output_file.write(&chunk).wrap_err("Could not write chunk to disk")?;	
    }

    output_file.flush().wrap_err("Failed to flush")?;

    Ok(())
}

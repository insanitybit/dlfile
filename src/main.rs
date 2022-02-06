mod sandbox;

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
        sandbox::sandbox()?;
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

    // Drop more privileges
    if !config.no_sandbox {
        sandbox::sandbox2()?;
    }

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

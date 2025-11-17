//! Live validation smoke tests that exercise the database validators against
//! real MySQL and Postgres instances provisioned with `testcontainers`.
//!
//! These are ignored by default because they require Docker. Run them with:
//! `cargo test --test live_db_validation -- --ignored`.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use kingfisher::validation::{validate_mysql, validate_postgres};
use testcontainers::{clients::Cli, core::WaitFor, GenericImage};
use tokio::{net::TcpStream, time::sleep};

const HOST_ALIAS: &str = "kingfisherlocal";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(250);

async fn wait_for_port(host: &str, port: u16) -> Result<()> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut last_err = None;

    loop {
        match TcpStream::connect((host, port)).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(err) => {
                last_err = Some(err);
                if Instant::now() >= deadline {
                    return Err(anyhow!(
                        "timed out after {:?} waiting for {host}:{port}: {last_err:?}",
                        STARTUP_TIMEOUT,
                    ));
                }
                sleep(STARTUP_POLL_INTERVAL).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn validates_mysql_secret_against_testcontainer() -> Result<()> {
    let docker = Cli::default();
    let image = GenericImage::new("mysql", "8.4")
        .with_env_var("MYSQL_ROOT_PASSWORD", "secret")
        .with_env_var("MYSQL_DATABASE", "app")
        .with_env_var("MYSQL_ROOT_HOST", "%")
        .with_wait_for(WaitFor::message_on_stdout("MySQL init process done. Ready for start up."));

    let container = docker.run(image);
    let port = container.get_host_port_ipv4(3306);

    wait_for_port(HOST_ALIAS, port).await?;

    let uri = format!("mysql://root:secret@{HOST_ALIAS}:{port}/app");
    let (is_valid, metadata) = validate_mysql(&uri).await?;

    assert!(is_valid, "expected MySQL validation to succeed, got {metadata:?}");
    assert!(
        metadata.iter().any(|entry| entry.contains("user=root")),
        "expected user metadata in {metadata:?}"
    );
    assert!(
        metadata.iter().any(|entry| entry.contains("database=app")),
        "expected database metadata in {metadata:?}"
    );

    drop(container);
    drop(docker);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn validates_postgres_secret_against_testcontainer() -> Result<()> {
    let docker = Cli::default();
    let image = GenericImage::new("postgres", "15")
        .with_env_var("POSTGRES_PASSWORD", "secret")
        .with_wait_for(WaitFor::message_on_stdout(
            "database system is ready to accept connections",
        ));
    let container = docker.run(image);
    let port = container.get_host_port_ipv4(5432);

    wait_for_port(HOST_ALIAS, port).await?;

    let uri = format!("postgres://postgres:secret@{HOST_ALIAS}:{port}/postgres");
    let (is_valid, metadata) = validate_postgres(&uri).await?;

    assert!(is_valid, "expected Postgres validation to succeed");
    assert!(metadata.is_empty(), "expected no metadata but found {metadata:?}");

    drop(container);
    drop(docker);
    Ok(())
}

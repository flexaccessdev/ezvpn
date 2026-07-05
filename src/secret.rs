//! Secret key generation and management commands (iroh).

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use iroh::SecretKey;
use log::info;
use std::path::PathBuf;

use crate::transport::endpoint::{load_secret, secret_to_endpoint_id};

/// JSON output for `generate-server-key` and `show-server-id`. Exactly one of
/// `path` (key written to a file) and `secret_key` (key requested on stdout via
/// `--output -`) is set for keygen; both are `None` for `show-server-id`.
#[derive(serde::Serialize)]
struct KeygenReport {
    endpoint_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_key: Option<String>,
}

fn print_report(report: &KeygenReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

/// Write the secret key material to `output`, owner-only (`0600` on Unix).
fn write_secret_file(output: &PathBuf, secret_content: &str, force: bool) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "File already exists: {}. Use --force to overwrite.",
            output.display()
        );
    }

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).context("Failed to create parent directory")?;
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut options = std::fs::OpenOptions::new();
        options.write(true).mode(0o600);
        if force {
            // Overwrite an existing file in place.
            options.create(true).truncate(true);
        } else {
            // Atomically refuse to overwrite, closing the TOCTOU window between
            // the `output.exists()` check above and this open.
            options.create_new(true);
        }
        let mut file = options
            .open(output)
            .context("Failed to open secret key file")?;

        // `.mode(0o600)` only takes effect when the file is created; on a
        // force-overwrite of a pre-existing file its old permissions persist,
        // so tighten the open descriptor explicitly before writing the secret.
        if force {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .context("Failed to set secret key file permissions")?;
        }

        file.write_all(secret_content.as_bytes())
            .context("Failed to write secret key file")?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(output, secret_content).context("Failed to write secret key file")?;
    }

    Ok(())
}

/// Generate a new secret key file (base64 encoded) and output the EndpointId
/// to stdout. With `--output -` the key itself goes to stdout instead of a
/// file; with `json`, everything is folded into one JSON document.
pub fn generate_secret(output: PathBuf, force: bool, json: bool) -> Result<()> {
    let secret = SecretKey::generate();
    let secret_base64 = BASE64.encode(secret.to_bytes());
    let endpoint_id = secret_to_endpoint_id(&secret);

    if output.as_os_str() == std::ffi::OsStr::new("-") {
        if json {
            return print_report(&KeygenReport {
                endpoint_id: endpoint_id.to_string(),
                path: None,
                secret_key: Some(secret_base64),
            });
        }
        println!("{}", secret_base64);
        eprintln!("EndpointId: {}", endpoint_id);
        return Ok(());
    }

    write_secret_file(&output, &secret_base64, force)?;
    info!("Secret key saved to: {}", output.display());
    if json {
        return print_report(&KeygenReport {
            endpoint_id: endpoint_id.to_string(),
            path: Some(output.display().to_string()),
            secret_key: None,
        });
    }
    println!("EndpointId: {}", endpoint_id);
    Ok(())
}

/// Show the EndpointId for an existing secret key file
pub fn show_id(secret_file: PathBuf, json: bool) -> Result<()> {
    let secret = load_secret(&secret_file)?;
    let endpoint_id = secret_to_endpoint_id(&secret);
    if json {
        return print_report(&KeygenReport {
            endpoint_id: endpoint_id.to_string(),
            path: None,
            secret_key: None,
        });
    }
    println!("{}", endpoint_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_report_file_mode_omits_secret_key() {
        let json = serde_json::to_string(&KeygenReport {
            endpoint_id: "abc".into(),
            path: Some("/tmp/key".into()),
            secret_key: None,
        })
        .unwrap();
        assert_eq!(json, r#"{"endpoint_id":"abc","path":"/tmp/key"}"#);
    }

    #[test]
    fn keygen_report_stdout_mode_omits_path() {
        let json = serde_json::to_string(&KeygenReport {
            endpoint_id: "abc".into(),
            path: None,
            secret_key: Some("s3cret".into()),
        })
        .unwrap();
        assert_eq!(json, r#"{"endpoint_id":"abc","secret_key":"s3cret"}"#);
    }

    #[test]
    fn keygen_report_show_id_has_only_endpoint_id() {
        let json = serde_json::to_string(&KeygenReport {
            endpoint_id: "abc".into(),
            path: None,
            secret_key: None,
        })
        .unwrap();
        assert_eq!(json, r#"{"endpoint_id":"abc"}"#);
    }
}

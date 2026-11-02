//! Ephemeral private material. Never serialize it to test output or reports.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{fs, io::Write, path::PathBuf};
use uuid::Uuid;

pub(super) struct TestKeys {
    directory: PathBuf,
    pub(super) path: PathBuf,
    materials: Vec<Value>,
}

impl TestKeys {
    pub(super) fn new() -> Result<Self> {
        let directory =
            std::env::temp_dir().join(format!("identity-phase23-keyset-{}", Uuid::now_v7()));
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        builder.create(&directory)?;
        let mut value = Self {
            path: directory.join("keys.json"),
            directory,
            materials: Vec::new(),
        };
        for kid in ["phase23-a", "phase23-b", "phase23-c"] {
            let generated = crate::test_support::KeyFixture::new()?;
            let source: Value = serde_json::from_slice(&fs::read(&generated.keyset)?)?;
            let mut material = source["keys"][0].clone();
            ensure!(material.is_object(), "generated key fixture invalid");
            material["kid"] = json!(kid);
            value.materials.push(material);
            let generated_directory = generated
                .keyset
                .parent()
                .context("generated key directory")?
                .to_owned();
            drop(generated);
            ensure!(
                !generated_directory.exists(),
                "generated temporary private material remained"
            );
        }
        value.write("keys.json", &json!({"keys":value.materials}))?;
        Ok(value)
    }

    pub(super) fn material(&self, index: usize) -> Value {
        self.materials[index].clone()
    }

    pub(super) fn write(&self, filename: &str, value: &Value) -> Result<PathBuf> {
        self.write_bytes(filename, &serde_json::to_vec(value)?)
    }

    pub(super) fn write_bytes(&self, filename: &str, value: &[u8]) -> Result<PathBuf> {
        ensure!(
            !filename.is_empty()
                && filename
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.')),
            "unsafe key fixture filename"
        );
        let path = self.directory.join(filename);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path)?.write_all(value)?;
        Ok(path)
    }

    pub(super) fn path_text(&self) -> Result<&str> {
        self.path.to_str().context("key fixture path must be UTF-8")
    }

    pub(super) fn cleanup(&self) -> Result<()> {
        if !self.directory.exists() {
            return Ok(());
        }
        let temporary = std::env::temp_dir().canonicalize()?;
        let resolved = self.directory.canonicalize()?;
        ensure!(
            resolved.parent() == Some(temporary.as_path())
                && self
                    .directory
                    .file_name()
                    .and_then(|v| v.to_str())
                    .is_some_and(|v| v.starts_with("identity-phase23-keyset-")),
            "refusing key cleanup outside owned temporary directory"
        );
        fs::remove_dir_all(&resolved)?;
        ensure!(
            !resolved.exists(),
            "temporary private key directory remained"
        );
        Ok(())
    }
}

impl Drop for TestKeys {
    fn drop(&mut self) {
        let temporary = std::env::temp_dir();
        if self.directory.parent() == Some(temporary.as_path())
            && self
                .directory
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("identity-phase23-keyset-"))
            && self
                .directory
                .canonicalize()
                .ok()
                .is_some_and(|v| v.parent() == temporary.canonicalize().ok().as_deref())
        {
            let _ = self.cleanup();
        }
    }
}

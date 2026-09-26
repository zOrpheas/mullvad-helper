//! Command execution abstraction (mockable in tests).
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

#[derive(Debug, Clone)]
pub struct CommandCall {
    pub program: String,
    pub args: Vec<String>,
}

#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync + std::fmt::Debug {
    async fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput>;
}

/// Real runner using tokio::process.
#[derive(Debug, Default)]
pub struct SystemRunner;

#[async_trait::async_trait]
impl CommandRunner for SystemRunner {
    async fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
        let out = tokio::process::Command::new(program)
            .args(args)
            .output()
            .await?;
        Ok(CommandOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }
}

/// Mock runner for tests.
#[derive(Debug, Default, Clone)]
pub struct MockRunner {
    outputs: Arc<Mutex<HashMap<String, CommandOutput>>>,
    pub calls: Arc<Mutex<Vec<CommandCall>>>,
}

impl MockRunner {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn stub(&self, program: &str, args: &[&str], output: CommandOutput) {
        let key = Self::key(program, args);
        self.outputs.lock().unwrap().insert(key, output);
    }
    fn key(program: &str, args: &[&str]) -> String {
        format!("{program}\0{}", args.join("\0"))
    }
    pub fn recorded(&self) -> Vec<CommandCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl CommandRunner for MockRunner {
    async fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
        self.calls.lock().unwrap().push(CommandCall {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });
        let key = Self::key(program, args);
        if let Some(o) = self.outputs.lock().unwrap().get(&key) {
            return Ok(o.clone());
        }
        // Prefix match: allow stubbing "wg show" regardless of extra args.
        Ok(CommandOutput {
            status: 1,
            stdout: String::new(),
            stderr: format!("mock: no stub for {program} {args:?}"),
        })
    }
}

pub fn ok(stdout: &str) -> CommandOutput {
    CommandOutput {
        status: 0,
        stdout: stdout.to_string(),
        stderr: String::new(),
    }
}

pub fn fail(status: i32, stderr: &str) -> CommandOutput {
    CommandOutput {
        status,
        stdout: String::new(),
        stderr: stderr.to_string(),
    }
}

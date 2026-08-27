//! MCP server discovery: parse the common `mcpServers` config shape (the
//! same shape Claude Desktop's `claude_desktop_config.json` and a
//! project's `.mcp.json` both use), then attempt live tool enumeration by
//! actually spawning each configured server and speaking MCP's JSON-RPC
//! over stdio -- not just trusting what the config file claims a server
//! exposes.

use serde::Serialize;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct McpServerConfig {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    /// Env var *names* only -- never values, so secrets never end up in a
    /// discovery report or the graph.
    pub env_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ToolDiscoveryResult {
    Tools(Vec<String>),
    /// A server that failed to start or didn't answer in time. Kept
    /// distinct from `Tools(vec![])` -- a config/startup problem is not
    /// evidence that a server has no tools.
    Unavailable(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredMcpServer {
    pub config: McpServerConfig,
    pub tools: ToolDiscoveryResult,
}

/// Parse an `mcpServers`-shaped config file: an object mapping server name
/// to `{command, args, env}`.
pub fn parse_mcp_config(text: &str) -> Result<Vec<McpServerConfig>, String> {
    let root: Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    let servers = root
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "config has no 'mcpServers' object".to_string())?;

    let mut configs: Vec<McpServerConfig> = servers
        .iter()
        .map(|(name, spec)| McpServerConfig {
            name: name.clone(),
            command: spec
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            args: spec
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            env_keys: spec
                .get("env")
                .and_then(|v| v.as_object())
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default(),
        })
        .collect();
    configs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(configs)
}

/// Discover every configured server's real, current tool list by spawning
/// it and running it through this function.
pub fn discover_all(configs: &[McpServerConfig], timeout: Duration) -> Vec<DiscoveredMcpServer> {
    configs
        .iter()
        .map(|config| DiscoveredMcpServer {
            config: config.clone(),
            tools: discover_tools(config, timeout),
        })
        .collect()
}

/// Spawn a configured MCP server over stdio and ask it for its tool list
/// via the real MCP JSON-RPC handshake (`initialize` then `tools/list`).
/// Best-effort with a hard timeout: a server that fails to start or hangs
/// is reported as `Unavailable`, never silently treated as zero tools.
pub fn discover_tools(config: &McpServerConfig, timeout: Duration) -> ToolDiscoveryResult {
    match discover_tools_inner(config, timeout) {
        Ok(tools) => ToolDiscoveryResult::Tools(tools),
        Err(reason) => ToolDiscoveryResult::Unavailable(reason),
    }
}

fn discover_tools_inner(
    config: &McpServerConfig,
    timeout: Duration,
) -> Result<Vec<String>, String> {
    if config.command.is_empty() {
        return Err("no command configured".to_string());
    }

    let mut child = Command::new(&config.command)
        .args(&config.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn '{}': {e}", config.command))?;

    let mut stdin = child.stdin.take().ok_or("failed to open server stdin")?;
    let stdout = child.stdout.take().ok_or("failed to open server stdout")?;
    let mut reader = BufReader::new(stdout);

    // std::io has no async cancellation, so the actual protocol exchange
    // runs on a helper thread with a hard channel timeout -- a hung server
    // must not hang discovery.
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let result = run_handshake(&mut stdin, &mut reader);
        let _ = tx.send(result);
    });

    let result = rx
        .recv_timeout(timeout)
        .unwrap_or_else(|_| Err("timed out waiting for server response".to_string()));

    let _ = child.kill();
    let _ = child.wait();
    let _ = handle.join();

    result
}

fn run_handshake(stdin: &mut impl Write, reader: &mut impl BufRead) -> Result<Vec<String>, String> {
    send_message(
        stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pyapicheck", "version": env!("CARGO_PKG_VERSION")},
            }
        }),
    )?;
    let _init_response = read_message(reader)?;

    send_message(
        stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )?;
    send_message(
        stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )?;
    let response = read_message(reader)?;

    if let Some(error) = response.get("error") {
        return Err(format!("server returned an error for tools/list: {error}"));
    }

    let tools = response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .ok_or("response had no result.tools array")?;

    Ok(tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect())
}

fn send_message(stdin: &mut impl Write, value: &Value) -> Result<(), String> {
    let line = serde_json::to_string(value).map_err(|e| e.to_string())?;
    writeln!(stdin, "{line}").map_err(|e| format!("failed to write to server stdin: {e}"))?;
    stdin
        .flush()
        .map_err(|e| format!("failed to flush server stdin: {e}"))
}

fn read_message(reader: &mut impl BufRead) -> Result<Value, String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("failed to read from server stdout: {e}"))?;
    if line.trim().is_empty() {
        return Err("server closed the connection without responding".to_string());
    }
    serde_json::from_str(&line).map_err(|e| format!("invalid JSON-RPC response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_mcp_servers_config_and_keeps_only_env_key_names() {
        let text = r#"{
            "mcpServers": {
                "refunds": {
                    "command": "python3",
                    "args": ["server.py"],
                    "env": {"API_KEY": "super-secret-value"}
                }
            }
        }"#;
        let configs = parse_mcp_config(text).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "refunds");
        assert_eq!(configs[0].command, "python3");
        assert_eq!(configs[0].env_keys, vec!["API_KEY".to_string()]);
    }

    #[test]
    fn rejects_config_with_no_mcp_servers_key() {
        assert!(parse_mcp_config(r#"{"foo": "bar"}"#).is_err());
    }

    #[test]
    fn live_discovery_against_fixture_server_returns_real_tools() {
        let fixture_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fixture_mcp_server.py");
        let config = McpServerConfig {
            name: "fixture".to_string(),
            command: "python3".to_string(),
            args: vec![fixture_path.display().to_string()],
            env_keys: vec![],
        };

        match discover_tools(&config, Duration::from_secs(10)) {
            ToolDiscoveryResult::Tools(tools) => {
                assert!(tools.contains(&"list_refunds".to_string()));
                assert!(tools.contains(&"process_refund".to_string()));
            }
            ToolDiscoveryResult::Unavailable(reason) => {
                panic!("expected real tools from the fixture server, got: {reason}")
            }
        }
    }

    #[test]
    fn missing_command_is_reported_unavailable_not_silently_empty() {
        let config = McpServerConfig {
            name: "broken".to_string(),
            command: "this-command-does-not-exist-xyz".to_string(),
            args: vec![],
            env_keys: vec![],
        };
        let result = discover_tools(&config, Duration::from_secs(3));
        assert!(matches!(result, ToolDiscoveryResult::Unavailable(_)));
    }
}

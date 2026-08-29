use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Discover an API inventory from an OpenAPI spec file on disk.
/// Returns the inventory serialized as a JSON string; the Python side
/// deserializes it rather than paying for a full PyO3 type conversion.
#[pyfunction]
#[allow(clippy::useless_conversion)] // `?` desugars through `From<PyErr> for PyErr`; pyo3 error-conversion pattern
fn discover(path: String) -> PyResult<String> {
    let inventory = pyapicheck_core::discover_from_file(std::path::Path::new(&path))
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&inventory).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Compute the remediation plan (fixes + fully patched spec text) for the
/// OpenAPI spec file on disk. Returns it serialized as a JSON string with
/// `fixes` and `patched_spec_text` fields; this does not write anything to
/// disk itself -- the Python CLI decides whether/where to write
/// `patched_spec_text` when `--apply` is passed.
#[pyfunction]
#[allow(clippy::useless_conversion)]
fn remediate(path: String) -> PyResult<String> {
    let plan = pyapicheck_core::remediate_from_file(std::path::Path::new(&path))
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&plan).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Recursively discover every OpenAPI/Swagger spec under a directory.
/// Returns a JSON array of inventories (one per matched spec file, possibly
/// empty).
#[pyfunction]
#[allow(clippy::useless_conversion)]
fn discover_directory(path: String) -> PyResult<String> {
    let inventories = pyapicheck_core::discover_from_directory(std::path::Path::new(&path))
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&inventories).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Discover two spec files and diff the resulting inventories. Returns the
/// `DriftReport` (added/removed/changed endpoints) serialized as JSON.
#[pyfunction]
#[allow(clippy::useless_conversion)]
fn diff(old_path: String, new_path: String) -> PyResult<String> {
    let report = pyapicheck_core::diff_files(
        std::path::Path::new(&old_path),
        std::path::Path::new(&new_path),
    )
    .map_err(PyValueError::new_err)?;
    serde_json::to_string(&report).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Discover a spec file and cross-reference it against a gateway access
/// log. Returns `{"inventory": ..., "lifecycle": ...}` serialized as JSON.
#[pyfunction]
#[allow(clippy::useless_conversion)]
fn report(spec_path: String, access_log_path: String) -> PyResult<String> {
    let result = pyapicheck_core::report_from_files(
        std::path::Path::new(&spec_path),
        std::path::Path::new(&access_log_path),
    )
    .map_err(PyValueError::new_err)?;
    serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Discover `spec_path`, then compute per-identity baselines, BOLA-shaped
/// sequential-ID findings, and first-time-observed-operation findings from
/// two traffic snapshots. Returns
/// `{"baselines": [...], "bola_findings": [...], "first_time_operations": [...]}`
/// as JSON.
#[pyfunction]
#[pyo3(signature = (spec_path, historical_log_path, current_log_path, known_agents=vec![]))]
#[allow(clippy::useless_conversion)]
fn baseline(
    spec_path: String,
    historical_log_path: String,
    current_log_path: String,
    known_agents: Vec<String>,
) -> PyResult<String> {
    let known_agents: std::collections::HashSet<String> = known_agents.into_iter().collect();
    let result = pyapicheck_core::baseline_from_files(
        std::path::Path::new(&spec_path),
        std::path::Path::new(&historical_log_path),
        std::path::Path::new(&current_log_path),
        &known_agents,
    )
    .map_err(PyValueError::new_err)?;
    serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Parse and validate a Cedar policy file. Returns a JSON array of
/// `{"id", "effect", "annotations"}` on success (real Cedar syntax
/// validation, not a heuristic check).
#[pyfunction]
#[allow(clippy::useless_conversion)]
fn policies_validate(policy_path: String) -> PyResult<String> {
    let policy_set = pyapicheck_core::validate_policy_file(std::path::Path::new(&policy_path))
        .map_err(PyValueError::new_err)?;
    let summary = pyapicheck_core::policy::summarize_policy_set(&policy_set);
    serde_json::to_string(&summary).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Run Phase 4's baseline detectors over `spec_path`/the two traffic logs
/// and generate Cedar policy recommendations from the findings. Returns a
/// JSON array of `{"policy_text", "effect_hint", "reason"}`.
#[pyfunction]
#[pyo3(signature = (spec_path, historical_log_path, current_log_path, known_agents=vec![]))]
#[allow(clippy::useless_conversion)]
fn policies_recommend(
    spec_path: String,
    historical_log_path: String,
    current_log_path: String,
    known_agents: Vec<String>,
) -> PyResult<String> {
    let known_agents: std::collections::HashSet<String> = known_agents.into_iter().collect();
    let recommendations = pyapicheck_core::policy_recommendations_from_files(
        std::path::Path::new(&spec_path),
        std::path::Path::new(&historical_log_path),
        std::path::Path::new(&current_log_path),
        &known_agents,
    )
    .map_err(PyValueError::new_err)?;
    serde_json::to_string(&recommendations).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Run Phase 4's baseline detectors, then check each finding against an
/// existing Cedar policy file using real Cedar evaluation. Returns a JSON
/// array of policy gaps (`{"principal", "resource", "reason",
/// "recommended_fix"}`) -- findings the policy would currently `Allow`.
#[pyfunction]
#[pyo3(signature = (policy_path, spec_path, historical_log_path, current_log_path, known_agents=vec![]))]
#[allow(clippy::useless_conversion)]
fn policies_diff(
    policy_path: String,
    spec_path: String,
    historical_log_path: String,
    current_log_path: String,
    known_agents: Vec<String>,
) -> PyResult<String> {
    let known_agents: std::collections::HashSet<String> = known_agents.into_iter().collect();
    let gaps = pyapicheck_core::policy_diff_from_files(
        std::path::Path::new(&policy_path),
        std::path::Path::new(&spec_path),
        std::path::Path::new(&historical_log_path),
        std::path::Path::new(&current_log_path),
        &known_agents,
    )
    .map_err(PyValueError::new_err)?;
    serde_json::to_string(&gaps).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Discover `spec_path` (and, if given, cross-reference `access_log_path`),
/// then persist the result to Postgres at `database_url` (running
/// migrations first). Returns the new inventory's row id. Opt-in only --
/// nothing else in the CLI touches a database unless this is called.
#[pyfunction]
#[pyo3(signature = (database_url, spec_path, access_log_path=None))]
#[allow(clippy::useless_conversion)]
fn persist(
    database_url: String,
    spec_path: String,
    access_log_path: Option<String>,
) -> PyResult<i64> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| PyValueError::new_err(format!("failed to start async runtime: {e}")))?;

    runtime.block_on(async {
        let inventory = pyapicheck_core::discover_from_file(std::path::Path::new(&spec_path))
            .map_err(PyValueError::new_err)?;

        let pool = pyapicheck_core::db::connect(&database_url)
            .await
            .map_err(PyValueError::new_err)?;
        pyapicheck_core::db::migrate(&pool)
            .await
            .map_err(PyValueError::new_err)?;
        let inventory_id = pyapicheck_core::db::persist_inventory(&pool, &inventory)
            .await
            .map_err(PyValueError::new_err)?;

        if let Some(log_path) = access_log_path {
            let log_text = std::fs::read_to_string(&log_path)
                .map_err(|e| PyValueError::new_err(format!("failed to read {log_path}: {e}")))?;
            let records = pyapicheck_core::parse_access_log(&log_text);
            pyapicheck_core::db::persist_traffic(&pool, inventory_id, &records)
                .await
                .map_err(PyValueError::new_err)?;
        }

        Ok(inventory_id)
    })
}

/// Re-read a previously persisted inventory back from Postgres by id.
#[pyfunction]
#[allow(clippy::useless_conversion)]
fn load_inventory(database_url: String, inventory_id: i64) -> PyResult<String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| PyValueError::new_err(format!("failed to start async runtime: {e}")))?;

    runtime.block_on(async {
        let pool = pyapicheck_core::db::connect(&database_url)
            .await
            .map_err(PyValueError::new_err)?;
        let inventory = pyapicheck_core::db::load_inventory(&pool, inventory_id)
            .await
            .map_err(PyValueError::new_err)?;
        serde_json::to_string(&inventory).map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

/// Discover MCP servers from an `mcpServers`-shaped config file, live
/// tool-introspect each one (best-effort, `timeout_secs` per server), and
/// write them into the security graph as `Tool` vertices. Returns the
/// discovery results (config + tools/status) as JSON.
#[pyfunction]
#[pyo3(signature = (database_url, config_path, timeout_secs=10))]
#[allow(clippy::useless_conversion)]
fn graph_load_mcp(
    database_url: String,
    config_path: String,
    timeout_secs: u64,
) -> PyResult<String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| PyValueError::new_err(format!("failed to start async runtime: {e}")))?;

    runtime.block_on(async {
        let text = std::fs::read_to_string(&config_path)
            .map_err(|e| PyValueError::new_err(format!("failed to read {config_path}: {e}")))?;
        let configs =
            pyapicheck_core::mcp::parse_mcp_config(&text).map_err(PyValueError::new_err)?;
        let discovered = pyapicheck_core::mcp::discover_all(
            &configs,
            std::time::Duration::from_secs(timeout_secs),
        );

        let pool = pyapicheck_core::graph::connect(&database_url)
            .await
            .map_err(PyValueError::new_err)?;
        pyapicheck_core::graph::ensure_graph(&pool)
            .await
            .map_err(PyValueError::new_err)?;
        for server in &discovered {
            pyapicheck_core::graph::upsert_mcp_server(&pool, server)
                .await
                .map_err(PyValueError::new_err)?;
        }

        serde_json::to_string(&discovered).map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

/// Write an agent identity (JSON: `{name, owner, allowed_tools,
/// allowed_apis, declared_scope}`) into the security graph, linking it to
/// its declared tools/APIs (which must already exist as `Tool`/`Endpoint`
/// vertices).
#[pyfunction]
#[allow(clippy::useless_conversion)]
fn graph_add_agent(database_url: String, agent_json: String) -> PyResult<()> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| PyValueError::new_err(format!("failed to start async runtime: {e}")))?;

    runtime.block_on(async {
        let agent: pyapicheck_core::model::AgentIdentity =
            serde_json::from_str(&agent_json).map_err(|e| PyValueError::new_err(e.to_string()))?;

        let pool = pyapicheck_core::graph::connect(&database_url)
            .await
            .map_err(PyValueError::new_err)?;
        pyapicheck_core::graph::ensure_graph(&pool)
            .await
            .map_err(PyValueError::new_err)?;
        pyapicheck_core::graph::upsert_agent(&pool, &agent)
            .await
            .map_err(PyValueError::new_err)
    })
}

/// "What can this agent reach": every node reachable from `agent_name` via
/// any path of graph edges. Returns a JSON array of `{label, name}`.
#[pyfunction]
#[allow(clippy::useless_conversion)]
fn graph_reachable(database_url: String, agent_name: String) -> PyResult<String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| PyValueError::new_err(format!("failed to start async runtime: {e}")))?;

    runtime.block_on(async {
        let pool = pyapicheck_core::graph::connect(&database_url)
            .await
            .map_err(PyValueError::new_err)?;
        pyapicheck_core::graph::ensure_graph(&pool)
            .await
            .map_err(PyValueError::new_err)?;
        let nodes = pyapicheck_core::graph::reachable_from(&pool, &agent_name)
            .await
            .map_err(PyValueError::new_err)?;
        serde_json::to_string(&nodes).map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

/// "What's the blast radius if this resource leaks": every Agent/User with
/// a path into `resource_name`. Returns a JSON array of `{label, name}`.
#[pyfunction]
#[allow(clippy::useless_conversion)]
fn graph_blast_radius(database_url: String, resource_name: String) -> PyResult<String> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| PyValueError::new_err(format!("failed to start async runtime: {e}")))?;

    runtime.block_on(async {
        let pool = pyapicheck_core::graph::connect(&database_url)
            .await
            .map_err(PyValueError::new_err)?;
        pyapicheck_core::graph::ensure_graph(&pool)
            .await
            .map_err(PyValueError::new_err)?;
        let nodes = pyapicheck_core::graph::blast_radius(&pool, &resource_name)
            .await
            .map_err(PyValueError::new_err)?;
        serde_json::to_string(&nodes).map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(discover, m)?)?;
    m.add_function(wrap_pyfunction!(remediate, m)?)?;
    m.add_function(wrap_pyfunction!(discover_directory, m)?)?;
    m.add_function(wrap_pyfunction!(diff, m)?)?;
    m.add_function(wrap_pyfunction!(report, m)?)?;
    m.add_function(wrap_pyfunction!(baseline, m)?)?;
    m.add_function(wrap_pyfunction!(policies_validate, m)?)?;
    m.add_function(wrap_pyfunction!(policies_recommend, m)?)?;
    m.add_function(wrap_pyfunction!(policies_diff, m)?)?;
    m.add_function(wrap_pyfunction!(persist, m)?)?;
    m.add_function(wrap_pyfunction!(load_inventory, m)?)?;
    m.add_function(wrap_pyfunction!(graph_load_mcp, m)?)?;
    m.add_function(wrap_pyfunction!(graph_add_agent, m)?)?;
    m.add_function(wrap_pyfunction!(graph_reachable, m)?)?;
    m.add_function(wrap_pyfunction!(graph_blast_radius, m)?)?;
    Ok(())
}

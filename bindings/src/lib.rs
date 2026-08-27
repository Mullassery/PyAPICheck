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

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(discover, m)?)?;
    m.add_function(wrap_pyfunction!(remediate, m)?)?;
    m.add_function(wrap_pyfunction!(discover_directory, m)?)?;
    m.add_function(wrap_pyfunction!(diff, m)?)?;
    m.add_function(wrap_pyfunction!(report, m)?)?;
    m.add_function(wrap_pyfunction!(persist, m)?)?;
    m.add_function(wrap_pyfunction!(load_inventory, m)?)?;
    Ok(())
}

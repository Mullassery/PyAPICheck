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

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(discover, m)?)?;
    m.add_function(wrap_pyfunction!(remediate, m)?)?;
    Ok(())
}

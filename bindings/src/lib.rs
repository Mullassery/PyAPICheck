use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Discover an API inventory from an OpenAPI spec file on disk.
/// Returns the inventory serialized as a JSON string; the Python side
/// deserializes it rather than paying for a full PyO3 type conversion.
#[pyfunction]
fn discover(path: String) -> PyResult<String> {
    let inventory = pyapicheck_core::discover_from_file(std::path::Path::new(&path))
        .map_err(PyValueError::new_err)?;
    serde_json::to_string(&inventory).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(discover, m)?)?;
    Ok(())
}

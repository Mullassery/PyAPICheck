//! Directory / repo-wide spec discovery: walk a directory tree for files
//! that look like OpenAPI/Swagger specs and discover each one independently.
//! A single repo commonly hosts multiple services, so this returns one
//! `Inventory` per matched file rather than trying to merge them.

use crate::discover_from_file;
use crate::model::Inventory;
use std::path::{Path, PathBuf};

/// Directories never worth descending into when looking for spec files.
const SKIP_DIRS: &[&str] = &["target", "node_modules", ".venv", "venv", "dist", "build"];

/// Recursively find files under `dir` whose name matches a known
/// OpenAPI/Swagger convention (`openapi.y*ml`, `openapi.json`,
/// `swagger.y*ml`, `swagger.json`, case-insensitive), then discover each.
/// Returns `Ok(vec![])` (not an error) when nothing matches — "no APIs
/// found in this directory" is a valid, reportable result, not a failure.
pub fn discover_from_directory(dir: &Path) -> Result<Vec<Inventory>, String> {
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }

    let mut spec_paths = Vec::new();
    walk(dir, &mut spec_paths)?;
    spec_paths.sort();

    spec_paths.iter().map(|p| discover_from_file(p)).collect()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("failed to read {}: {e}", dir.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if path.is_dir() {
            if name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(&path, out)?;
        } else if is_spec_filename(&name) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_spec_filename(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        "openapi.yaml"
            | "openapi.yml"
            | "openapi.json"
            | "swagger.yaml"
            | "swagger.yml"
            | "swagger.json"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    const MINIMAL_SPEC: &str = r#"
info:
  title: Svc
  version: "1.0"
paths:
  /ping:
    get:
      responses:
        "200":
          description: ok
"#;

    #[test]
    fn finds_specs_in_nested_services_and_ignores_noise_dirs() {
        let tmp = std::env::temp_dir().join(format!("pyapicheck-dirtest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        write(&tmp, "service-a/openapi.yaml", MINIMAL_SPEC);
        write(
            &tmp,
            "service-b/docs/swagger.json",
            &MINIMAL_SPEC.replace("yaml", "json"),
        );
        write(&tmp, "service-b/node_modules/openapi.yaml", MINIMAL_SPEC);
        write(&tmp, "README.md", "not a spec");

        let inventories = discover_from_directory(&tmp).expect("directory should discover");
        assert_eq!(inventories.len(), 2);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn empty_directory_returns_empty_vec_not_error() {
        let tmp = std::env::temp_dir().join(format!("pyapicheck-emptytest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let inventories = discover_from_directory(&tmp).expect("should not error");
        assert!(inventories.is_empty());

        fs::remove_dir_all(&tmp).unwrap();
    }
}

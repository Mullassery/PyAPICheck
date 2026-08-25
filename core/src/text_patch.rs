//! Format-preserving spec patching.
//!
//! `remediate::apply_fixes` operates on a parsed `serde_json::Value` and is
//! the right tool for *analysis* (e.g. the end-to-end test in
//! `remediate.rs` re-discovers the patched `Value` to confirm a fix
//! actually changes `authenticated`). But writing that `Value` back out via
//! `serde_json::to_string_pretty`/`serde_yaml::to_string` re-serializes the
//! *entire* document: keys get alphabetized, YAML comments are silently
//! dropped (comments aren't part of the JSON/YAML data model at all, so a
//! generic `Value` never even sees them), and formatting choices (quote
//! style, flow vs. block) change throughout the file. For a spec that's
//! meant to ship as a reviewable, minimal PR diff, that's a real defect --
//! not a cosmetic one, since it can silently delete human-authored
//! comments.
//!
//! These functions instead write each fix directly into the *original
//! text* as a single line -- replacing an existing same-key line in place
//! if the operation already has one (e.g. an explicit `security: []`
//! opt-out), otherwise inserting a new line -- located by indentation-aware
//! (YAML) or brace-depth-aware (JSON) line scanning. Everything else in the
//! file -- comments, key order, quote style -- is untouched.

use crate::remediate::SpecFix;

fn field_value_yaml(fix: &SpecFix) -> Option<String> {
    match fix.key.as_str() {
        "security" => fix
            .scheme_name
            .as_ref()
            .map(|scheme| format!("security: [{{{scheme}: []}}]")),
        "operationId" => fix
            .operation_id
            .as_ref()
            .map(|id| format!("operationId: {id}")),
        _ => None,
    }
}

fn field_value_json(fix: &SpecFix) -> Option<String> {
    match fix.key.as_str() {
        "security" => fix
            .scheme_name
            .as_ref()
            .map(|scheme| format!("\"security\": [{{\"{scheme}\": []}}]")),
        "operationId" => fix
            .operation_id
            .as_ref()
            .map(|id| format!("\"operationId\": \"{id}\"")),
        _ => None,
    }
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Where a fix's new key should go, relative to the operation's method
/// line: either replacing an existing line that already declares that key
/// (e.g. `security: []`), or being inserted as a new line right after the
/// method line.
enum Target {
    Replace(usize),
    InsertAfter(usize),
}

/// Finds the line index of `paths.<path>.<method>` in a YAML document's
/// lines, and where `key` should be written: replacing an existing
/// same-key line within the operation body if one is present (avoids
/// producing a duplicate mapping key -- e.g. a `no_auth` fix's target
/// operation typically already has an explicit `security: []` opt-out),
/// otherwise inserted right after the method line.
fn find_yaml_operation_line(
    lines: &[&str],
    path: &str,
    method: &str,
    key: &str,
) -> Option<(Target, usize)> {
    let paths_idx = lines
        .iter()
        .position(|l| l.trim_end() == "paths:" && indent_of(l) == 0)?;

    let mut path_idx = None;
    let mut path_indent = 0;
    let mut i = paths_idx + 1;
    while i < lines.len() {
        let line = lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        let indent = indent_of(line);
        if indent == 0 {
            break; // left the `paths:` block entirely
        }
        if path_idx.is_none() {
            path_indent = indent;
        }
        if indent == path_indent && yaml_key_matches(line, path) {
            path_idx = Some(i);
            break;
        }
        if indent < path_indent {
            break;
        }
        i += 1;
    }
    let path_idx = path_idx?;

    let step = path_indent; // paths: is at indent 0, so step == path_indent
    let method_indent = path_indent + step;
    let method_lower = method.to_lowercase();

    let mut j = path_idx + 1;
    while j < lines.len() {
        let line = lines[j];
        if line.trim().is_empty() {
            j += 1;
            continue;
        }
        let indent = indent_of(line);
        if indent <= path_indent {
            break; // left this path's block
        }
        if indent == method_indent && yaml_key_matches(line, &method_lower) {
            let method_line_idx = j;
            let body_indent = method_indent + step;

            let mut k = method_line_idx + 1;
            while k < lines.len() {
                let body_line = lines[k];
                if body_line.trim().is_empty() {
                    k += 1;
                    continue;
                }
                let body_indent_here = indent_of(body_line);
                if body_indent_here <= method_indent {
                    break; // left the operation body
                }
                if body_indent_here == body_indent && yaml_key_matches(body_line, key) {
                    return Some((Target::Replace(k), body_indent));
                }
                k += 1;
            }
            return Some((Target::InsertAfter(method_line_idx), body_indent));
        }
        j += 1;
    }
    None
}

/// A YAML block-mapping key line matches `key` if, after stripping
/// indentation, splitting on the first `:`, and stripping an optional
/// matched quote pair, the key part equals `key`.
fn yaml_key_matches(line: &str, key: &str) -> bool {
    let Some((k, _rest)) = line.trim().split_once(':') else {
        return false;
    };
    let k = k.trim();
    let k = k
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| k.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(k);
    k == key
}

/// Writes each fix in `fixes` into `text` (a YAML OpenAPI document): if the
/// operation already has a line for that key (e.g. an explicit
/// `security: []` opt-out -- the actual `no_auth` case in practice), that
/// line is replaced in place; otherwise a new line is inserted right after
/// the method line. Fixes whose `path`/`method` can no longer be located
/// (e.g. the document doesn't match what `fixes` was computed from) are
/// silently skipped.
pub fn patch_yaml_text(text: &str, fixes: &[SpecFix]) -> String {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();

    // Apply from the bottom up so earlier edits don't shift the line
    // indices later fixes were located against.
    let mut located: Vec<(Target, usize, String)> = Vec::new();
    for fix in fixes {
        let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
        if let Some((target, body_indent)) =
            find_yaml_operation_line(&borrowed, &fix.path, &fix.method, &fix.key)
        {
            if let Some(value) = field_value_yaml(fix) {
                located.push((target, body_indent, value));
            }
        }
    }
    located.sort_by_key(|(target, ..)| {
        std::cmp::Reverse(match target {
            Target::Replace(idx) | Target::InsertAfter(idx) => *idx,
        })
    });

    for (target, body_indent, value) in located {
        let line = format!("{}{value}", " ".repeat(body_indent));
        match target {
            Target::Replace(idx) => lines[idx] = line,
            Target::InsertAfter(idx) => lines.insert(idx + 1, line),
        }
    }

    let mut result = lines.join("\n");
    if text.ends_with('\n') {
        result.push('\n');
    }
    result
}

/// JSON equivalent of `find_yaml_operation_line`: locates where `key`
/// should be written inside `"paths"."<path>"."<method>"` -- replacing an
/// existing same-key line within the operation body if present (avoids a
/// duplicate JSON key, which most parsers accept but silently resolve to
/// "last value wins", not what a reviewer would expect from a diff),
/// otherwise inserted right after the method's opening line.
fn find_json_operation_line(
    lines: &[&str],
    path: &str,
    method: &str,
    key: &str,
) -> Option<(Target, usize)> {
    let paths_idx = lines.iter().position(|l| {
        let t = l.trim();
        t.starts_with("\"paths\"") && t.contains('{')
    })?;
    let paths_indent = indent_of(lines[paths_idx]);

    let path_key = format!("\"{path}\"");
    let mut path_idx = None;
    let mut path_indent = 0;
    let mut i = paths_idx + 1;
    while i < lines.len() {
        let line = lines[i];
        let indent = indent_of(line);
        if line.trim() == "}" && indent <= paths_indent {
            break;
        }
        if path_idx.is_none() && line.trim_start().starts_with(&path_key) {
            path_idx = Some(i);
            path_indent = indent;
            break;
        }
        i += 1;
    }
    let path_idx = path_idx?;
    let step = path_indent - paths_indent;
    let method_indent = path_indent + step;

    let method_key = format!("\"{method}\"", method = method.to_lowercase());
    let mut j = path_idx + 1;
    while j < lines.len() {
        let line = lines[j];
        let indent = indent_of(line);
        if indent <= path_indent && line.trim().starts_with('}') {
            break;
        }
        if indent == method_indent && line.trim_start().starts_with(&method_key) {
            let method_line_idx = j;
            let body_indent = method_indent + step;
            let key_prefix = format!("\"{key}\"");

            let mut k = method_line_idx + 1;
            while k < lines.len() {
                let body_line = lines[k];
                let body_indent_here = indent_of(body_line);
                if body_indent_here <= method_indent && body_line.trim().starts_with('}') {
                    break; // left the operation body
                }
                if body_indent_here == body_indent
                    && body_line.trim_start().starts_with(&key_prefix)
                {
                    return Some((Target::Replace(k), body_indent));
                }
                k += 1;
            }
            return Some((Target::InsertAfter(method_line_idx), body_indent));
        }
        j += 1;
    }
    None
}

/// Writes each fix in `fixes` into `text` (a JSON OpenAPI document,
/// pretty-printed with a consistent indent step): if the operation already
/// has a line for that key, it's replaced in place (preserving whether it
/// had a trailing comma); otherwise a new line is inserted right after the
/// method's opening line, with a trailing comma since it precedes the
/// operation's existing keys.
pub fn patch_json_text(text: &str, fixes: &[SpecFix]) -> String {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();

    let mut located: Vec<(Target, usize, String)> = Vec::new();
    for fix in fixes {
        let borrowed: Vec<&str> = lines.iter().map(String::as_str).collect();
        if let Some((target, body_indent)) =
            find_json_operation_line(&borrowed, &fix.path, &fix.method, &fix.key)
        {
            if let Some(value) = field_value_json(fix) {
                located.push((target, body_indent, value));
            }
        }
    }
    located.sort_by_key(|(target, ..)| {
        std::cmp::Reverse(match target {
            Target::Replace(idx) | Target::InsertAfter(idx) => *idx,
        })
    });

    for (target, body_indent, value) in located {
        match target {
            Target::Replace(idx) => {
                let had_trailing_comma = lines[idx].trim_end().ends_with(',');
                let comma = if had_trailing_comma { "," } else { "" };
                lines[idx] = format!("{}{value}{comma}", " ".repeat(body_indent));
            }
            Target::InsertAfter(idx) => {
                lines.insert(idx + 1, format!("{}{value},", " ".repeat(body_indent)));
            }
        }
    }

    let mut result = lines.join("\n");
    if text.ends_with('\n') {
        result.push('\n');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fix(
        path: &str,
        method: &str,
        key: &str,
        scheme: Option<&str>,
        op_id: Option<&str>,
    ) -> SpecFix {
        SpecFix {
            path: path.to_string(),
            method: method.to_string(),
            factor_id: if key == "security" {
                "no_auth".to_string()
            } else {
                "missing_metadata".to_string()
            },
            description: "test".to_string(),
            key: key.to_string(),
            scheme_name: scheme.map(String::from),
            operation_id: op_id.map(String::from),
        }
    }

    const YAML_SPEC: &str = r#"openapi: 3.0.3
info:
  title: t
  version: "1.0"
paths:
  /widgets:
    post:
      # keep this comment
      security: []
      responses:
        "201":
          description: ok
"#;

    #[test]
    fn yaml_patch_preserves_comments_and_order() {
        let fixes = vec![fix(
            "/widgets",
            "POST",
            "security",
            Some("bearerAuth"),
            None,
        )];
        let patched = patch_yaml_text(YAML_SPEC, &fixes);

        assert!(
            patched.contains("# keep this comment"),
            "comment must survive:\n{patched}"
        );
        assert!(patched.contains("security: [{bearerAuth: []}]"));
        // YAML_SPEC already has an explicit `security: []` -- the fix must
        // replace that line in place (same line count), not insert a
        // second `security` key alongside it (which would be an invalid
        // duplicate mapping key).
        let original_lines: Vec<&str> = YAML_SPEC.lines().collect();
        let patched_lines: Vec<&str> = patched.lines().collect();
        assert_eq!(patched_lines.len(), original_lines.len());
        assert!(
            !patched.contains("security: []"),
            "old security: [] line must be gone"
        );
        // Every other line is untouched.
        for orig_line in original_lines.iter().filter(|l| l.trim() != "security: []") {
            assert!(
                patched_lines.contains(orig_line),
                "missing original line: {orig_line}"
            );
        }
    }

    #[test]
    fn yaml_patch_inserts_operation_id() {
        let fixes = vec![fix(
            "/widgets",
            "POST",
            "operationId",
            None,
            Some("post_widgets"),
        )];
        let patched = patch_yaml_text(YAML_SPEC, &fixes);

        assert!(patched.contains("operationId: post_widgets"));
    }

    #[test]
    fn yaml_patch_inserts_security_when_no_existing_key() {
        // No `security:` key anywhere in this operation (falls to the
        // global default absence) -- must insert a new line, not replace
        // one that doesn't exist.
        let spec = r#"openapi: 3.0.3
info:
  title: t
  version: "1.0"
paths:
  /widgets:
    post:
      responses:
        "201":
          description: ok
"#;
        let fixes = vec![fix(
            "/widgets",
            "POST",
            "security",
            Some("bearerAuth"),
            None,
        )];
        let patched = patch_yaml_text(spec, &fixes);

        assert!(patched.contains("security: [{bearerAuth: []}]"));
        assert_eq!(patched.lines().count(), spec.lines().count() + 1);
        for orig_line in spec.lines() {
            assert!(patched.lines().any(|l| l == orig_line));
        }
    }

    #[test]
    fn yaml_patch_targets_correct_path_when_multiple_paths_present() {
        let spec = r#"openapi: 3.0.3
info:
  title: t
  version: "1.0"
paths:
  /widgets:
    get:
      responses:
        "200":
          description: ok
  /gadgets:
    post:
      security: []
      responses:
        "201":
          description: ok
"#;
        let fixes = vec![fix("/gadgets", "POST", "security", Some("apiKey"), None)];
        let patched = patch_yaml_text(spec, &fixes);

        let lines: Vec<&str> = patched.lines().collect();
        let inserted_idx = lines
            .iter()
            .position(|l| l.trim() == "security: [{apiKey: []}]")
            .unwrap();
        // Must land inside /gadgets' post block, not /widgets' get block.
        assert!(lines[..inserted_idx]
            .iter()
            .any(|l| l.trim() == "/gadgets:"));
        assert!(lines[inserted_idx - 1].trim() == "post:");
    }

    const JSON_SPEC: &str = r#"{
  "openapi": "3.0.3",
  "info": {
    "title": "t",
    "version": "1.0"
  },
  "paths": {
    "/widgets": {
      "post": {
        "security": [],
        "responses": {
          "201": {
            "description": "ok"
          }
        }
      }
    }
  }
}
"#;

    #[test]
    fn json_patch_replaces_existing_security_line() {
        // JSON_SPEC already has `"security": [],` -- must be replaced in
        // place, not duplicated (duplicate JSON keys are ambiguous/parser-
        // dependent, and definitely not a minimal diff).
        let fixes = vec![fix(
            "/widgets",
            "POST",
            "security",
            Some("bearerAuth"),
            None,
        )];
        let patched = patch_json_text(JSON_SPEC, &fixes);

        assert!(patched.contains("\"security\": [{\"bearerAuth\": []}],"));
        assert_eq!(patched.matches("\"security\"").count(), 1);
        assert_eq!(patched.lines().count(), JSON_SPEC.lines().count());
        let parsed: serde_json::Value =
            serde_json::from_str(&patched).expect("patched JSON must parse");
        assert_eq!(
            parsed.pointer("/paths/~1widgets/post/security"),
            Some(&serde_json::json!([{"bearerAuth": []}]))
        );
    }

    #[test]
    fn json_patch_inserts_security_when_no_existing_key() {
        let spec = r#"{
  "openapi": "3.0.3",
  "info": {
    "title": "t",
    "version": "1.0"
  },
  "paths": {
    "/widgets": {
      "post": {
        "responses": {
          "201": {
            "description": "ok"
          }
        }
      }
    }
  }
}
"#;
        let fixes = vec![fix(
            "/widgets",
            "POST",
            "security",
            Some("bearerAuth"),
            None,
        )];
        let patched = patch_json_text(spec, &fixes);

        assert!(patched.contains("\"security\": [{\"bearerAuth\": []}],"));
        assert_eq!(patched.lines().count(), spec.lines().count() + 1);
        let _: serde_json::Value = serde_json::from_str(&patched).expect("patched JSON must parse");
    }

    #[test]
    fn json_patch_inserts_operation_id() {
        let fixes = vec![fix(
            "/widgets",
            "POST",
            "operationId",
            None,
            Some("post_widgets"),
        )];
        let patched = patch_json_text(JSON_SPEC, &fixes);

        assert!(patched.contains("\"operationId\": \"post_widgets\","));
        let _: serde_json::Value = serde_json::from_str(&patched).expect("patched JSON must parse");
    }

    #[test]
    fn unlocatable_fix_is_skipped_without_panicking() {
        let fixes = vec![fix(
            "/does-not-exist",
            "GET",
            "security",
            Some("bearerAuth"),
            None,
        )];
        let patched = patch_yaml_text(YAML_SPEC, &fixes);

        assert_eq!(patched, YAML_SPEC);
    }
}

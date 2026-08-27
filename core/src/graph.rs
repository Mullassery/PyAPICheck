//! Security graph persistence via Postgres + Apache AGE (Phase 3): the
//! `User`/`Agent`/`Tool`/`Endpoint`/`Resource`/`Role` vertex vocabulary and
//! `CAN_CALL`/`EXPOSES`/`ACCESSES`/`HAS_ROLE` edges from the product
//! vision doc, plus the reachability/blast-radius traversals built on top.
//!
//! Two AGE quirks, verified empirically against a real `apache/age`
//! container before writing any of this (not assumed from docs):
//!
//! 1. `cypher()`'s third (parameters) argument must be a literal
//!    query-parameter AST node -- `PREPARE q AS ... $1 ...; EXECUTE q(...)`
//!    works, but both a plain string constant and a `$1::agtype` cast
//!    fail with "third argument of cypher function must be a parameter".
//!    sqlx's typed `.bind()` API has no way to send an untyped/agtype
//!    parameter through the extended query protocol to satisfy this, so
//!    every value that reaches a Cypher query goes through
//!    `cypher_string` (escaped double-quoted literal interpolation)
//!    instead -- the documented workaround most AGE client libraries use.
//! 2. `LOAD 'age'` and `search_path` are session-level settings, not
//!    database-level, so a fresh pooled connection needs them re-applied;
//!    `connect` does this via `after_connect` on every connection the pool
//!    hands out, not just the first one.

use crate::mcp::{DiscoveredMcpServer, ToolDiscoveryResult};
use crate::model::AgentIdentity;
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

const GRAPH_NAME: &str = "pyapicheck_graph";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexLabel {
    User,
    Agent,
    Tool,
    Endpoint,
    Resource,
    Role,
}

impl VertexLabel {
    fn as_str(self) -> &'static str {
        match self {
            VertexLabel::User => "User",
            VertexLabel::Agent => "Agent",
            VertexLabel::Tool => "Tool",
            VertexLabel::Endpoint => "Endpoint",
            VertexLabel::Resource => "Resource",
            VertexLabel::Role => "Role",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeLabel {
    CanCall,
    Exposes,
    Accesses,
    HasRole,
}

impl EdgeLabel {
    fn as_str(self) -> &'static str {
        match self {
            EdgeLabel::CanCall => "CAN_CALL",
            EdgeLabel::Exposes => "EXPOSES",
            EdgeLabel::Accesses => "ACCESSES",
            EdgeLabel::HasRole => "HAS_ROLE",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReachableNode {
    pub label: String,
    pub name: String,
}

/// Escape a value for safe interpolation into a double-quoted Cypher
/// string literal (see module doc for why this is necessary at all).
fn cypher_string(value: &str) -> Result<String, String> {
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(format!(
            "value must not contain control characters: {value:?}"
        ));
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

/// Connect to Postgres, configuring every pooled connection for AGE.
pub async fn connect(database_url: &str) -> Result<PgPool, String> {
    PgPoolOptions::new()
        .max_connections(5)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("LOAD 'age'").execute(&mut *conn).await?;
                sqlx::query("SET search_path = ag_catalog, \"$user\", public")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
        .map_err(|e| format!("failed to connect to graph database: {e}"))
}

const ALL_VERTEX_LABELS: &[VertexLabel] = &[
    VertexLabel::User,
    VertexLabel::Agent,
    VertexLabel::Tool,
    VertexLabel::Endpoint,
    VertexLabel::Resource,
    VertexLabel::Role,
];
const ALL_EDGE_LABELS: &[EdgeLabel] = &[
    EdgeLabel::CanCall,
    EdgeLabel::Exposes,
    EdgeLabel::Accesses,
    EdgeLabel::HasRole,
];

/// Ensure the AGE extension, this project's graph, and every known vertex/
/// edge label all exist. Safe to call on every startup, including
/// concurrently from multiple callers -- every step here raced two
/// parallel callers against a fresh database before shipping, and each
/// failure mode found that way gets its own re-check-before-erroring
/// tolerance rather than an assumption that "IF NOT EXISTS"-style SQL is
/// enough on its own:
/// - `CREATE EXTENSION IF NOT EXISTS age`'s install script itself isn't
///   concurrency-safe on a brand-new database (`duplicate key value
///   violates unique constraint pg_namespace_nspname_index`).
/// - `create_graph` isn't idempotent.
/// - A vertex/edge label's backing table is created lazily by AGE on
///   first `MERGE`/`CREATE` if not pre-declared, and *that* lazy creation
///   isn't concurrency-safe either (`relation "Tool" already exists`) --
///   which is why every label is explicitly pre-created here via
///   `create_vlabel`/`create_elabel` up front, rather than left to race
///   on whichever caller's MERGE happens to run first.
pub async fn ensure_graph(pool: &PgPool) -> Result<(), String> {
    if let Err(e) = sqlx::query("CREATE EXTENSION IF NOT EXISTS age")
        .execute(pool)
        .await
    {
        if !extension_exists(pool).await? {
            return Err(format!("failed to create age extension: {e}"));
        }
    }

    if !graph_exists(pool).await? {
        if let Err(e) = sqlx::query(&format!("SELECT create_graph('{GRAPH_NAME}')"))
            .execute(pool)
            .await
        {
            if !graph_exists(pool).await? {
                return Err(format!("failed to create graph: {e}"));
            }
        }
    }

    for label in ALL_VERTEX_LABELS {
        ensure_label(pool, "create_vlabel", label.as_str()).await?;
    }
    for label in ALL_EDGE_LABELS {
        ensure_label(pool, "create_elabel", label.as_str()).await?;
    }

    Ok(())
}

async fn ensure_label(pool: &PgPool, create_fn: &str, label: &str) -> Result<(), String> {
    if label_exists(pool, label).await? {
        return Ok(());
    }
    if let Err(e) = sqlx::query(&format!("SELECT {create_fn}('{GRAPH_NAME}', '{label}')"))
        .execute(pool)
        .await
    {
        if !label_exists(pool, label).await? {
            return Err(format!("failed to create label {label:?}: {e}"));
        }
    }
    Ok(())
}

async fn label_exists(pool: &PgPool, label: &str) -> Result<bool, String> {
    sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM ag_catalog.ag_label
            WHERE name = $1 AND graph = (SELECT graphid FROM ag_catalog.ag_graph WHERE name = $2)
        )",
    )
    .bind(label)
    .bind(GRAPH_NAME)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("failed to check label existence for {label:?}: {e}"))
}

async fn extension_exists(pool: &PgPool) -> Result<bool, String> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'age')")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("failed to check age extension existence: {e}"))
}

async fn graph_exists(pool: &PgPool) -> Result<bool, String> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = $1)")
        .bind(GRAPH_NAME)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("failed to check graph existence: {e}"))
}

/// Create or update a vertex, matched by (label, name).
pub async fn upsert_vertex(pool: &PgPool, label: VertexLabel, name: &str) -> Result<(), String> {
    let name_lit = cypher_string(name)?;
    let query = format!(
        "SELECT * FROM cypher('{GRAPH_NAME}', $$
            MERGE (n:{label} {{name: {name_lit}}})
            RETURN n
        $$) as (n agtype)",
        label = label.as_str(),
    );
    sqlx::query(&query)
        .execute(pool)
        .await
        .map_err(|e| format!("failed to upsert {} vertex {name:?}: {e}", label.as_str()))?;
    Ok(())
}

/// Create an edge between two *existing* vertices. Errors (rather than the
/// silent no-op a `MATCH` on a missing vertex would otherwise produce) if
/// either endpoint doesn't exist yet -- see the module-level design
/// constraint in ROADMAP.md Phase 3.3.
pub async fn upsert_edge(
    pool: &PgPool,
    from_label: VertexLabel,
    from_name: &str,
    edge: EdgeLabel,
    to_label: VertexLabel,
    to_name: &str,
) -> Result<(), String> {
    let from_lit = cypher_string(from_name)?;
    let to_lit = cypher_string(to_name)?;
    let query = format!(
        "SELECT * FROM cypher('{GRAPH_NAME}', $$
            MATCH (a:{from_label} {{name: {from_lit}}}), (b:{to_label} {{name: {to_lit}}})
            MERGE (a)-[:{edge}]->(b)
            RETURN a
        $$) as (a agtype)",
        from_label = from_label.as_str(),
        to_label = to_label.as_str(),
        edge = edge.as_str(),
    );
    let rows = sqlx::query(&query)
        .fetch_all(pool)
        .await
        .map_err(|e| format!("failed to upsert edge {from_name:?} -> {to_name:?}: {e}"))?;

    if rows.is_empty() {
        return Err(format!(
            "cannot link {} {from_name:?} -> {} {to_name:?}: one or both vertices don't exist yet",
            from_label.as_str(),
            to_label.as_str(),
        ));
    }
    Ok(())
}

/// Write an `Agent` vertex and `CAN_CALL` edges to each of its declared
/// tools/APIs. Every declared tool/API must already exist as a `Tool`/
/// `Endpoint` vertex -- an agent can't be wired to a capability that was
/// never discovered (fails via `upsert_edge`'s error if not).
pub async fn upsert_agent(pool: &PgPool, agent: &AgentIdentity) -> Result<(), String> {
    upsert_vertex(pool, VertexLabel::Agent, &agent.name).await?;

    let name_lit = cypher_string(&agent.name)?;
    let owner_lit = cypher_string(&agent.owner)?;
    let scope_lit = cypher_string(&agent.declared_scope)?;
    let query = format!(
        "SELECT * FROM cypher('{GRAPH_NAME}', $$
            MATCH (n:Agent {{name: {name_lit}}})
            SET n.owner = {owner_lit}, n.declared_scope = {scope_lit}
            RETURN n
        $$) as (n agtype)"
    );
    sqlx::query(&query)
        .execute(pool)
        .await
        .map_err(|e| format!("failed to set agent properties for {:?}: {e}", agent.name))?;

    for tool in &agent.allowed_tools {
        upsert_edge(
            pool,
            VertexLabel::Agent,
            &agent.name,
            EdgeLabel::CanCall,
            VertexLabel::Tool,
            tool,
        )
        .await?;
    }
    for api in &agent.allowed_apis {
        upsert_edge(
            pool,
            VertexLabel::Agent,
            &agent.name,
            EdgeLabel::CanCall,
            VertexLabel::Endpoint,
            api,
        )
        .await?;
    }
    Ok(())
}

/// Write a `Tool` vertex for a discovered MCP server: its real tool list
/// (comma-joined, from live introspection) and discovery status as
/// properties. A server whose live discovery came back `Unavailable` still
/// gets a vertex -- it's a known, if currently unreachable, capability --
/// with `status` recording why, never silently recorded as having zero
/// tools.
pub async fn upsert_mcp_server(pool: &PgPool, server: &DiscoveredMcpServer) -> Result<(), String> {
    upsert_vertex(pool, VertexLabel::Tool, &server.config.name).await?;

    let (tools_prop, status_prop) = match &server.tools {
        ToolDiscoveryResult::Tools(tools) => (tools.join(","), "discovered".to_string()),
        ToolDiscoveryResult::Unavailable(reason) => {
            (String::new(), format!("unavailable: {reason}"))
        }
    };

    let name_lit = cypher_string(&server.config.name)?;
    let tools_lit = cypher_string(&tools_prop)?;
    let status_lit = cypher_string(&status_prop)?;
    let query = format!(
        "SELECT * FROM cypher('{GRAPH_NAME}', $$
            MATCH (n:Tool {{name: {name_lit}}})
            SET n.tools = {tools_lit}, n.status = {status_lit}
            RETURN n
        $$) as (n agtype)"
    );
    sqlx::query(&query).execute(pool).await.map_err(|e| {
        format!(
            "failed to set tool properties for {:?}: {e}",
            server.config.name
        )
    })?;
    Ok(())
}

async fn traverse(pool: &PgPool, query: &str) -> Result<Vec<ReachableNode>, String> {
    let rows = sqlx::query(query)
        .fetch_all(pool)
        .await
        .map_err(|e| format!("graph traversal failed: {e}"))?;

    let mut out: Vec<ReachableNode> = rows
        .into_iter()
        .map(|row| {
            let label: String = row.try_get("lbl").map_err(|e| e.to_string())?;
            let name: String = row.try_get("nm").map_err(|e| e.to_string())?;
            Ok(ReachableNode { label, name })
        })
        .collect::<Result<_, String>>()?;
    out.sort_by(|a, b| a.label.cmp(&b.label).then(a.name.cmp(&b.name)));
    Ok(out)
}

/// "What can this agent reach": every node connected from `agent_name` via
/// any path of outgoing edges, up to 6 hops -- a bound, not an
/// approximation; 6 comfortably covers Agent -> Tool -> Endpoint ->
/// Resource chains with room to spare, while keeping a pathological graph
/// from turning this into an unbounded traversal.
pub async fn reachable_from(pool: &PgPool, agent_name: &str) -> Result<Vec<ReachableNode>, String> {
    let name_lit = cypher_string(agent_name)?;
    let query = format!(
        "SELECT (lbl)::text AS lbl, (nm)::text AS nm FROM cypher('{GRAPH_NAME}', $$
            MATCH (a:Agent {{name: {name_lit}}})-[*1..6]->(r)
            RETURN DISTINCT label(r), r.name
        $$) as (lbl agtype, nm agtype)"
    );
    traverse(pool, &query).await
}

/// "What's the blast radius if this resource/credential leaks": every
/// `Agent`/`User` with a path *into* `resource_name`, up to 6 hops.
pub async fn blast_radius(
    pool: &PgPool,
    resource_name: &str,
) -> Result<Vec<ReachableNode>, String> {
    let name_lit = cypher_string(resource_name)?;
    let query = format!(
        "SELECT (lbl)::text AS lbl, (nm)::text AS nm FROM cypher('{GRAPH_NAME}', $$
            MATCH (a)-[*1..6]->(r {{name: {name_lit}}})
            RETURN DISTINCT label(a), a.name
        $$) as (lbl agtype, nm agtype)"
    );
    traverse(pool, &query).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs a real, reachable Postgres+AGE database -- set `DATABASE_URL`
    /// (e.g. against `docker run apache/age`) to run these. Skipped, not
    /// failed, when unset; CI sets it via an `apache/age` service so these
    /// run for real on every push.
    async fn test_pool_or_skip() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = connect(&url).await.expect("connect to graph test database");
        ensure_graph(&pool).await.expect("ensure graph exists");
        Some(pool)
    }

    fn unique_suffix() -> String {
        format!("{:?}", std::time::SystemTime::now())
    }

    #[tokio::test]
    async fn agent_can_reach_its_declared_tools_and_their_resources() {
        let Some(pool) = test_pool_or_skip().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let suffix = unique_suffix();
        let agent_name = format!("finance-agent-{suffix}");
        let tool_name = format!("refunds-api-{suffix}");
        let resource_name = format!("accounts_table-{suffix}");
        let unrelated_resource = format!("unrelated-resource-{suffix}");

        upsert_vertex(&pool, VertexLabel::Tool, &tool_name)
            .await
            .unwrap();
        upsert_vertex(&pool, VertexLabel::Resource, &resource_name)
            .await
            .unwrap();
        upsert_vertex(&pool, VertexLabel::Resource, &unrelated_resource)
            .await
            .unwrap();
        upsert_edge(
            &pool,
            VertexLabel::Tool,
            &tool_name,
            EdgeLabel::Accesses,
            VertexLabel::Resource,
            &resource_name,
        )
        .await
        .unwrap();

        let agent = AgentIdentity {
            name: agent_name.clone(),
            owner: "alice".to_string(),
            allowed_tools: vec![tool_name.clone()],
            allowed_apis: vec![],
            declared_scope: "process customer refunds".to_string(),
        };
        upsert_agent(&pool, &agent).await.unwrap();

        let reachable = reachable_from(&pool, &agent_name).await.unwrap();
        let names: Vec<&str> = reachable.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&tool_name.as_str()));
        assert!(names.contains(&resource_name.as_str()));
        assert!(!names.contains(&unrelated_resource.as_str()));

        let radius = blast_radius(&pool, &resource_name).await.unwrap();
        let radius_names: Vec<&str> = radius.iter().map(|n| n.name.as_str()).collect();
        assert!(radius_names.contains(&agent_name.as_str()));
        assert!(radius_names.contains(&tool_name.as_str()));
    }

    #[tokio::test]
    async fn wiring_an_agent_to_an_undiscovered_tool_fails() {
        let Some(pool) = test_pool_or_skip().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let suffix = unique_suffix();
        let agent = AgentIdentity {
            name: format!("ghost-agent-{suffix}"),
            owner: "bob".to_string(),
            allowed_tools: vec![format!("never-discovered-tool-{suffix}")],
            allowed_apis: vec![],
            declared_scope: "".to_string(),
        };
        let result = upsert_agent(&pool, &agent).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn upserting_an_mcp_server_records_its_discovered_tools() {
        let Some(pool) = test_pool_or_skip().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let suffix = unique_suffix();
        let server = DiscoveredMcpServer {
            config: crate::mcp::McpServerConfig {
                name: format!("fixture-mcp-{suffix}"),
                command: "python3".to_string(),
                args: vec![],
                env_keys: vec![],
            },
            tools: ToolDiscoveryResult::Tools(vec![
                "list_refunds".to_string(),
                "process_refund".to_string(),
            ]),
        };

        upsert_mcp_server(&pool, &server).await.unwrap();

        let query = format!(
            "SELECT (t)::text AS tools, (s)::text AS status FROM cypher('{GRAPH_NAME}', $$
                MATCH (n:Tool {{name: {name_lit}}}) RETURN n.tools, n.status
            $$) as (t agtype, s agtype)",
            name_lit = cypher_string(&server.config.name).unwrap(),
        );
        let row = sqlx::query(&query).fetch_one(&pool).await.unwrap();
        let tools: String = row.try_get("tools").unwrap();
        let status: String = row.try_get("status").unwrap();
        assert_eq!(tools, "list_refunds,process_refund");
        assert_eq!(status, "discovered");
    }

    #[tokio::test]
    async fn cypher_string_rejects_newlines_but_escapes_quotes() {
        assert!(cypher_string("has\nnewline").is_err());
        assert_eq!(cypher_string(r#"say "hi""#).unwrap(), r#""say \"hi\"""#);
    }
}

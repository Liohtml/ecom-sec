//! Thin MySQL/MariaDB helper shared by self-hosted adapters.  Connections are
//! opened lazily and read-only statements are used exclusively.

use mysql::prelude::Queryable;
use mysql::{Conn, OptsBuilder, Row, Value};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("database connection failed: {0}")]
    Connect(String),
    #[error("query failed: {0}")]
    Query(String),
    /// The statement was refused by the read-only guard.
    #[error("Abfrage abgelehnt: {0}")]
    Rejected(String),
}

/// Credentials parsed from a shop configuration file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DbCredentials {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub user: String,
    pub password: String,
    pub database: String,
    #[serde(default)]
    pub socket: Option<String>,
}

impl DbCredentials {
    /// Parse a `mysql://user:pass@host:port/db` style URL (Shopware, Symfony).
    pub fn from_url(url: &str) -> Option<Self> {
        let rest = url
            .strip_prefix("mysql://")
            .or_else(|| url.strip_prefix("mysql2://"))
            .or_else(|| url.strip_prefix("mariadb://"))?;
        let (auth, hostpart) = rest.rsplit_once('@')?;
        let (user, password) = auth.split_once(':').unwrap_or((auth, ""));
        let (hostport, dbq) = hostpart.split_once('/').unwrap_or((hostpart, ""));
        let database = dbq.split('?').next().unwrap_or("").to_string();
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()),
            None => (hostport.to_string(), None),
        };
        Some(DbCredentials {
            host,
            port,
            user: percent_decode(user),
            password: percent_decode(password),
            database,
            socket: None,
        })
    }

    pub fn connect(&self) -> Result<Conn, DbError> {
        let mut builder = OptsBuilder::new()
            .user(Some(self.user.clone()))
            .pass(Some(self.password.clone()))
            .db_name(Some(self.database.clone()))
            .read_timeout(Some(Duration::from_secs(20)))
            .write_timeout(Some(Duration::from_secs(20)))
            .tcp_connect_timeout(Some(Duration::from_secs(10)));
        if let Some(sock) = &self.socket {
            builder = builder.socket(Some(sock.clone()));
        } else {
            builder = builder
                .ip_or_hostname(Some(self.host.clone()))
                .tcp_port(self.port.unwrap_or(3306));
        }
        Conn::new(builder).map_err(|e| DbError::Connect(sanitize(&e.to_string(), &self.password)))
    }

    /// Masked display string for reports.
    pub fn display(&self) -> String {
        format!(
            "{}@{}{}/{}",
            self.user,
            self.socket.as_deref().unwrap_or(&self.host),
            self.port.map(|p| format!(":{p}")).unwrap_or_default(),
            self.database
        )
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn sanitize(msg: &str, secret: &str) -> String {
    if secret.is_empty() {
        msg.to_string()
    } else {
        msg.replace(secret, "***")
    }
}

/// Run a query and return rows as string maps (NULL → empty).
pub fn query_rows(conn: &mut Conn, sql: &str) -> Result<Vec<Vec<(String, String)>>, DbError> {
    let rows: Vec<Row> = conn.query(sql).map_err(|e| DbError::Query(e.to_string()))?;
    Ok(rows.into_iter().map(row_to_pairs).collect())
}

/// Check if a table exists in the current schema.
pub fn table_exists(conn: &mut Conn, table: &str) -> Result<bool, DbError> {
    let sql = format!(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = '{}'",
        table.replace('\'', "")
    );
    let n: Option<u64> = conn
        .query_first(sql)
        .map_err(|e| DbError::Query(e.to_string()))?;
    Ok(n.unwrap_or(0) > 0)
}

/// Column names of a table (lower-case).
pub fn columns(conn: &mut Conn, table: &str) -> Result<Vec<String>, DbError> {
    let sql = format!(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = '{}'",
        table.replace('\'', "")
    );
    let cols: Vec<String> = conn.query(sql).map_err(|e| DbError::Query(e.to_string()))?;
    Ok(cols.into_iter().map(|c| c.to_ascii_lowercase()).collect())
}

fn row_to_pairs(row: Row) -> Vec<(String, String)> {
    let columns = row.columns();
    let mut out = Vec::with_capacity(columns.len());
    for (i, col) in columns.iter().enumerate() {
        let value = match row.as_ref(i) {
            Some(Value::NULL) | None => String::new(),
            Some(Value::Bytes(b)) => String::from_utf8_lossy(b).to_string(),
            Some(Value::Int(v)) => v.to_string(),
            Some(Value::UInt(v)) => v.to_string(),
            Some(Value::Float(v)) => v.to_string(),
            Some(Value::Double(v)) => v.to_string(),
            Some(Value::Date(y, m, d, h, mi, s, _)) => {
                format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}")
            }
            Some(Value::Time(neg, d, h, m, s, _)) => {
                format!(
                    "{}{}:{:02}:{:02}",
                    if *neg { "-" } else { "" },
                    d * 24 + *h as u32,
                    m,
                    s
                )
            }
        };
        out.push((col.name_str().to_string(), value));
    }
    out
}

/// Helper to fetch a column from a row returned by [`query_rows`].
pub fn col<'a>(row: &'a [(String, String)], name: &str) -> &'a str {
    row.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

// ------------------------------------------------------------------ read-only guard

/// Maximum number of rows a guarded read-only query may return.
pub const READ_ONLY_MAX_ROWS: usize = 200;
/// Server-side execution limit of a guarded read-only query.
pub const READ_ONLY_TIMEOUT: Duration = Duration::from_secs(20);
/// Maximum length of a guarded statement.
pub const READ_ONLY_MAX_LEN: usize = 4000;

/// Keywords and functions that must never appear in a guarded statement
/// (outside of string literals).  Deliberately broad: a false rejection is
/// cheap, a write is not.
const FORBIDDEN: &str = r"(?i)\b(INSERT|UPDATE|DELETE|REPLACE|UPSERT|MERGE|DROP|ALTER|CREATE|TRUNCATE|RENAME|GRANT|REVOKE|SET|CALL|DO|HANDLER|LOAD|LOCK|UNLOCK|INTO|OUTFILE|DUMPFILE|LOAD_FILE|SHARE|SLEEP|BENCHMARK|GET_LOCK|RELEASE_LOCK|RELEASE_ALL_LOCKS|PREPARE|EXECUTE|DEALLOCATE|KILL|SHUTDOWN|FLUSH|RESET|PURGE|INSTALL|UNINSTALL|ANALYZE|OPTIMIZE|REPAIR|CHECKSUM|BINLOG|CACHE|SYS_EXEC|SYS_EVAL|NEXTVAL|SETVAL|LASTVAL|START|BEGIN|COMMIT|ROLLBACK|SAVEPOINT|XA)\b";

/// Replace string literals and quoted identifiers by placeholders so that the
/// keyword checks only see SQL structure.
fn sql_skeleton(sql: &str) -> Result<String, DbError> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' || c == '`' {
            let quote = c;
            i += 1;
            let mut closed = false;
            while i < chars.len() {
                let d = chars[i];
                if d == '\\' && quote != '`' {
                    i += 2;
                    continue;
                }
                if d == quote {
                    if i + 1 < chars.len() && chars[i + 1] == quote {
                        i += 2;
                        continue;
                    }
                    closed = true;
                    i += 1;
                    break;
                }
                i += 1;
            }
            if !closed {
                return Err(DbError::Rejected(
                    "nicht geschlossenes Anführungszeichen".into(),
                ));
            }
            out.push_str(if quote == '`' { " ident " } else { " 'lit' " });
        } else {
            out.push(c);
            i += 1;
        }
    }
    Ok(out)
}

/// Validate a statement for strictly read-only execution and return the
/// statement that may be executed.
///
/// Rules: a single `SELECT`, `SHOW` or `DESCRIBE`/`DESC` statement, no
/// comments, no variable assignment, none of the keywords in a broad deny
/// list (writes, locks, `INTO OUTFILE`, `SLEEP`, transactions …).  `SELECT`
/// statements get `LIMIT 200` appended when they have no trailing `LIMIT`; an
/// explicit trailing `LIMIT` above 200 is rejected.
pub fn guard_read_only_sql(sql: &str) -> Result<String, DbError> {
    let trimmed = sql.trim().trim_end_matches(';').trim_end();
    if trimmed.is_empty() {
        return Err(DbError::Rejected("leere Abfrage".into()));
    }
    if trimmed.len() > READ_ONLY_MAX_LEN {
        return Err(DbError::Rejected(format!(
            "Abfrage länger als {READ_ONLY_MAX_LEN} Zeichen"
        )));
    }
    let skeleton = sql_skeleton(trimmed)?;
    if skeleton.contains("--") || skeleton.contains('#') || skeleton.contains("/*") {
        return Err(DbError::Rejected("Kommentare sind nicht erlaubt".into()));
    }
    if skeleton.contains(';') {
        return Err(DbError::Rejected(
            "nur eine einzelne Anweisung ist erlaubt".into(),
        ));
    }
    if skeleton.contains(":=") {
        return Err(DbError::Rejected(
            "Variablenzuweisungen sind nicht erlaubt".into(),
        ));
    }
    let first = skeleton
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    let is_select = first == "SELECT";
    if !matches!(first.as_str(), "SELECT" | "SHOW" | "DESCRIBE" | "DESC") {
        return Err(DbError::Rejected(format!(
            "nur SELECT, SHOW und DESCRIBE sind erlaubt (gefunden: {first})"
        )));
    }
    let forbidden = regex::Regex::new(FORBIDDEN).expect("valid regex");
    if let Some(m) = forbidden.find(&skeleton) {
        return Err(DbError::Rejected(format!(
            "Schlüsselwort {} ist nicht erlaubt",
            m.as_str().to_ascii_uppercase()
        )));
    }
    if !is_select {
        return Ok(trimmed.to_string());
    }
    let limit = regex::Regex::new(r"(?i)\bLIMIT\s+(\d+)(?:\s*,\s*(\d+)|\s+OFFSET\s+\d+)?\s*$")
        .expect("valid regex");
    match limit.captures(&skeleton) {
        Some(c) => {
            let count: u64 = c
                .get(2)
                .or_else(|| c.get(1))
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(u64::MAX);
            if count > READ_ONLY_MAX_ROWS as u64 {
                return Err(DbError::Rejected(format!(
                    "LIMIT {count} überschreitet das Maximum von {READ_ONLY_MAX_ROWS} Zeilen"
                )));
            }
            Ok(trimmed.to_string())
        }
        None => Ok(format!("{trimmed} LIMIT {READ_ONLY_MAX_ROWS}")),
    }
}

/// Execute a statement after [`guard_read_only_sql`] inside a read-only
/// transaction with a server-side time limit (MySQL `MAX_EXECUTION_TIME`,
/// MariaDB `max_statement_time`) and the 20 s socket timeouts of
/// [`DbCredentials::connect`].  At most [`READ_ONLY_MAX_ROWS`] rows are
/// returned.
pub fn query_read_only(
    creds: &DbCredentials,
    sql: &str,
) -> Result<Vec<Vec<(String, String)>>, DbError> {
    let statement = guard_read_only_sql(sql)?;
    let mut conn = creds.connect()?;
    let ms = READ_ONLY_TIMEOUT.as_millis();
    // Best effort: not every server version knows every variable.
    let _ = conn.query_drop("SET SESSION TRANSACTION READ ONLY");
    let _ = conn.query_drop(format!("SET SESSION MAX_EXECUTION_TIME={ms}"));
    let _ = conn.query_drop(format!(
        "SET SESSION max_statement_time={}",
        READ_ONLY_TIMEOUT.as_secs()
    ));
    let _ = conn.query_drop("START TRANSACTION READ ONLY");
    let result = query_rows(&mut conn, &statement);
    let _ = conn.query_drop("ROLLBACK");
    let mut rows = result.map_err(|e| match e {
        DbError::Query(m) => DbError::Query(sanitize(&m, &creds.password)),
        other => other,
    })?;
    rows.truncate(READ_ONLY_MAX_ROWS);
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_guard_accepts_queries_and_enforces_limit() {
        assert_eq!(
            guard_read_only_sql("SELECT cLogin FROM tadminlogin").unwrap(),
            "SELECT cLogin FROM tadminlogin LIMIT 200"
        );
        assert_eq!(
            guard_read_only_sql("select * from tplugin limit 10;").unwrap(),
            "select * from tplugin limit 10"
        );
        assert!(guard_read_only_sql("SELECT * FROM t LIMIT 5, 50").is_ok());
        assert!(guard_read_only_sql("SHOW TABLES").is_ok());
        assert!(guard_read_only_sql("DESCRIBE tadminlogin").is_ok());
        // Keywords inside string literals are fine.
        assert!(guard_read_only_sql(
            "SELECT * FROM temailhistory WHERE cBetreff LIKE '%update; drop%'"
        )
        .is_ok());
        // Subquery LIMIT does not count as the outer LIMIT.
        assert!(guard_read_only_sql("SELECT * FROM (SELECT 1 LIMIT 1) x")
            .unwrap()
            .ends_with("LIMIT 200"));
    }

    #[test]
    fn read_only_guard_rejects_writes_and_tricks() {
        for sql in [
            "",
            "DELETE FROM tadminlogin",
            "UPDATE tadminlogin SET cPass = 'x'",
            "SELECT 1; DROP TABLE x",
            "SELECT * FROM t LIMIT 1000",
            "SELECT * FROM t INTO OUTFILE '/tmp/x'",
            "SELECT LOAD_FILE('/etc/passwd')",
            "SELECT SLEEP(100)",
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t LOCK IN SHARE MODE",
            "SELECT 1 /*! ; DROP TABLE t */",
            "SELECT 1 -- x",
            "SELECT @a := 1",
            "SET SESSION sql_mode = ''",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "EXPLAIN SELECT 1",
            "SELECT 'unterminated",
            "CALL p()",
        ] {
            assert!(guard_read_only_sql(sql).is_err(), "should reject {sql:?}");
        }
    }

    #[test]
    fn parses_database_url() {
        let c =
            DbCredentials::from_url("mysql://shop:p%40ss@db.local:3307/shopware?serverVersion=8")
                .unwrap();
        assert_eq!(c.user, "shop");
        assert_eq!(c.password, "p@ss");
        assert_eq!(c.host, "db.local");
        assert_eq!(c.port, Some(3307));
        assert_eq!(c.database, "shopware");
        assert!(DbCredentials::from_url("postgres://x").is_none());
    }
}

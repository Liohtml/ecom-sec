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

#[cfg(test)]
mod tests {
    use super::*;

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

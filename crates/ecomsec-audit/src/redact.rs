//! Secret redaction for everything that is sent to the model.
//!
//! Tool output (file excerpts, grep hits, database rows, finding evidence)
//! passes through [`redact`] before it leaves the machine.  Configuration
//! files that hold credentials (`includes/config.JTL-Shop.ini.php`, `.env*`,
//! …) are redacted in strict mode, where every value except a small list of
//! harmless keys is masked; key files (`*.pem`, `.htpasswd`, …) are withheld
//! completely.

use base64::Engine as _;
use ecomsec_core::util::{mask, mask_email};
use regex::{Captures, Regex};
use std::sync::OnceLock;

/// Result of a redaction pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted {
    pub text: String,
    /// Number of masked values.
    pub count: usize,
}

/// How a file must be treated before its content is shown to the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    Normal,
    /// Configuration with credentials: mask every value except harmless keys.
    Strict,
    /// Key material / password files: never show the content.
    Withhold,
}

/// Classify a path (relative to the shop root).
pub fn path_sensitivity(rel: &str) -> Sensitivity {
    let lower = rel.replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let withhold_ext = [
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".crt",
        ".der",
        ".kdbx",
    ];
    if withhold_ext.iter().any(|e| name.ends_with(e))
        || matches!(
            name,
            ".htpasswd" | "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa" | ".git-credentials"
        )
    {
        return Sensitivity::Withhold;
    }
    if lower.ends_with("config.jtl-shop.ini.php")
        || name == ".env"
        || name.starts_with(".env.")
        || matches!(
            name,
            "auth.json"
                | "parameters.yml"
                | "parameters.yaml"
                | "parameters.php"
                | "wp-config.php"
                | "env.php"
                | "local.xml"
                | ".npmrc"
                | ".pgpass"
                | ".my.cnf"
                | "my.cnf"
        )
        || lower.contains("config/secrets/")
        || lower.contains("config/jwt/")
    {
        return Sensitivity::Strict;
    }
    Sensitivity::Normal
}

struct Patterns {
    pem: Regex,
    define: Regex,
    kv_quoted: Regex,
    line_kv: Regex,
    url_creds: Regex,
    tokens: Regex,
    hashes: Regex,
    email: Regex,
    hex: Regex,
    b64: Regex,
    secret_name: Regex,
    safe_name: Regex,
    suspicious: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        pem: Regex::new(r"(?s)-----BEGIN ([A-Z0-9 ]+)-----.*?(?:-----END [A-Z0-9 ]+-----|\z)").unwrap(),
        define: Regex::new(
            r#"(?i)(define\s*\(\s*['"]([A-Za-z0-9_]+)['"]\s*,\s*)(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")"#,
        )
        .unwrap(),
        kv_quoted: Regex::new(
            r#"(?i)(["']?([A-Za-z0-9_.\-]*(?:password|passwd|passwort|kennwort|pwd|pass|secret|api[_\-]?key|apikey|access[_\-]?key|private[_\-]?key|auth[_\-]?key|token|salt|credentials?)[A-Za-z0-9_.\-]*)["']?\s*(?:=>|:|=)\s*)(?:'([^'\r\n]{3,})'|"([^"\r\n]{3,})")"#,
        )
        .unwrap(),
        line_kv: Regex::new(r"(?m)^([ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*[=:][ \t]*)([^\r\n]*)$").unwrap(),
        url_creds: Regex::new(r#"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@'"]+:)([^\s@'"/]+)@"#).unwrap(),
        tokens: Regex::new(concat!(
            r"\b(?:shp(?:at|ss|ca|pa|ua)_[A-Fa-f0-9]{16,}",
            r"|sk-ant-[A-Za-z0-9_\-]{10,}",
            r"|(?:AKIA|ASIA)[0-9A-Z]{16}",
            r"|gh[pousr]_[A-Za-z0-9]{20,}",
            r"|github_pat_[A-Za-z0-9_]{20,}",
            r"|xox[abprs]-[A-Za-z0-9\-]{10,}",
            r"|[rs]k_(?:live|test)_[A-Za-z0-9]{10,}",
            r"|AIza[0-9A-Za-z_\-]{35}",
            r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"
        ))
        .unwrap(),
        hashes: Regex::new(concat!(
            r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}",
            r#"|\$argon2(?:id|i|d)\$[^\s'"]+"#,
            r#"|\$(?:1|5|6|apr1)\$[^\s'"$]*\$[^\s'"]+"#
        ))
        .unwrap(),
        email: Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap(),
        hex: Regex::new(r"\b[A-Fa-f0-9]{40,}\b").unwrap(),
        b64: Regex::new(r"[A-Za-z0-9+/]{60,}={0,2}").unwrap(),
        secret_name: Regex::new(
            r"(?i)(PASS|PWD|SECRET|KEY|TOKEN|SALT|AUTH|CRED|PRIVATE|SIGNATURE|DSN|DATABASE_URL)",
        )
        .unwrap(),
        safe_name: Regex::new(concat!(
            r"(?i)^(URL_SHOP|PFAD_ROOT|DB_HOST|DB_NAME|DB_SOCKET|DB_PORT|DB_USER|DB_CHARSET|",
            r"APP_ENV|APP_URL|APP_DEBUG|SHOPWARE_HTTP_CACHE_ENABLED|SHOPWARE_HTTP_DEFAULT_TTL|",
            r"SHOPWARE_ES_ENABLED|SHOPWARE_CDN_STRATEGY_DEFAULT|SHOPWARE_ADMINISTRATION_PATH_NAME|",
            r"COMPOSER_HOME|INSTANCE_ID|BLUE_GREEN_DEPLOYMENT|SHOP_LOG_LEVEL|JTL_CHARSET|",
            r"[A-Z0-9_]*_ENABLED|[A-Z0-9_]*_DEBUG|[A-Z0-9_]*_LEVEL)$"
        ))
        .unwrap(),
        suspicious: Regex::new(
            r"(?i)(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|base64_decode|gzinflate|gzuncompress|str_rot13|create_function|preg_replace|<\?php|<script|document\.write|atob|fromCharCode|\$_POST|\$_GET|\$_REQUEST|\$_COOKIE|fsockopen|curl_exec|file_put_contents|move_uploaded_file)",
        )
        .unwrap(),
    })
}

const MASK: &str = "[REDIGIERT]";

fn already_masked(value: &str) -> bool {
    value.contains(MASK) || value.contains("[REDIGIERT") || value.contains("***")
}

/// Redact with the default rules (any file, DB output, evidence).
pub fn redact(text: &str) -> Redacted {
    redact_with(text, false)
}

/// Redact a credentials file: every value except harmless keys is masked.
pub fn redact_strict(text: &str) -> Redacted {
    redact_with(text, true)
}

/// Redact according to the sensitivity of a path.  `Withhold` yields a
/// placeholder without content.
pub fn redact_for(sensitivity: Sensitivity, text: &str) -> Redacted {
    match sensitivity {
        Sensitivity::Normal => redact(text),
        Sensitivity::Strict => redact_strict(text),
        Sensitivity::Withhold => Redacted {
            text: format!(
                "[Inhalt zurückgehalten: Schlüssel-/Passwortdatei, {} Zeilen]",
                text.lines().count()
            ),
            count: 1,
        },
    }
}

/// Redact a database cell: values of columns whose name suggests a secret
/// (password hash, token, key …) or payment data are masked completely.
pub fn redact_cell(column: &str, value: &str) -> Redacted {
    static COL: OnceLock<Regex> = OnceLock::new();
    let col = COL.get_or_init(|| {
        Regex::new(r"(?i)(pass|pwd|secret|token|salt|hash|key|otp|2fa|totp|tfa|iban|bic|card|karte|cvc|cvv|credential|session)").unwrap()
    });
    if !value.is_empty() && col.is_match(column) {
        return Redacted {
            text: MASK.to_string(),
            count: 1,
        };
    }
    redact(value)
}

fn redact_with(text: &str, strict: bool) -> Redacted {
    let p = patterns();
    let mut count = 0usize;

    // PEM blocks (keep the number of lines so that line numbers stay valid).
    let out = p.pem.replace_all(text, |c: &Captures| {
        count += 1;
        let newlines = c[0].matches('\n').count();
        format!(
            "[REDIGIERT: PEM-Block {}]{}",
            c[1].trim(),
            "\n".repeat(newlines)
        )
    });

    // PHP define('NAME', 'value').
    let out = p.define.replace_all(&out, |c: &Captures| {
        let name = &c[2];
        let value = c
            .get(3)
            .or_else(|| c.get(4))
            .map(|m| m.as_str())
            .unwrap_or("");
        let secret = p.secret_name.is_match(name) || (strict && !p.safe_name.is_match(name));
        if secret && !value.is_empty() && !already_masked(value) {
            count += 1;
            format!("{}'{MASK}'", &c[1])
        } else {
            c[0].to_string()
        }
    });

    // 'password' => 'x', "apiKey": "x", token = "x".
    let out = p.kv_quoted.replace_all(&out, |c: &Captures| {
        let value = c
            .get(3)
            .or_else(|| c.get(4))
            .map(|m| m.as_str())
            .unwrap_or("");
        if already_masked(value) {
            return c[0].to_string();
        }
        count += 1;
        format!("{}'{MASK}'", &c[1])
    });

    // KEY=value lines (.env, ini, YAML).
    let out = p.line_kv.replace_all(&out, |c: &Captures| {
        let name = &c[2];
        let value = c[3].trim();
        if value.is_empty() || already_masked(value) {
            return c[0].to_string();
        }
        let mask_it = if strict {
            !p.safe_name.is_match(name)
        } else {
            // Outside of credential files only literal-looking values are
            // masked, so that code (`password: req.body.password,`) stays readable.
            p.secret_name.is_match(name)
                && !value.contains(|ch: char| ch.is_whitespace() || "$(){}[];,<>".contains(ch))
                && value.len() >= 4
        };
        if mask_it {
            count += 1;
            format!("{}{MASK}", &c[1])
        } else {
            c[0].to_string()
        }
    });

    // scheme://user:password@host
    let out = p.url_creds.replace_all(&out, |c: &Captures| {
        if already_masked(&c[2]) {
            return c[0].to_string();
        }
        count += 1;
        format!("{}{MASK}@", &c[1])
    });

    // Well-known token formats.
    let out = p.tokens.replace_all(&out, |c: &Captures| {
        count += 1;
        format!("[REDIGIERT: Token {}]", mask(&c[0]))
    });

    // Password hashes.
    let out = p.hashes.replace_all(&out, |_: &Captures| {
        count += 1;
        "[REDIGIERT: Passwort-Hash]".to_string()
    });

    // E-mail addresses (personal data).
    let out = p.email.replace_all(&out, |c: &Captures| {
        count += 1;
        mask_email(&c[0])
    });

    // Long hex strings (keys, salts, hashes).
    let out = p.hex.replace_all(&out, |c: &Captures| {
        count += 1;
        format!("[REDIGIERT: Hex-Wert, {} Zeichen]", c[0].len())
    });

    // Long base64 blobs: masked, with a hint whether the decoded content looks
    // like code (useful for malware triage without revealing the content).
    let out = p.b64.replace_all(&out, |c: &Captures| {
        let s = &c[0];
        let mixed = s.chars().any(|ch| ch.is_ascii_uppercase())
            && s.chars().any(|ch| ch.is_ascii_lowercase())
            && s.chars().any(|ch| ch.is_ascii_digit());
        if !mixed {
            return s.to_string();
        }
        count += 1;
        format!(
            "[REDIGIERT: Base64-Blob, {} Zeichen{}]",
            s.len(),
            describe_base64(s)
        )
    });

    Redacted {
        text: out.into_owned(),
        count,
    }
}

/// Short, content-free description of what a base64 blob decodes to.
fn describe_base64(s: &str) -> String {
    let trimmed = s.trim_end_matches('=');
    let usable = &trimmed[..trimmed.len() - trimmed.len() % 4];
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let Ok(bytes) = engine.decode(usable) else {
        return String::new();
    };
    let printable = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    if bytes.is_empty() || printable * 10 < bytes.len() * 9 {
        return "; dekodiert: binär/komprimiert".into();
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut hits: Vec<String> = patterns()
        .suspicious
        .find_iter(&text)
        .map(|m| m.as_str().to_ascii_lowercase())
        .collect();
    hits.sort();
    hits.dedup();
    if hits.is_empty() {
        "; dekodiert: Text ohne Code-Merkmale".into()
    } else {
        hits.truncate(8);
        format!("; dekodiert enthält: {}", hits.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jtl_config_is_redacted_strictly() {
        let cfg = "<?php\ndefine('URL_SHOP', 'https://demo.example');\ndefine('DB_HOST','127.0.0.1');\ndefine('DB_USER','shopuser');\ndefine('DB_PASS','Sup3rGeheim!');\ndefine('BLOWFISH_KEY', 'abcdefghijkl');\ndefine('SOME_OTHER', 'value123');\n";
        let r = redact_for(path_sensitivity("includes/config.JTL-Shop.ini.php"), cfg);
        assert!(!r.text.contains("Sup3rGeheim"), "{}", r.text);
        assert!(!r.text.contains("abcdefghijkl"));
        assert!(
            !r.text.contains("value123"),
            "strict mode masks unknown keys"
        );
        assert!(r.text.contains("https://demo.example"));
        assert!(r.text.contains("127.0.0.1"));
        // Default mode still masks the password define.
        let d = redact(cfg);
        assert!(!d.text.contains("Sup3rGeheim"));
        assert!(d.text.contains("value123"));
    }

    #[test]
    fn env_file_and_tokens_are_redacted() {
        // Built at run time so that no token-shaped literal is committed
        // (GitHub push protection would otherwise flag the test sample).
        let token = format!("shpat_{}", "0123456789abcdef".repeat(2));
        let env = format!(
            "APP_ENV=prod\nAPP_SECRET=0123456789abcdef0123\nDATABASE_URL=mysql://sw:pa55word@db:3306/sw\nMAILER_DSN=smtp://mail.example\nSHOPIFY_TOKEN={token}\n"
        );
        let r = redact_for(path_sensitivity(".env"), &env);
        assert!(r.text.contains("APP_ENV=prod"));
        assert!(!r.text.contains("0123456789abcdef0123"));
        assert!(!r.text.contains("pa55word"));
        assert!(!r.text.contains(&token));
        // Outside .env: URL credentials and Shopify tokens are still masked.
        let code = format!("$url = 'mysql://sw:pa55word@db/sw'; $t = '{token}';");
        let c = redact(&code);
        assert!(!c.text.contains("pa55word"), "{}", c.text);
        assert!(!c.text.contains("0123456789abcdef0123456789abcdef"));
        assert!(c.count >= 2);
    }

    #[test]
    fn pem_hashes_blobs_and_emails() {
        let pem = "a\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabc\n-----END PRIVATE KEY-----\nb";
        let r = redact(pem);
        assert!(!r.text.contains("MIIEvQ"));
        assert_eq!(
            r.text.lines().count(),
            pem.lines().count(),
            "line count kept"
        );

        let php = r#"$cfg = ['password' => 'hunter2!', 'user' => 'bob']; $h = '$2y$10$abcdefghijklmnopqrstuuJ0123456789ABCDEFGHIJKLMNOPQRSTU';"#;
        let r = redact(php);
        assert!(!r.text.contains("hunter2"), "{}", r.text);
        assert!(r.text.contains("'bob'"));
        assert!(r.text.contains("Passwort-Hash"));

        let payload = "eval(base64_decode('PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgc3lzdGVtKCRfR0VUWyd4J10pOyA/Pg=='));";
        let r = redact(payload);
        assert!(r.text.contains("Base64-Blob"), "{}", r.text);
        assert!(r.text.contains("dekodiert enthält"), "{}", r.text);
        assert!(r.text.contains("eval"));

        let r = redact("Kontakt: max.mustermann@example.com");
        assert!(!r.text.contains("max.mustermann"));

        let r = redact("salt = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
        assert!(!r.text.contains("9f86d081884c7d65"));
    }

    #[test]
    fn code_stays_readable() {
        let code = "  password: req.body.password,\n$sql = \"SELECT * FROM user WHERE id = \" . $_GET['id'];\n";
        let r = redact(code);
        assert_eq!(r.text, code);
        assert_eq!(r.count, 0);
    }

    #[test]
    fn key_files_are_withheld_and_cells_masked() {
        assert_eq!(
            path_sensitivity("config/jwt/private.pem"),
            Sensitivity::Withhold
        );
        assert_eq!(path_sensitivity("admin/.htpasswd"), Sensitivity::Withhold);
        assert_eq!(path_sensitivity(".env.local"), Sensitivity::Strict);
        assert_eq!(path_sensitivity("plugins/x/y.php"), Sensitivity::Normal);
        let r = redact_for(Sensitivity::Withhold, "secret\nkey");
        assert!(!r.text.contains("secret"));
        assert_eq!(redact_cell("cPass", "abc").text, "[REDIGIERT]");
        assert_eq!(redact_cell("cLogin", "admin").text, "admin");
    }
}

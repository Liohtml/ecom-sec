//! Small helpers shared across the workspace.

use std::path::Path;

/// Display a path relative to `root` using forward slashes.
pub fn relative_display(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let s = rel.to_string_lossy().replace('\\', "/");
    if s.is_empty() {
        ".".to_string()
    } else {
        s
    }
}

/// Mask a secret for display: keeps the first and last two characters.
pub fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    match chars.len() {
        0 => String::new(),
        1..=4 => "*".repeat(chars.len()),
        n => {
            let head: String = chars[..2].iter().collect();
            let tail: String = chars[n - 2..].iter().collect();
            format!("{head}{}{tail}", "*".repeat(n - 4))
        }
    }
}

/// Mask an e-mail address: `jo***@ex***.de`.
pub fn mask_email(value: &str) -> String {
    match value.split_once('@') {
        Some((local, domain)) => {
            let (dom, tld) = domain.rsplit_once('.').unwrap_or((domain, ""));
            let l = local.chars().take(2).collect::<String>();
            let d = dom.chars().take(2).collect::<String>();
            if tld.is_empty() {
                format!("{l}***@{d}***")
            } else {
                format!("{l}***@{d}***.{tld}")
            }
        }
        None => mask(value),
    }
}

/// Truncate a string for evidence output, making control characters visible.
pub fn excerpt(input: &str, max: usize) -> String {
    let cleaned: String = input
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.chars().count() <= max {
        cleaned
    } else {
        let mut out: String = cleaned.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// SHA-256 hex digest of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Format a byte count.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_values() {
        assert_eq!(mask("abcdef"), "ab**ef");
        assert_eq!(mask("abc"), "***");
        assert_eq!(mask_email("john.doe@example.com"), "jo***@ex***.com");
    }

    #[test]
    fn relative_paths() {
        assert_eq!(
            relative_display(Path::new("/srv/shop"), Path::new("/srv/shop/admin/x.php")),
            "admin/x.php"
        );
        assert_eq!(
            relative_display(Path::new("/srv/shop"), Path::new("/srv/shop")),
            "."
        );
    }
}

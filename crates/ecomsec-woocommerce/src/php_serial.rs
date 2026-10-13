//! Minimal, tolerant parser for PHP's `serialize()` format as stored by
//! WordPress in `wp_options` / `wp_usermeta` (capabilities, active plugins,
//! cron, payment gateway settings, session tokens).
//!
//! Only data is decoded – objects become [`PhpValue::Object`] with their
//! properties, nothing is ever instantiated.  String lengths are byte
//! lengths as in PHP.

#[derive(Debug, Clone, PartialEq)]
pub enum PhpValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<(PhpValue, PhpValue)>),
    Object(String, Vec<(PhpValue, PhpValue)>),
}

impl PhpValue {
    /// String representation of scalars (keys and values).
    pub fn as_string(&self) -> String {
        match self {
            PhpValue::Null => String::new(),
            PhpValue::Bool(b) => if *b { "1" } else { "" }.to_string(),
            PhpValue::Int(i) => i.to_string(),
            PhpValue::Float(f) => f.to_string(),
            PhpValue::Str(s) => s.clone(),
            PhpValue::Array(_) | PhpValue::Object(..) => String::new(),
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            PhpValue::Int(i) => Some(*i),
            PhpValue::Str(s) => s.trim().parse().ok(),
            PhpValue::Float(f) => Some(*f as i64),
            PhpValue::Bool(b) => Some(*b as i64),
            _ => None,
        }
    }

    pub fn truthy(&self) -> bool {
        match self {
            PhpValue::Null => false,
            PhpValue::Bool(b) => *b,
            PhpValue::Int(i) => *i != 0,
            PhpValue::Float(f) => *f != 0.0,
            PhpValue::Str(s) => !s.is_empty() && s != "0",
            PhpValue::Array(a) | PhpValue::Object(_, a) => !a.is_empty(),
        }
    }

    /// Entries of an array or object.
    pub fn entries(&self) -> &[(PhpValue, PhpValue)] {
        match self {
            PhpValue::Array(a) | PhpValue::Object(_, a) => a,
            _ => &[],
        }
    }

    /// Value for a string/int key.
    pub fn get(&self, key: &str) -> Option<&PhpValue> {
        self.entries()
            .iter()
            .find(|(k, _)| k.as_string() == key)
            .map(|(_, v)| v)
    }
}

/// Parse a serialized value.  Returns `None` for anything that is not valid
/// serialized data (plain option strings, JSON, …).
pub fn unserialize(input: &str) -> Option<PhpValue> {
    let bytes = input.trim().as_bytes();
    let mut p = Parser { b: bytes, i: 0 };
    let v = p.value(0)?;
    Some(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn expect(&mut self, c: u8) -> Option<()> {
        if self.peek()? == c {
            self.i += 1;
            Some(())
        } else {
            None
        }
    }

    fn until(&mut self, c: u8) -> Option<&str> {
        let start = self.i;
        while self.peek()? != c {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).ok()?;
        self.i += 1;
        Some(s)
    }

    fn value(&mut self, depth: usize) -> Option<PhpValue> {
        if depth > 64 {
            return None;
        }
        let tag = self.peek()?;
        self.i += 1;
        match tag {
            b'N' => {
                self.expect(b';')?;
                Some(PhpValue::Null)
            }
            b'b' => {
                self.expect(b':')?;
                let v = self.until(b';')?;
                Some(PhpValue::Bool(v == "1"))
            }
            b'i' => {
                self.expect(b':')?;
                let v = self.until(b';')?;
                Some(PhpValue::Int(v.trim().parse().ok()?))
            }
            b'd' => {
                self.expect(b':')?;
                let v = self.until(b';')?;
                Some(PhpValue::Float(v.trim().parse().unwrap_or(0.0)))
            }
            b's' => {
                self.expect(b':')?;
                let len: usize = self.until(b':')?.parse().ok()?;
                self.expect(b'"')?;
                let end = self.i.checked_add(len)?;
                let raw = self.b.get(self.i..end)?;
                let s = String::from_utf8_lossy(raw).to_string();
                self.i = end;
                self.expect(b'"')?;
                self.expect(b';')?;
                Some(PhpValue::Str(s))
            }
            b'a' => {
                self.expect(b':')?;
                let n: usize = self.until(b':')?.parse().ok()?;
                let entries = self.entries(n, depth)?;
                Some(PhpValue::Array(entries))
            }
            b'O' => {
                self.expect(b':')?;
                let len: usize = self.until(b':')?.parse().ok()?;
                self.expect(b'"')?;
                let end = self.i.checked_add(len)?;
                let class = String::from_utf8_lossy(self.b.get(self.i..end)?).to_string();
                self.i = end;
                self.expect(b'"')?;
                self.expect(b':')?;
                let n: usize = self.until(b':')?.parse().ok()?;
                let entries = self.entries(n, depth)?;
                Some(PhpValue::Object(class, entries))
            }
            _ => None,
        }
    }

    fn entries(&mut self, n: usize, depth: usize) -> Option<Vec<(PhpValue, PhpValue)>> {
        self.expect(b'{')?;
        let mut out = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            let k = self.value(depth + 1)?;
            let v = self.value(depth + 1)?;
            out.push((k, v));
        }
        self.expect(b'}')?;
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_capabilities() {
        let v = unserialize(r#"a:2:{s:13:"administrator";b:1;s:12:"shop_manager";b:0;}"#).unwrap();
        assert!(v.get("administrator").unwrap().truthy());
        assert!(!v.get("shop_manager").unwrap().truthy());
    }

    #[test]
    fn parses_nested_and_utf8() {
        let v = unserialize(
            r#"a:3:{i:0;s:27:"woocommerce/woocommerce.php";s:5:"näme";s:3:"x;y";s:1:"n";a:1:{s:1:"f";d:1.5;}}"#,
        )
        .unwrap();
        assert_eq!(v.entries()[0].1.as_string(), "woocommerce/woocommerce.php");
        assert_eq!(v.get("näme").unwrap().as_string(), "x;y");
        assert_eq!(v.get("n").unwrap().get("f"), Some(&PhpValue::Float(1.5)));
    }

    #[test]
    fn rejects_plain_strings() {
        assert!(unserialize("https://example.com").is_none());
        assert!(unserialize(r#"a:1:{s:5:"x";}"#).is_none());
    }
}

//! Verification of [minisign](https://jedisct1.github.io/minisign/) signatures.
//!
//! Release archives are authenticated by a minisign signature over
//! `SHA256SUMS` (prehashed BLAKE2b-512, the minisign default since the
//! `ED` algorithm id). The public key is embedded from `distrib/minisign.pub`
//! so a replaced release asset cannot swap the key.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signature, VerifyingKey};

/// Public key file checked into the repository (`distrib/minisign.pub`).
const PUB_FILE: &str = include_str!("../../../distrib/minisign.pub");

const COMMENT_PREFIX: &str = "untrusted comment: ";
const TRUSTED_PREFIX: &str = "trusted comment: ";
const ALG_LEGACY: &[u8] = b"Ed";
const ALG_HASHED: &[u8] = b"ED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    PublicKey,
    SignatureFile,
    KeyId,
    Signature,
    Comment,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VerifyError::PublicKey => "öffentlicher minisign-Schlüssel ist ungültig",
            VerifyError::SignatureFile => "Signaturdatei ist unvollständig oder beschädigt",
            VerifyError::KeyId => {
                "Schlüssel-ID der Signatur passt nicht zum öffentlichen Schlüssel"
            }
            VerifyError::Signature => "Signatur ist ungültig",
            VerifyError::Comment => "Signatur des vertrauenswürdigen Kommentars ist ungültig",
        })
    }
}

impl std::error::Error for VerifyError {}

/// `true` while `distrib/minisign.pub` is still the committed placeholder.
/// Install and self-update refuse to run in that state.
pub fn is_placeholder() -> bool {
    PUB_FILE
        .lines()
        .next()
        .unwrap_or("")
        .contains("PLACEHOLDER")
}

/// Base64 public key (the key line of `distrib/minisign.pub`).
pub fn embedded_public_key() -> &'static str {
    pub_file_key(PUB_FILE).expect("distrib/minisign.pub enthält keinen Schlüssel")
}

fn pub_file_key(text: &str) -> Option<&str> {
    text.lines()
        .map(|l| l.trim_end_matches('\r').trim())
        .find(|l| !l.is_empty() && !l.starts_with(COMMENT_PREFIX))
}

/// Verify `message` against a minisign signature file and a base64 public key.
///
/// Accepts prehashed signatures (`ED`, BLAKE2b-512 of the file) and legacy
/// signatures over the raw file (`Ed`). The trusted comment is checked too;
/// a valid file signature with a broken comment signature is rejected.
pub fn verify(
    public_key_b64: &str,
    signature_text: &str,
    message: &[u8],
) -> Result<(), VerifyError> {
    let (key_id, verifying_key) = parse_public_key(public_key_b64)?;
    let parsed = parse_signature(signature_text)?;
    if parsed.key_id != key_id {
        return Err(VerifyError::KeyId);
    }
    let signed_message: Vec<u8> = if parsed.prehashed {
        Blake2b512::digest(message).to_vec()
    } else {
        message.to_vec()
    };
    verifying_key
        .verify_strict(&signed_message, &parsed.signature)
        .map_err(|_| VerifyError::Signature)?;
    let mut comment_message = parsed.signature.to_bytes().to_vec();
    comment_message.extend_from_slice(parsed.trusted_comment.as_bytes());
    verifying_key
        .verify_strict(&comment_message, &parsed.global_signature)
        .map_err(|_| VerifyError::Comment)?;
    Ok(())
}

struct ParsedSig {
    prehashed: bool,
    key_id: [u8; 8],
    signature: Signature,
    trusted_comment: String,
    global_signature: Signature,
}

fn parse_public_key(text: &str) -> Result<([u8; 8], VerifyingKey), VerifyError> {
    let raw = decode_b64(text.trim())?;
    if raw.len() != 42 || &raw[..2] != ALG_LEGACY {
        return Err(VerifyError::PublicKey);
    }
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&raw[2..10]);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[10..42]);
    let verifying_key = VerifyingKey::from_bytes(&pk).map_err(|_| VerifyError::PublicKey)?;
    Ok((key_id, verifying_key))
}

fn parse_signature(text: &str) -> Result<ParsedSig, VerifyError> {
    let lines: Vec<&str> = text
        .split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() != 4
        || !lines[0].starts_with(COMMENT_PREFIX)
        || !lines[2].starts_with(TRUSTED_PREFIX)
    {
        return Err(VerifyError::SignatureFile);
    }
    let raw = decode_b64(lines[1])?;
    if raw.len() != 74 {
        return Err(VerifyError::SignatureFile);
    }
    let prehashed = if &raw[..2] == ALG_HASHED {
        true
    } else if &raw[..2] == ALG_LEGACY {
        false
    } else {
        return Err(VerifyError::SignatureFile);
    };
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&raw[2..10]);
    let signature = Signature::from_slice(&raw[10..74]).map_err(|_| VerifyError::SignatureFile)?;
    let global = decode_b64(lines[3])?;
    if global.len() != 64 {
        return Err(VerifyError::SignatureFile);
    }
    let global_signature =
        Signature::from_slice(&global).map_err(|_| VerifyError::SignatureFile)?;
    Ok(ParsedSig {
        prehashed,
        key_id,
        signature,
        trusted_comment: lines[2][TRUSTED_PREFIX.len()..].to_string(),
        global_signature,
    })
}

fn decode_b64(text: &str) -> Result<Vec<u8>, VerifyError> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut padded = compact;
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    STANDARD
        .decode(padded.as_bytes())
        .map_err(|_| VerifyError::SignatureFile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_key() -> String {
        let text = include_str!("../fixtures/minisign/minisign.pub");
        pub_file_key(text).unwrap().to_string()
    }

    #[test]
    fn official_prehashed_signature_verifies() {
        let key = fixture_key();
        let sig = include_str!("../fixtures/minisign/SHA256SUMS.minisig");
        let msg = include_bytes!("../fixtures/minisign/SHA256SUMS");
        verify(&key, sig, msg).unwrap();
    }

    #[test]
    fn official_legacy_signature_verifies() {
        let key = fixture_key();
        let sig = include_str!("../fixtures/minisign/legacy.txt.minisig");
        let msg = include_bytes!("../fixtures/minisign/legacy.txt");
        verify(&key, sig, msg).unwrap();
    }

    #[test]
    fn manipulated_message_is_rejected() {
        let key = fixture_key();
        let sig = include_str!("../fixtures/minisign/SHA256SUMS.minisig");
        let mut msg = include_bytes!("../fixtures/minisign/SHA256SUMS").to_vec();
        msg[0] ^= 0xff;
        assert_eq!(verify(&key, sig, &msg), Err(VerifyError::Signature));
    }

    #[test]
    fn manipulated_trusted_comment_is_rejected() {
        let key = fixture_key();
        let sig = include_str!("../fixtures/minisign/SHA256SUMS.minisig");
        let msg = include_bytes!("../fixtures/minisign/SHA256SUMS");
        let tampered = sig.replace("trusted comment: fixture", "trusted comment: other");
        assert_ne!(tampered, sig);
        assert_eq!(verify(&key, &tampered, msg), Err(VerifyError::Comment));
    }

    #[test]
    fn wrong_public_key_is_rejected() {
        let sig = include_str!("../fixtures/minisign/SHA256SUMS.minisig");
        let msg = include_bytes!("../fixtures/minisign/SHA256SUMS");
        let err = verify(embedded_public_key(), sig, msg).unwrap_err();
        assert_eq!(err, VerifyError::KeyId);
    }

    #[test]
    fn truncated_signature_file_is_rejected() {
        let key = fixture_key();
        assert_eq!(
            verify(&key, "untrusted comment: x\n", b"data"),
            Err(VerifyError::SignatureFile)
        );
    }

    #[test]
    fn embedded_key_parses_and_placeholder_flag_matches_file() {
        parse_public_key(embedded_public_key()).unwrap();
        let comment = PUB_FILE.lines().next().unwrap();
        assert_eq!(is_placeholder(), comment.contains("PLACEHOLDER"));
    }

    #[test]
    fn installer_and_readme_embed_the_same_key() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let install = std::fs::read_to_string(root.join("install.sh")).unwrap();
        let readme = std::fs::read_to_string(root.join("README.md")).unwrap();
        let key = embedded_public_key();
        assert!(
            install.contains(&format!("MINISIGN_PUB='{key}'")),
            "install.sh"
        );
        assert!(readme.contains(key), "README.md");
        let flag = if is_placeholder() {
            "MINISIGN_PUB_IS_PLACEHOLDER=1"
        } else {
            "MINISIGN_PUB_IS_PLACEHOLDER=0"
        };
        assert!(install.contains(flag), "{flag}");
    }
}

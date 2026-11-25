//! The Vault-side confirmation surface (trusted-confirmation-surface.md).
//!
//! Tier implemented (ADR-012): macOS system dialog (system-owned chrome — no
//! web content, not theme/plugin/dapp-stylable) carrying a user-selected
//! secret phrase that only the Vault side can read. SEP/biometric binding is
//! the next tier, deferred with the ADR.
//!
//! Fail-closed rules, all enforced here:
//! - no phrase file, unreadable phrase file, or group/world-readable phrase
//!   file → refuse (a surface that cannot prove genuineness must not confirm);
//! - non-macOS platform → refuse (no lower-assurance fallback is silently
//!   substituted);
//! - dialog error, timeout, or dismissal → reject, never approve.
//!
//! `CIPHERLAYER_CONFIRM_AUTO=approve|reject` bypasses the dialog for tests
//! and harnesses only — it is loud on stderr and reported to the caller in
//! the refusal/audit detail, mirroring the transport's `--yes` discipline.

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

/// What the human decided (or what stands in for it under the test hook).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Approved { auto: bool },
    Rejected { detail: String },
}

/// Everything that can prevent a decision — always fail-closed.
#[derive(Debug)]
pub struct SurfaceUnavailable(pub String);

fn phrase_path() -> PathBuf {
    std::env::var("CIPHERLAYER_CONFIRM_PHRASE_FILE")
        .unwrap_or_else(|_| "./data/vaultd/confirm-phrase".into())
        .into()
}

/// The anti-spoof phrase: readable only Vault-side. Enforced owner-only,
/// same discipline as the socket.
fn load_phrase() -> Result<String, SurfaceUnavailable> {
    let path = phrase_path();
    let meta = std::fs::metadata(&path).map_err(|e| {
        SurfaceUnavailable(format!(
            "confirmation phrase file {} unavailable ({e}) — create it (owner-only, chmod 600) \
             with your personal anti-spoof phrase",
            path.display()
        ))
    })?;
    if meta.mode() & 0o077 != 0 {
        return Err(SurfaceUnavailable(format!(
            "confirmation phrase file {} is group/world accessible (mode {:o}) — chmod 600 it",
            path.display(),
            meta.mode() & 0o777
        )));
    }
    let phrase = std::fs::read_to_string(&path)
        .map_err(|e| SurfaceUnavailable(format!("could not read phrase file: {e}")))?;
    let phrase = phrase.trim().to_string();
    if phrase.is_empty() {
        return Err(SurfaceUnavailable(
            "confirmation phrase file is empty — a genuine surface must display a phrase".into(),
        ));
    }
    Ok(phrase)
}

fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render the confirmation and return the human's decision.
/// `body` is the deterministic evidence text (built by the daemon from the
/// signing request — never from caller-supplied markup). `escalated` demands
/// the stronger affordance: the operator must type ESCALATE to approve.
pub fn confirm(body: &str, escalated: bool) -> Result<Decision, SurfaceUnavailable> {
    // Test/harness hook — explicit, loud, and honest in the outcome detail.
    if let Ok(auto) = std::env::var("CIPHERLAYER_CONFIRM_AUTO") {
        eprintln!(
            "WARNING: CIPHERLAYER_CONFIRM_AUTO={auto} bypasses the confirmation surface \
             (tests/harness only; recorded in the decision detail)"
        );
        return match auto.as_str() {
            "approve" => Ok(Decision::Approved { auto: true }),
            "reject" => Ok(Decision::Rejected {
                detail: "auto-rejected (CIPHERLAYER_CONFIRM_AUTO=reject, test hook)".into(),
            }),
            other => Err(SurfaceUnavailable(format!(
                "CIPHERLAYER_CONFIRM_AUTO must be approve or reject, got {other:?}"
            ))),
        };
    }

    if !cfg!(target_os = "macos") {
        return Err(SurfaceUnavailable(
            "no trusted confirmation surface on this platform yet (macOS system dialog is the \
             only implemented tier, ADR-012) — refusing rather than degrading silently"
                .into(),
        ));
    }

    let phrase = load_phrase()?;
    let text = format!(
        "Your secret phrase: {phrase}\n\
         (genuine Vault confirmations always show this phrase)\n\n{body}"
    );
    let text = escape_applescript(&text);

    let script = if escalated {
        // Escalation: explicit acknowledgement — type ESCALATE to approve.
        format!(
            "display dialog \"{text}\n\nPOLICY ESCALATION: type ESCALATE to approve.\" \
             with title \"CipherLayer Vault — Signature Escalation\" \
             default answer \"\" \
             buttons {{\"Reject\", \"Approve\"}} default button \"Reject\" \
             cancel button \"Reject\" with icon caution giving up after 120"
        )
    } else {
        format!(
            "display dialog \"{text}\" \
             with title \"CipherLayer Vault — Confirm Signature\" \
             buttons {{\"Reject\", \"Approve\"}} default button \"Reject\" \
             cancel button \"Reject\" with icon caution giving up after 120"
        )
    };

    let out = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| SurfaceUnavailable(format!("could not launch the system dialog: {e}")))?;

    // Cancel button / Escape exits non-zero (-128): an explicit rejection.
    if !out.status.success() {
        return Ok(Decision::Rejected {
            detail: "rejected at the Vault confirmation surface".into(),
        });
    }
    let reply = String::from_utf8_lossy(&out.stdout);
    if reply.contains("gave up:true") {
        return Ok(Decision::Rejected {
            detail: "confirmation timed out (120s) — fail closed".into(),
        });
    }
    if !reply.contains("button returned:Approve") {
        return Ok(Decision::Rejected {
            detail: "rejected at the Vault confirmation surface".into(),
        });
    }
    if escalated && !reply.contains("text returned:ESCALATE") {
        return Ok(Decision::Rejected {
            detail: "escalation not acknowledged (ESCALATE was not typed) — fail closed".into(),
        });
    }
    Ok(Decision::Approved { auto: false })
}

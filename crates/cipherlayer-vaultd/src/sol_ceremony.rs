//! ADR-021: vaultd's hosting of the Solana external-signer ceremony.
//!
//! The engine (`cipherlayer_vault::SolExternalSigningCeremony`) is pure
//! logic; this module owns the human channel — vaultd's **own controlling
//! terminal** (`/dev/tty`). The approval phrase is typed here (echo on; the
//! phrase is not a secret, presence-at-this-terminal is the point) and the
//! key is pasted here (echo off). Both fail closed if vaultd has no tty:
//! a headless vaultd cannot run this ceremony, by design (ADR-021 §2 —
//! secret entry must not transit an `osascript` child or any IPC).
//!
//! The key's journey: tty read (echo off) → engine `sign` (parse → derive
//! check → sign → wipe) → gone. It never enters a request/response, an env
//! var, a log line, or this module's state.

use cipherlayer_vault::SolExternalSignerError;
use std::io::{BufRead, BufReader, Write};
use zeroize::Zeroize;

pub struct TtyUnavailable(pub String);

/// One prompt/response exchange on the controlling terminal. Opened fresh
/// per prompt — no persistent handles, nothing buffered across calls.
fn open_tty() -> Result<(std::fs::File, std::fs::File), TtyUnavailable> {
    let reader = std::fs::File::open("/dev/tty")
        .map_err(|e| TtyUnavailable(format!("no controlling terminal for key entry: {e}")))?;
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|e| TtyUnavailable(format!("no controlling terminal for key entry: {e}")))?;
    Ok((reader, writer))
}

/// Toggle echo on the controlling terminal. `stty` operates on its stdin,
/// which is bound to /dev/tty here — the same portable mechanism the
/// console's EVM key prompt uses.
fn set_tty_echo(on: bool) -> Result<(), TtyUnavailable> {
    let tty = std::fs::File::open("/dev/tty")
        .map_err(|e| TtyUnavailable(format!("no controlling terminal: {e}")))?;
    let status = std::process::Command::new("stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdin(tty)
        .status()
        .map_err(|e| TtyUnavailable(format!("stty failed: {e}")))?;
    if !status.success() {
        return Err(TtyUnavailable("stty exited nonzero".into()));
    }
    Ok(())
}

/// Show `text` and read one echoed line (the approval phrase path).
pub fn prompt_visible(text: &str) -> Result<String, TtyUnavailable> {
    let (reader, mut writer) = open_tty()?;
    write!(writer, "{text}").map_err(|e| TtyUnavailable(e.to_string()))?;
    writer.flush().map_err(|e| TtyUnavailable(e.to_string()))?;
    let mut line = String::new();
    BufReader::new(reader)
        .read_line(&mut line)
        .map_err(|e| TtyUnavailable(e.to_string()))?;
    Ok(line.trim().to_string())
}

/// Show `text` and read one line with echo OFF (the key path). Echo is
/// restored even on read failure. The caller owns wiping the returned
/// String (the engine's `sign` wipes it on every path).
///
/// The read is deliberately unbuffered: a `BufReader` would hold the key
/// bytes in an internal heap buffer that is dropped without zeroization
/// (external-audit finding, 2026-07-19). Bytes go straight from the tty fd
/// into a `Zeroizing` accumulator, one at a time, and the single-byte
/// staging cell is wiped before return — no intermediate copy survives.
pub fn prompt_secret(text: &str) -> Result<String, TtyUnavailable> {
    use std::io::Read;
    let (mut reader, mut writer) = open_tty()?;
    write!(writer, "{text}").map_err(|e| TtyUnavailable(e.to_string()))?;
    writer.flush().map_err(|e| TtyUnavailable(e.to_string()))?;
    set_tty_echo(false)?;
    let mut buf: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(Vec::with_capacity(256));
    let mut byte = [0u8; 1];
    let read_result = loop {
        match reader.read(&mut byte) {
            Ok(0) => break Ok(()), // EOF ends the line
            Ok(_) if byte[0] == b'\n' => break Ok(()),
            Ok(_) => buf.push(byte[0]),
            Err(e) => break Err(e),
        }
    };
    byte.zeroize();
    let _ = set_tty_echo(true);
    let _ = writeln!(writer); // the newline the terminal didn't echo
    if let Err(e) = read_result {
        return Err(TtyUnavailable(e.to_string())); // buf wiped on drop
    }
    match std::str::from_utf8(&buf) {
        // The one unavoidable copy: the String handed to the engine, which
        // wipes it on every path; `buf` is wiped when this frame drops.
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(TtyUnavailable(
            "key input was not valid UTF-8 — refusing (input not echoed)".into(),
        )),
    }
}

/// Render the phase-1 facts block for the vaultd terminal. Deterministic,
/// from the request only; lamports are shown raw AND in SOL (9 decimals)
/// so a magnitude error is visible at a glance.
pub fn render_facts(
    cluster_name: &str,
    genesis: &str,
    facts: &cipherlayer_vault::ipc::WireSolFacts,
    phrase: &str,
    is_mainnet: bool,
) -> String {
    let sol = facts.lamports as f64 / 1e9;
    let fee = match facts.fee_estimate_lamports {
        Some(f) => format!("{f} lamports (pre-approval estimate)"),
        None => "unknown (devnet only may proceed)".into(),
    };
    format!(
        "\n== CipherLayer Solana external-signer ceremony (ADR-021) ==\n{}\
         cluster:   {cluster_name}\n\
         genesis:   {genesis} (pinned)\n\
         from:      {}\n\
         to:        {}\n\
         amount:    {} lamports ({sol} SOL)\n\
         fee:       {fee}\n\n\
         Type {phrase} to approve these facts (blank = refuse): ",
        if is_mainnet {
            "*** REAL SOLANA MAINNET — REAL FUNDS, IRREVERSIBLE ***\n"
        } else {
            ""
        },
        facts.from_pubkey,
        facts.to_pubkey,
        facts.lamports,
    )
}

/// Human-facing wrapper for phase 2's key prompt text.
pub fn key_prompt(cluster_name: &str) -> String {
    format!("paste the {cluster_name} private key (base58 64-byte keypair; input hidden): ")
}

/// Advisory text mapping for refusals that deserve a terminal echo on the
/// vaultd side too (the operator is standing at this terminal).
pub fn echo_refusal(err: &SolExternalSignerError) {
    eprintln!("sol ceremony refused: {err}");
}

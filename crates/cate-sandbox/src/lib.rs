// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-sandbox: Prozess-Sandbox (M-6 + S2-Haertung).
//!
//! Garantien: argv-Array (nie Shell-String), Allowlist oder expliziter
//! Pfad, Timeout + Kill, Output-Cap, isoliertes Scratch-Verzeichnis,
//! Audit-Log-Eintrag pro Run — plus S2: `env_clear` mit expliziter
//! Env-Allowlist, Kind-Kill per OS-Gruppe (Windows Job-Objekt mit
//! `KILL_ON_JOB_CLOSE`, Unix Prozessgruppe per `setpgid` + Gruppen-Kill),
//! Ressourcen-Limits wo OS-seitig moeglich (Windows Job-Limits,
//! Linux `setrlimit`; sonst dokumentierter Fallback auf Timeout-Kill).
//! S4 (Staged Confinement): [`StageProfile`]-Stufen-Matrix (Netz-
//! Stufe nur mit [`RedactionOutput`], Daten-Stufe env-entschluesselt
//! ohne Proxy/Secrets), Dry-Run-Preview ([`FixDryRunPreview`]) und
//! TOCTOU-sichere exec-Pruefung ([`toctou_resolve`]).
//! Kein Netz-Deny auf Prozessebene — das bleibt Container-Laufzeit
//! (Phase S3, Restrisiko, s. `docs/SANDBOX_DESIGN.md`).
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Standard-Timeout (s), wenn der Aufrufer nichts anderes vorgibt.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;
/// Harte Obergrenze fuer `timeout_secs` (s).
pub const MAX_TIMEOUT_SECS: u64 = 600;
/// Standard-Output-Cap pro Stream (stdout / stderr je 1 MiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Standard-Prozesslimit (Windows Job-Objekt, pro Job gezaehlt).
pub const DEFAULT_MAX_PROCESSES_WINDOWS: u32 = 64;
/// Poll-Intervall der Timeout-Ueberwachung.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);
static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Konfiguration der Sandbox (Operator-Seite, kein Shell-String).
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Erlaubte Binary-Basenamen (z. B. cargo, pytest).
    /// Gilt nur fuer blosse Namen ohne Pfadtrennzeichen; absolute Pfade
    /// sind auch ohne Allowlist-Eintrag erlaubt (expliziter Pfad).
    pub allowlist: Vec<String>,
    /// Cap pro Output-Stream in Bytes.
    pub max_output_bytes: usize,
    /// Harte Obergrenze fuer `timeout_secs`.
    pub max_timeout_secs: u64,
    /// Explizite Umgebungs-Allowlist (S2/R4): das Kind erbt NUR diese
    /// Variablen aus der Eltern-Umgebung (`env_clear` + selektives
    /// Wiederherstellen). Alles andere — Secrets, Proxy-Credentials,
    /// Session-Tokens — erreicht das Kind nie. Default:
    /// [`default_env_allowlist`].
    pub env_allowlist: Vec<String>,
    /// Operator-gesetzte Zusatzvariablen (ueberschreiben gleichnamige
    /// geerbte Werte). Einziger Weg, dem Kind gezielt Werte mitzugeben.
    pub extra_env: Vec<(String, String)>,
    /// Ressourcen-Limits (S2/R3). Was das OS nicht kann, ist `None`
    /// (dokumentierter Fallback auf Timeout-Kill, s. [`ResourceLimits`]).
    pub limits: ResourceLimits,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_timeout_secs: MAX_TIMEOUT_SECS,
            env_allowlist: default_env_allowlist(),
            extra_env: Vec::new(),
            limits: ResourceLimits::default(),
        }
    }
}

/// Ressourcen-Limits des Sandbox-Kinds (S2/R3).
///
/// Durchsetzung je OS (Best-Effort, Rest via Timeout-Kill + S3-Container):
/// - Windows: Job-Objekt (`ActiveProcessLimit` aus `max_processes`,
///   `ProcessMemoryLimit` aus `max_memory_bytes`).
/// - Linux: `setrlimit` im Kind vor `exec` (`RLIMIT_NPROC`/`RLIMIT_AS`/
///   `RLIMIT_FSIZE`/`RLIMIT_CPU`). **Achtung:** `RLIMIT_NPROC` zaehlt
///   pro realer UID, nicht pro Sandbox — deshalb Default `None` auf
///   Linux (Gruppen-Kill + Timeout sind dort der Backstop; echtes
///   `pids.max` braucht cgroups = S3).
/// - Andere Unix (z. B. macOS): nur Prozessgruppe + Kill, keine rlimits.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Max. Prozesse: Windows Job-Limit (pro Job, sicher); Linux
    /// `RLIMIT_NPROC` (pro UID — nur explizit setzen, nie Default).
    pub max_processes: Option<u32>,
    /// Max. Speicher pro Prozess (Windows Job / Linux `RLIMIT_AS`).
    /// Default `None`: legitime Toolchains (Compiler) brauchen mehr;
    /// harte RAM-Kappe erst S3 (`memory.max`).
    pub max_memory_bytes: Option<u64>,
    /// Max. Dateigroesse pro Write (nur Linux `RLIMIT_FSIZE`).
    pub max_file_bytes: Option<u64>,
    /// Max. CPU-Sekunden pro Prozess (nur Linux `RLIMIT_CPU`).
    pub max_cpu_secs: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            // Pro-Job-Limit ist sicher (zaehlt nur Sandbox-Prozesse).
            #[cfg(windows)]
            max_processes: Some(DEFAULT_MAX_PROCESSES_WINDOWS),
            // Pro-UID-Semantik auf Linux: kein sicherer Default.
            #[cfg(not(windows))]
            max_processes: None,
            max_memory_bytes: None,
            max_file_bytes: None,
            max_cpu_secs: None,
        }
    }
}

/// Standard Env-Allowlist (S2/R4): Laufzeit-Noetigstes, sonst nichts.
/// Laufzeit (Interpreter/Toolchain) braucht: `PATH`, System (Windows:
/// `SystemRoot`/`SystemDrive`/`COMSPEC`/`PATHEXT`/`OS`), Temp (`TEMP`/
/// `TMP`/`TMPDIR`), Locale (`LANG`/`LC_ALL`/`TZ`), Home (`HOME`/`USER`/
/// `USERNAME`, brauchen z. B. Cargo/Tool-Caches).
///
/// Bewusst NICHT enthalten (R2-light + Secret-Hygiene): `HTTP_PROXY`,
/// `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (keine ambient Proxy-Creds im
/// Kind; echtes Egress-Deny erst S3) sowie saemtliche Secret-/Token-/
/// Key-Variablen — sie fallen durch `env_clear` weg, ohne je namentlich
/// bekannt sein zu muessen.
pub fn default_env_allowlist() -> Vec<String> {
    [
        "PATH",
        "SystemRoot",
        "SystemDrive",
        "PATHEXT",
        "COMSPEC",
        "OS",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "HOME",
        "USER",
        "USERNAME",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
    ]
    .iter()
    .map(ToString::to_string)
    .collect()
}

/// Baut die Kind-Umgebung: nur Allowlist-Werte aus dem Elter plus
/// `extra_env` (ueberschreibt gleichnamige geerbte Werte).
pub fn build_env(config: &SandboxConfig) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for key in &config.env_allowlist {
        if let Ok(val) = std::env::var(key) {
            if !out.iter().any(|(k, _)| k == key) {
                out.push((key.clone(), val));
            }
        }
    }
    for (key, val) in &config.extra_env {
        if let Some(slot) = out.iter_mut().find(|(k, _)| k == key) {
            slot.1 = val.clone();
        } else {
            out.push((key.clone(), val.clone()));
        }
    }
    out
}

/// S4 Staged Confinement: Confinement-Profile einer Pipeline-Stufe.
///
/// Sandlock-Regel ("lethal trifecta brechen"): Faehigkeiten werden
/// getrennt statt vertraut — eine Stufe mit Netz sieht nie Roh-Daten
/// (Findings/Secrets), eine Stufe mit Roh-Daten hat nie Netz. Das Profil
/// steuert die Env-Zugangspolitik der Sandbox (S2-R4-Mechanismus); was
/// die Stufe in argv/Files bekommt, entscheidet der Aufrufer via
/// [`RedactionOutput`] (`Network`) bzw. Scratch-only-Inhalte (`Data`).
///
/// Stufen-Matrix (getestet in `tests/stage_profile.rs`):
///
/// | Profil    | Netz | Roh-Daten (Findings/Secrets) | Kontext |
/// |-----------|------|------------------------------|---------|
/// | `Network` | JA   | NEIN                         | nur Redaction-Output |
/// | `Data`    | NEIN | JA                           | Rohtext lokal, nie versendet |
/// | `Neutral` | NEIN | NEIN                         | weder noch |
///
/// Ehrliche Grenzen (kein falsches Versprechen, S3 bleibt die
/// Container-Garantie, s. `docs/SANDBOX_DESIGN.md` §5 Restrisiken):
/// `Network` blockiert Netz-Draehte nicht auf Prozessebene (§5 R2) und
/// `Data` erteilt keine Schreibrechte ausserhalb `scratch/` — beides
/// bleibt hier Policy, OS-Erzwingung erst S3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StageProfile {
    /// Netz-Stufe: nur redigierter Kontext rein (argv aus
    /// [`RedactionOutput`]), nie Roh-Findings/Secrets.
    Network,
    /// Daten-Stufe: volle lokale Daten (Findings/Snippets), rein lokal —
    /// kein Netz-Argument, kein Cloud-Subprozess.
    Data,
    /// Weder noch (z. B. Cleanup-Stage, Binary rein ohne Kontext).
    Neutral,
}

impl StageProfile {
    /// Matrix-Zeile: `true` bei Netz-Stufe (Network).
    pub const fn has_network(&self) -> bool {
        matches!(self, Self::Network)
    }

    /// Matrix-Zeile: `true` bei Daten-Stufe (Data).
    pub const fn has_data(&self) -> bool {
        matches!(self, Self::Data)
    }

    /// Env-Allowlist des Profils: Basis-Keys fuer alle Profile, zusaetzlich
    /// Home-Mapping fuer `Data` (lokale Tools mit Cache im Home).
    /// Basis: PATH (Toolchain), TEMP/TMP/TMPDIR (Scratch-Mapping),
    /// SystemRoot/SystemDrive (Windows-Laufzeit). Bewusst STETS abwesend:
    /// Proxy-Variablen (R2-light, `HTTP(S)_PROXY`/`ALL_PROXY`) und alle
    /// Secret-/Token-/Key-Variablen (R4) — auch fuer `Data`.
    pub fn env_allowlist_for(&self) -> Vec<String> {
        let mut keys: Vec<&str> =
            ["PATH", "TEMP", "TMP", "TMPDIR", "SystemRoot", "SystemDrive"].to_vec();
        if *self == Self::Data {
            keys.extend(["HOME", "USER", "USERNAME", "PATHEXT"]);
        }
        keys.iter().map(ToString::to_string).collect()
    }

    /// Baut die Config fuer die Stufe: Default-Limits (S2), Env-Allowlist
    /// = Profil-Menge, keine Extra-Variablen (Operator-Override ist der
    /// bewusste Aufrufer-Entscheid, nie Profile-Default).
    pub fn config_for_profile(&self) -> SandboxConfig {
        SandboxConfig {
            allowlist: Vec::new(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_timeout_secs: MAX_TIMEOUT_SECS,
            env_allowlist: self.env_allowlist_for(),
            extra_env: Vec::new(),
            limits: ResourceLimits::default(),
        }
    }
}

impl fmt::Display for StageProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network => write!(f, "network"),
            Self::Data => write!(f, "data"),
            Self::Neutral => write!(f, "neutral"),
        }
    }
}

/// Redaction-Output als Datenkontakt-Typ (S4): Netz-Stufen beziehen die
/// Spawn-Args nur aus diesem Typ — im argv ist das Urgestein
/// (Findings/Secrets) schon redigiert (Marker «redacted:…»), bevor es den
/// Subprozess erreicht. Roh-Findings an Netz-Stufen sind ueber die
/// Runner-API nicht darstellbar (§S4, Trennung Netz XOR Daten).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactionOutput(String);

impl RedactionOutput {
    /// Umschlag fuer einen bereits redigierten String (z. B. via
    /// `cate-core::redact::redact_text`). Der Aufrufer traegt die
    /// Redact-Verantwortung; die Sandbox redigiert nicht doppelt,
    /// sondern dokumentiert die Pflicht hier.
    pub const fn new(redacted: String) -> Self {
        Self(redacted)
    }

    /// Lesender Zugriff (Stufen-Runner bauen argv daraus).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RedactionOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// S4 Dry-Run-Preview ohne Schreibeffekt (Fix-Vorschlag-Ebene):
/// `capture_effects` baut aus einem Sandbox-Preview-Run Metadaten (Exit,
/// Drain-/Output-Cap-Flags, Laengen — nie Inhalt), die als Datensatz
/// verglichen/gespeichert werden koennen; Apply macht der echte
/// Proposal-Apply (`cate-mcp` ProposalStore/apply-history, dort mit
/// Approval-Gate + Audit, unveraendert). Hier nur der Capture-Ebene-Typ
/// plus JSON-Roundtrip-Vertraeglichkeit (serde).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixDryRunPreview {
    /// Programm des geplanten/previewten Run (Pfad/Allowlist-Name).
    pub program: String,
    /// Geplante argv-Laenge (Metadaten, nie Inhalte).
    pub args_len: usize,
    /// Geplanter Timeout (s).
    pub timeout_secs: u64,
    /// Confinement-Profil des Runs.
    pub profile: StageProfile,
    /// Effects-Capture (Exit/Laengen/Trunkierung, nie Inhalte).
    pub effects: FixDryRunEffects,
}

/// Effekt-Metadaten eines Runs (keine Inhalte, kein Secret-Leak).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixDryRunEffects {
    /// Exit-Code des Preview-Run (falls fertig gelaufen).
    pub exit_code: Option<i32>,
    /// Output-Cap-/Abandon-Flags zusammengefasst.
    pub truncated: bool,
    /// stdout/stderr-Laenge (Bytezahl, nie der Text).
    pub stdout_len: usize,
    pub stderr_len: usize,
}

impl FixDryRunPreview {
    /// Erstellt die Preview aus ausgefuehrtem Sandbox-Result:
    /// Effekte gecaptured, apply/commit ist ein getrennter Schritt.
    pub fn capture_effects(
        request: &SandboxRequest<'_>,
        profile: StageProfile,
        res: &SandboxResult,
    ) -> Self {
        Self {
            program: request.program.to_string(),
            args_len: request.args.len(),
            timeout_secs: request.timeout_secs,
            profile,
            effects: FixDryRunEffects {
                exit_code: res.exit_code,
                truncated: res.stdout_truncated || res.stderr_truncated,
                stdout_len: res.stdout.len(),
                stderr_len: res.stderr.len(),
            },
        }
    }
}

/// Ein Sandbox-Lauf: Programm + argv (Array!) + Scratch + Timeout.
#[derive(Debug, Clone)]
pub struct SandboxRequest<'a> {
    /// Blosser Binary-Name (Allowlist) oder absoluter Pfad.
    pub program: &'a str,
    /// Argumente als Array — wird nie zu einem Shell-String verbunden.
    pub args: &'a [&'a str],
    /// Isoliertes Arbeitsverzeichnis (per [`create_scratch`] erzeugt).
    pub scratch: &'a Path,
    /// Wall-Clock-Timeout in Sekunden (1..=`SandboxConfig::max_timeout_secs`).
    pub timeout_secs: u64,
}

/// Ergebnis eines Sandbox-Laufs.
#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub run_id: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl SandboxResult {
    /// Re-Test bestanden: kein Timeout und Exit-Code 0.
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

/// Fehler der Sandbox (kein Run fand statt bzw. Spawn unmoeglich).
#[derive(Debug)]
pub enum SandboxError {
    EmptyProgram,
    BinaryNotAllowed(String),
    ScratchEscape(String),
    ScratchNotDir(String),
    TimeoutOutOfRange(u64),
    SpawnFailed(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProgram => write!(f, "Programmname darf nicht leer sein"),
            Self::BinaryNotAllowed(p) => {
                write!(
                    f,
                    "Binary nicht erlaubt (weder Allowlist noch expliziter Pfad): {p}"
                )
            }
            Self::ScratchEscape(p) => write!(f, "Scratch-Escape abgelehnt: {p}"),
            Self::ScratchNotDir(p) => {
                write!(f, "Scratch-Verzeichnis fehlt oder kein Verzeichnis: {p}")
            }
            Self::TimeoutOutOfRange(t) => write!(f, "timeout_secs ausserhalb 1..=max: {t}"),
            Self::SpawnFailed(e) => write!(f, "Prozess-Start fehlgeschlagen: {e}"),
        }
    }
}

impl std::error::Error for SandboxError {}

/// Audit-Log-Eintrag pro Run (append-only, JSON-serialisierbar).
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub run_id: String,
    pub program: String,
    pub argv_len: usize,
    pub timeout_secs: u64,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
    pub started_unix_ms: u64,
}

impl AuditEntry {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Laufende Nummer im Run-Audit (`sbx-<millis>-<n>`).
pub fn next_run_id() -> String {
    let n = RUN_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    let ms = unix_ms();
    format!("sbx-{ms}-{n}")
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Erzeugt ein isoliertes Scratch-Verzeichnis unter dem System-Temp.
/// Rueckgabe ist pro Prozess eindeutig (pid + Zeit + Zaehler).
pub fn create_scratch() -> std::io::Result<PathBuf> {
    let n = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;
    let dir = std::env::temp_dir().join(format!(
        "cate-sandbox-{}-{}-{}",
        std::process::id(),
        unix_ms(),
        n
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Entfernt ein Scratch-Verzeichnis (best effort vom Aufrufer nach Run-Ende).
pub fn remove_scratch(dir: &Path) -> std::io::Result<()> {
    std::fs::remove_dir_all(dir)
}

/// Prueft einen Scratch-relativen Pfad (Path-Jail): absolut, `..`,
/// Laufwerks- und Tilde-Escapes werden abgelehnt.
pub fn resolve_in_scratch(scratch: &Path, rel: &str) -> Result<PathBuf, SandboxError> {
    let t = rel.replace('\\', "/");
    if t.is_empty() || t.contains('\0') {
        return Err(SandboxError::ScratchEscape(rel.to_string()));
    }
    let p = Path::new(&t);
    if p.is_absolute()
        || t.starts_with('/')
        || t.split('/').any(|s| s == "..")
        || t.starts_with("~/")
        || (t.len() > 1 && t.chars().nth(1) == Some(':'))
    {
        return Err(SandboxError::ScratchEscape(rel.to_string()));
    }
    Ok(scratch.join(t))
}

/// Loest `program` auf: blosser Name → Allowlist; absoluter Pfad →
/// muss existierende Datei sein; alles andere → abgelehnt.
pub fn resolve_program(config: &SandboxConfig, program: &str) -> Result<PathBuf, SandboxError> {
    if program.trim().is_empty() || program.contains('\0') {
        return Err(SandboxError::EmptyProgram);
    }
    let p = Path::new(program);
    let looks_like_path = program.contains('/') || program.contains('\\') || p.is_absolute();
    if !looks_like_path {
        let allowed = config.allowlist.iter().any(|a| {
            if cfg!(windows) {
                a.eq_ignore_ascii_case(program)
            } else {
                a == program
            }
        });
        if allowed {
            return Ok(PathBuf::from(program));
        }
        return Err(SandboxError::BinaryNotAllowed(program.to_string()));
    }
    if !p.is_absolute() {
        return Err(SandboxError::BinaryNotAllowed(program.to_string()));
    }
    match std::fs::metadata(p) {
        Ok(m) if m.is_file() => Ok(p.to_path_buf()),
        _ => Err(SandboxError::BinaryNotAllowed(program.to_string())),
    }
}

/// TOCTOU-sichere exec-Pruefung (S4): Pfad-NACH-Aufloesung gegen die
/// Allowlist-Regel — kein Zeitfenster zwischen Pruefen und Spawnen, das
/// ein Symlink/Junction-Austausch exploiten koennte.
///
/// Vorgehen (Windows + Unix gleich): `program` zuerst nach den
/// `resolve_program`-Regeln aufloesen (Allowlist-Name oder expliziter
/// absoluter Pfad), dann Zieldatei-Oeffnen und Kanonischen Pfad zwingend
/// ermitteln (`canonicalize` resolvt Symlinks/Junctions vollstaendig).
/// Der Rueckgabepfad ist der beim Check-Zeitpunkt ECHTE Pfad; der Spawn
/// ([`run_sandboxed`]) nutzt diesen aufgelösten Pfad statt des
/// Raw-Strings — so gibt es kein offenes Zeitfenster mehr.
///
/// Fail-closed: Abweichungs-/Symlink-/Junction-Escape, Oeffnen oder
/// Kanonisierung fehlschlagen → `BinaryNotAllowed` (nie ein
/// Zurueckfallen auf den ungeprueften Pfad).
///
/// Testfall (Symlink nach Pruefung ausgetauscht → abgelehnt) s.
/// `tests/toctou.rs`; dieser Test oeffnet die Datei, prueft den Pfad,
/// tauscht danach die Datei unter dem Pfad (Symlink) aus und ruft
/// `toctou_resolve` erneut auf — die zweite Pruefung verweigert.
pub fn toctou_resolve(config: &SandboxConfig, program: &str) -> Result<PathBuf, SandboxError> {
    let raw = resolve_program(config, program)?;
    // Berechtigter Pfad: Datei muss existieren (symlink_metadata folgt
    // dem Link NICHT — es prüft ob `raw` selbst ein Link ist).
    std::fs::symlink_metadata(&raw)
        .map_err(|_| SandboxError::BinaryNotAllowed(program.to_string()))?;
    // Objekt öffnen, dann kanonisch auflösen: Das handle-laufende
    // Ziel entspricht dem Pfad, der SPAETER gespawnt wird.
    std::fs::File::open(&raw).map_err(|_| SandboxError::BinaryNotAllowed(program.to_string()))?;
    let canon = raw
        .canonicalize()
        .map_err(|_| SandboxError::BinaryNotAllowed(program.to_string()))?;
    // Abweichungs-/Escape-Check: Der kanonische Pfad muss mit dem
    // verifizierten Raw-Pfad kompatibel bleiben. Auf WindowsCaseless
    // vergleichen; bei Abweichung (Symlink nach Ausserhalb, Junction-
    // Umweg) → verweigern.
    let same = if cfg!(windows) {
        both_paths_compatible(&raw, &canon)
    } else {
        raw == canon
    };
    if same {
        Ok(canon)
    } else {
        Err(SandboxError::BinaryNotAllowed(program.to_string()))
    }
}

/// Windows-Pfadvergleich: `canonicalize` liefert `\\?\C:\...`
/// (Uniform-Praefix) — Prefix wird gestrippt (`\\?\UNC\` behoerig
/// zu `\\server\share\...`), danach case-insensitive Vergleich.
#[cfg(windows)]
fn both_paths_compatible(a: &Path, b: &Path) -> bool {
    fn strip_unc(p: &str) -> String {
        if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{rest}")
        } else if let Some(rest) = p.strip_prefix(r"\\?\") {
            rest.to_string()
        } else {
            p.to_string()
        }
    }
    let a_s = strip_unc(&a.to_string_lossy().replace('/', "\\"));
    let b_s = strip_unc(&b.to_string_lossy().replace('/', "\\"));
    a_s.eq_ignore_ascii_case(&b_s)
}

/// Unix-Pfadvergleich: Byte-genau (keine Caseless-Semantik erwartet).
#[cfg(not(windows))]
fn both_paths_compatible(a: &Path, b: &Path) -> bool {
    a == b
}

/// Kappt Bytes auf `limit`; Rueckgabe: (Text, trunkiert?).
pub fn cap_output(bytes: &[u8], limit: usize) -> (String, bool) {
    let truncated = bytes.len() > limit;
    let cut = if truncated { limit } else { bytes.len() };
    (
        String::from_utf8_lossy(&bytes[..cut]).into_owned(),
        truncated,
    )
}

fn drain_capped(
    handle: impl Read + Send + 'static,
    limit: usize,
) -> thread::JoinHandle<(Vec<u8>, usize)> {
    thread::spawn(move || {
        let mut h = handle;
        let mut buf = Vec::new();
        let mut total: usize = 0;
        let mut tmp = [0u8; 8192];
        loop {
            match h.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if buf.len() < limit {
                        let room = limit - buf.len();
                        buf.extend_from_slice(&tmp[..n.min(room)]);
                    }
                    // Weiter drainen (Rueckstau vermeiden), Ueberschuss verwerfen.
                }
                Err(_) => break,
            }
        }
        (buf, total)
    })
}

/// OS-Gruppe fuer Kind-Kill (S2/R1) + Limits (S2/R3).
///
/// Windows: Job-Objekt mit `KILL_ON_JOB_CLOSE` — stirbt das letzte
/// Job-Handle (Guard-Drop am Ende von [`run_sandboxed`]), killt das OS
/// das direkte Kind UND alle Enkel (kein Breakaway per Default).
/// Optional: `ActiveProcessLimit` / `ProcessMemoryLimit` aus
/// [`ResourceLimits`]. Reines `kernel32`-FFI, keine Dependency.
///
/// Fail-closed: laesst sich kein Job erzeugen oder zuweisen (z. B.
/// Host selbst in Job ohne Nested-Support), wird der Spawn abgebrochen
/// statt uncontained zu laufen.
#[cfg(windows)]
mod job {
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;

    type Handle = *mut std::ffi::c_void;
    type Dword = u32;
    type Bool = i32;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x0000_2000;
    const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: Dword = 0x0000_0008;
    const JOB_OBJECT_LIMIT_PROCESS_MEMORY: Dword = 0x0000_0100;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimits {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: Dword,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: Dword,
        affinity: usize,
        priority_class: Dword,
        scheduling_class: Dword,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_op: u64,
        write_op: u64,
        other_op: u64,
        read_transfer: u64,
        write_transfer: u64,
        other_transfer: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimits {
        basic: BasicLimits,
        io: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    // Layout-Gegenprobe (64-bit): BASIC=64 + IO=48 + 4x8 = 144 Bytes.
    const _: () = assert!(std::mem::size_of::<ExtendedLimits>() == 144);

    extern "system" {
        fn CreateJobObjectW(attrs: *mut std::ffi::c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            class: i32,
            info: *const std::ffi::c_void,
            len: Dword,
        ) -> Bool;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> Bool;
        fn CloseHandle(handle: Handle) -> Bool;
    }

    /// Job-Handle-Guard: Drop schliesst das letzte Handle → OS killt
    /// per `KILL_ON_JOB_CLOSE` alle verbliebenen Job-Prozesse.
    pub struct JobGuard {
        handle: Handle,
    }

    impl JobGuard {
        pub fn create(limits: &super::ResourceLimits) -> Option<Self> {
            unsafe {
                let handle = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
                if handle.is_null() {
                    return None;
                }
                let mut info = ExtendedLimits::default();
                info.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if let Some(n) = limits.max_processes {
                    info.basic.limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                    info.basic.active_process_limit = n;
                }
                if let Some(m) = limits.max_memory_bytes {
                    info.basic.limit_flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                    info.process_memory_limit = m as usize;
                }
                let ok = SetInformationJobObject(
                    handle,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    std::ptr::from_ref(&info).cast(),
                    std::mem::size_of::<ExtendedLimits>() as Dword,
                );
                if ok == 0 {
                    CloseHandle(handle);
                    return None;
                }
                Some(Self { handle })
            }
        }

        pub fn assign(&self, child: &Child) -> bool {
            unsafe { AssignProcessToJobObject(self.handle, child.as_raw_handle() as Handle) != 0 }
        }
    }

    impl Drop for JobGuard {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// OS-Gruppe fuer Kind-Kill (S2/R1) + Limits (S2/R3), Unix-Seite.
///
/// Das Kind wird per `setpgid(0, 0)` Gruppenfuehrer (pre-exec,
/// fail-closed: schlaegt `setpgid` fehl, schlaegt der Spawn fehl).
/// Bei Timeout geht `SIGKILL` an die negative PGID — das trifft das
/// direkte Kind UND alle Enkel in der Gruppe. Reines libc-FFI
/// (`setpgid`/`setrlimit`/`kill`), keine Dependency.
///
/// Limits (nur Linux, `setrlimit`, Best-Effort): `RLIMIT_NPROC`/
/// `RLIMIT_AS`/`RLIMIT_FSIZE`/`RLIMIT_CPU` aus [`ResourceLimits`].
/// rlimit-Fehler sind nicht fatal (Backstop: Gruppen-Kill + Timeout).
#[cfg(unix)]
mod pgroup {
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    const SIGKILL: i32 = 9;
    #[cfg(target_os = "linux")]
    const RLIMIT_CPU: u32 = 0;
    #[cfg(target_os = "linux")]
    const RLIMIT_FSIZE: u32 = 1;
    #[cfg(target_os = "linux")]
    const RLIMIT_NPROC: u32 = 6;
    #[cfg(target_os = "linux")]
    const RLIMIT_AS: u32 = 9;

    #[repr(C)]
    #[cfg(target_os = "linux")]
    struct RLimit {
        cur: u64,
        max: u64,
    }

    extern "C" {
        fn setpgid(pid: i32, pgid: i32) -> i32;
        fn kill(pid: i32, sig: i32) -> i32;
        #[cfg(target_os = "linux")]
        fn setrlimit(resource: u32, rlp: *const RLimit) -> i32;
    }

    #[cfg(target_os = "linux")]
    fn set_one(resource: u32, value: u64) {
        let lim = RLimit {
            cur: value,
            max: value,
        };
        unsafe {
            setrlimit(resource, &lim);
        }
    }

    /// Laeuft im Kind nach fork, vor exec: eigene Prozessgruppe
    /// (fail-closed) + Best-Effort-rlimits.
    fn pre_exec_setup(limits: &super::ResourceLimits) -> io::Result<()> {
        let rc = unsafe { setpgid(0, 0) };
        if rc != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "setpgid fehlgeschlagen (keine Prozessgruppe)",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(secs) = limits.max_cpu_secs {
                set_one(RLIMIT_CPU, secs);
            }
            if let Some(bytes) = limits.max_file_bytes {
                set_one(RLIMIT_FSIZE, bytes);
            }
            if let Some(n) = limits.max_processes {
                set_one(RLIMIT_NPROC, u64::from(n));
            }
            if let Some(bytes) = limits.max_memory_bytes {
                set_one(RLIMIT_AS, bytes);
            }
        }
        Ok(())
    }

    pub fn apply(cmd: &mut Command, limits: &super::ResourceLimits) {
        let owned = limits.clone();
        unsafe {
            cmd.pre_exec(move || pre_exec_setup(&owned));
        }
    }

    /// SIGKILL an die gesamte Prozessgruppe, danach direktes Kind ernten.
    /// Trifft Enkel auch dann, wenn das direkte Kind bereits tot ist
    /// (Gruppenzugehoerigkeit bleibt bis exec/_exit einer neuen Gruppe).
    /// Luecke: Enkel mit eigenem `setsid`/neuer Session entkommen der
    /// Gruppe — das braucht cgroups (S3, dokumentiert).
    pub fn kill_tree(child: &mut Child) -> Option<i32> {
        let pgid = child.id() as i32;
        unsafe {
            kill(-pgid, SIGKILL);
        }
        // Falls die Gruppe bereits weg ist: direkt nachlegen.
        let _ = child.kill();
        match child.wait() {
            Ok(status) => status.code(),
            Err(_) => None,
        }
    }
}

/// Gnadenfrist fuers Pipe-Drainen nach Kind-Ende (S2).
///
/// Enkel erben die stdout/stderr-Pipes und koennen sie ueber das
/// direkte Kind hinaus offen halten — `join()` duerfte dann ewig
/// blockieren (beobachtet: 60-s-Enkel-Pings). Nach der Frist zaehlt
/// der Run mit bisher Gelesenem; Abandon wertet als trunkiert.
const DRAIN_GRACE: Duration = Duration::from_secs(3);

/// Wartet maximal [`DRAIN_GRACE`] auf einen Drain-Thread.
/// Rueckgabe: (gelesene Bytes, Gesamt-Bytes, abandon?).
fn join_drain(handle: thread::JoinHandle<(Vec<u8>, usize)>) -> (Vec<u8>, usize, bool) {
    let deadline = Instant::now() + DRAIN_GRACE;
    loop {
        if handle.is_finished() {
            let (buf, total) = handle.join().unwrap_or_default();
            return (buf, total, false);
        }
        if Instant::now() >= deadline {
            // Thread laeuft weiter bis Pipe-EOF (Enkel-Tod), sein Puffer
            // wird verworfen — als trunkiert gewertet, nie als Haenger.
            return (Vec::new(), 0, true);
        }
        thread::sleep(POLL_INTERVAL);
    }
}
/// Timeout-Kill an der OS-Gruppe (S2/R1): Unix = Gruppen-Kill,
/// Windows = direktes Kind (Enkel raeumt der Job-Guard per
/// `KILL_ON_JOB_CLOSE` ab), sonst direktes Kind. Kehrt blockierend
/// erst zurueck, wenn das direkte Kind geerntet ist.
fn kill_on_timeout(child: &mut std::process::Child) -> Option<i32> {
    #[cfg(unix)]
    return pgroup::kill_tree(child);
    #[cfg(not(unix))]
    {
        let _ = child.kill();
        match child.wait() {
            Ok(status) => status.code(),
            Err(_) => None,
        }
    }
}

/// Führt `request` in der Sandbox aus: kein Shell-String, `env_clear` +
/// Allowlist-Umgebung, Timeout + Gruppen-Kill, Output-Cap,
/// Arbeitsverzeichnis = `scratch`.
///
/// S2-Härtung: Das Kind läuft in einer OS-Gruppe (Windows Job-Objekt
/// mit `KILL_ON_JOB_CLOSE`, Unix eigene Prozessgruppe) — bei Timeout
/// stirbt der ganze Baum, nicht nur das direkte Kind. Lässt sich die
/// Gruppe nicht herstellen, schlägt der Run fail-closed fehl
/// ([`SandboxError::SpawnFailed`]) statt uncontained zu laufen.
pub fn run_sandboxed(
    config: &SandboxConfig,
    request: &SandboxRequest<'_>,
) -> Result<(SandboxResult, AuditEntry), SandboxError> {
    if request.timeout_secs == 0 || request.timeout_secs > config.max_timeout_secs {
        return Err(SandboxError::TimeoutOutOfRange(request.timeout_secs));
    }
    let program = resolve_program(config, request.program)?;
    if !request.scratch.is_dir() {
        return Err(SandboxError::ScratchNotDir(
            request.scratch.display().to_string(),
        ));
    }
    let started = unix_ms();
    let run_id = next_run_id();
    let mut cmd = Command::new(&program);
    cmd.args(request.args)
        .current_dir(request.scratch)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // S2/R4: Umgebung loeschen, nur Allowlist + extra_env wiederherstellen.
    cmd.env_clear();
    for (key, val) in build_env(config) {
        cmd.env(key, val);
    }
    // S2/R1 (+R3-Limits): Kind in OS-Gruppe einordnen.
    #[cfg(unix)]
    pgroup::apply(&mut cmd, &config.limits);
    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;
    // Windows: Kind dem Job zuweisen — fail-closed bei Fehlschlag.
    #[cfg(windows)]
    let _job = match job::JobGuard::create(&config.limits) {
        Some(guard) => {
            if !guard.assign(&child) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SandboxError::SpawnFailed(
                    "Job-Objekt-Zuweisung fehlgeschlagen (kein uncontained Run)".to_string(),
                ));
            }
            guard
        }
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SandboxError::SpawnFailed(
                "Job-Objekt-Erzeugung fehlgeschlagen (kein uncontained Run)".to_string(),
            ));
        }
    };

    let out_h = child.stdout.take().expect("stdout piped");
    let err_h = child.stderr.take().expect("stderr piped");
    let out_t = drain_capped(out_h, config.max_output_bytes);
    let err_t = drain_capped(err_h, config.max_output_bytes);

    let deadline = Instant::now() + Duration::from_secs(request.timeout_secs);
    let mut timed_out = false;
    let exit_code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    // S2/R1: ganze OS-Gruppe killen (Kind + Enkel), nicht
                    // nur das direkte Kind. Job-Guard (`_job`) lebt bis
                    // Funktionsende und raeumt Nachzuegler per
                    // KILL_ON_JOB_CLOSE ab.
                    break kill_on_timeout(&mut child);
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => break None,
        }
    };
    // Windows: Job explizit schliessen, BEVOR gedraint wird — Enkel
    // sterben per KILL_ON_JOB_CLOSE, Pipes sehen EOF, kein Haenger.
    // (Unix: Gruppen-Kill hat Enkel bereits erfasst bzw. Grace greift.)
    // Gilt fuer Timeout- UND Clean-Exit-Pfad: Run-Ende = Baum-Ende.
    #[cfg(windows)]
    drop(_job);

    let (out_bytes, out_total, out_abandoned) = join_drain(out_t);
    let (err_bytes, err_total, err_abandoned) = join_drain(err_t);
    let (stdout, _) = cap_output(&out_bytes, config.max_output_bytes);
    let (stderr, _) = cap_output(&err_bytes, config.max_output_bytes);
    let stdout_truncated = out_total > config.max_output_bytes;
    let stderr_truncated = err_total > config.max_output_bytes;
    // Abandon (Enkel hielten Pipes offen) zaehlt als trunkiert.
    let truncated = stdout_truncated || stderr_truncated || out_abandoned || err_abandoned;

    let result = SandboxResult {
        run_id: run_id.clone(),
        exit_code,
        timed_out,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    };
    let audit = AuditEntry {
        run_id,
        program: request.program.to_string(),
        argv_len: request.args.len(),
        timeout_secs: request.timeout_secs,
        exit_code,
        timed_out,
        truncated,
        started_unix_ms: started,
    };
    Ok((result, audit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_name_needs_allowlist() {
        let cfg = SandboxConfig {
            allowlist: vec!["cargo".to_string()],
            ..Default::default()
        };
        assert!(resolve_program(&cfg, "cargo").is_ok());
        assert!(matches!(
            resolve_program(&cfg, "evil-bin-xyz"),
            Err(SandboxError::BinaryNotAllowed(_))
        ));
    }

    #[test]
    fn relative_path_with_separator_rejected() {
        let cfg = SandboxConfig::default();
        assert!(matches!(
            resolve_program(&cfg, "bin/tool"),
            Err(SandboxError::BinaryNotAllowed(_))
        ));
        assert!(matches!(
            resolve_program(&cfg, "../tool"),
            Err(SandboxError::BinaryNotAllowed(_))
        ));
    }

    #[test]
    fn scratch_jail_rejects_escapes() {
        let base = Path::new("/tmp/scratch");
        for bad in ["../x", "a/../../b", "/abs", "", "C:/win"] {
            assert!(
                resolve_in_scratch(base, bad).is_err(),
                "muss ablehnen: {bad:?}"
            );
        }
        assert!(resolve_in_scratch(base, "sub/dir/f.txt").is_ok());
    }

    #[test]
    fn cap_marks_truncation() {
        let (s, t) = cap_output(b"hello", 10);
        assert_eq!(s, "hello");
        assert!(!t);
        let big = vec![b'x'; 100];
        let (s, t) = cap_output(&big, 10);
        assert_eq!(s.len(), 10);
        assert!(t);
    }

    #[test]
    fn env_filtering_drops_secrets_and_proxy() {
        // Eltern-Canary + Proxy-Creds duerfen nie ins Kind gelangen.
        std::env::set_var("CATE_SANDBOX_UNIT_CANARY", "unit-geheim-123");
        std::env::set_var("CATE_SANDBOX_UNIT_PROXY", "http://proxy.invalid:3128");
        std::env::set_var("HTTP_PROXY", "http://proxy.invalid:3128");
        let mut cfg = SandboxConfig::default();
        cfg.extra_env.push((
            "CATE_SANDBOX_UNIT_EXTRA".to_string(),
            "sichtbar".to_string(),
        ));
        let env = build_env(&cfg);
        assert!(
            !env.iter().any(|(k, _)| k == "CATE_SANDBOX_UNIT_CANARY"),
            "Canary darf nicht vererbt werden"
        );
        assert!(
            !env.iter().any(|(k, _)| k == "HTTP_PROXY"),
            "Proxy-Creds duerfen nicht vererbt werden"
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "CATE_SANDBOX_UNIT_EXTRA" && v == "sichtbar"),
            "extra_env muss durchkommen"
        );
        std::env::remove_var("CATE_SANDBOX_UNIT_CANARY");
        std::env::remove_var("CATE_SANDBOX_UNIT_PROXY");
        std::env::remove_var("HTTP_PROXY");
    }

    #[test]
    fn default_allowlist_keeps_runtime_needs_nothing_else() {
        let allow = default_env_allowlist();
        for needed in ["PATH", "TEMP", "SystemRoot"] {
            assert!(
                allow.iter().any(|k| k == needed),
                "Laufzeit-Variable fehlt: {needed}"
            );
        }
        for banned in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "CATE_SANDBOX_UNIT_CANARY",
        ] {
            assert!(
                !allow.iter().any(|k| k == banned),
                "darf nicht in Allowlist stehen: {banned}"
            );
        }
    }

    #[test]
    fn resource_limits_default_conservative() {
        let lim = ResourceLimits::default();
        // Speicher-/File-/CPU-Kappen sind nie Default (braechen legitime
        // Toolchains); harte Kappen erst S3.
        assert!(lim.max_memory_bytes.is_none());
        assert!(lim.max_file_bytes.is_none());
        assert!(lim.max_cpu_secs.is_none());
        #[cfg(windows)]
        assert_eq!(lim.max_processes, Some(64));
        // Linux: RLIMIT_NPROC zaehlt pro UID — kein sicherer Default.
        #[cfg(not(windows))]
        assert!(lim.max_processes.is_none());
    }
}

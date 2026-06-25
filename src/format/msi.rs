//! MSI installer format handler.
//!
//! An `.msi` is a CFB (Compound File Binary) document containing database
//! tables and streams. Installable files are packed in one or more **embedded
//! CAB streams** referenced by the `Media` table (model B). We reuse the
//! existing [`CabHandler`] to read those files.
//!
//! Detection: CFB magic (`D0 CF 11 E0 A1 B1 1A E1`) **plus** `.msi` file
//! extension (case-insensitive) → `Confidence::MAGIC`. Without the extension
//! we return `Confidence::NONE` so that Office CFB files (`.doc`, `.xls`, …)
//! are not hijacked.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use crate::archive::{
    ArchiveReader, Confidence, Entry, FormatHandler, FormatId, OpenOptions, Source,
};
use crate::error::{Error, Result};
use crate::format::CabHandler;

/// CFB file-format magic (8 bytes).
const CFB_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Upper bound on `Directory_Parent` chain length when resolving a path. Guards
/// against cyclic or pathologically deep `Directory` trees in crafted files.
const MAX_DIR_DEPTH: usize = 256;

pub struct MsiHandler;

impl FormatHandler for MsiHandler {
    fn id(&self) -> FormatId {
        FormatId::Msi
    }

    /// `Confidence::MAGIC` only when BOTH conditions hold:
    /// 1. `header` starts with the 8-byte CFB magic.
    /// 2. `name` (the file name, not the full path) ends with `.msi`
    ///    (case-insensitive).
    fn probe(&self, header: &[u8], name: Option<&str>) -> Confidence {
        let has_cfb_magic = header.starts_with(CFB_MAGIC);
        let has_msi_ext = name
            .map(|n| {
                std::path::Path::new(n)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("msi"))
            })
            .unwrap_or(false);
        if has_cfb_magic && has_msi_ext {
            Confidence::MAGIC
        } else {
            Confidence::NONE
        }
    }

    fn open(&self, src: Source, opts: &OpenOptions) -> Result<Box<dyn ArchiveReader>> {
        // MSI requires a seekable source with a real on-disk path (the `msi`
        // crate opens by path).
        let path = match &src {
            Source::Seekable { path: Some(p), .. } => p.clone(),
            Source::Stream { .. } => {
                return Err(Error::Unsupported {
                    format: "msi".into(),
                    feature: "streaming (msi requires seek)".into(),
                });
            }
            Source::Seekable { path: None, .. } => {
                return Err(Error::Unsupported {
                    format: "msi".into(),
                    feature: "seekable source without a path".into(),
                });
            }
        };

        // Open the MSI package. An open failure at this stage means the file
        // is not a valid MSI/CFB database → UnknownFormat.
        let mut package =
            msi::Package::open(std::fs::File::open(&path)?).map_err(|_| Error::UnknownFormat)?;

        // A valid MSI must have the _Tables table (internal MSI metadata). If
        // it doesn't, we treat it as an unrecognised CFB document.
        if !package.has_table("_Tables") {
            return Err(Error::UnknownFormat);
        }

        // Read the Media table to find embedded CAB streams. Rows are only
        // present when the package actually has files to install; an empty
        // (or absent) Media table is valid — we just return zero entries.
        let cab_stream_names: Vec<String> = if package.has_table("Media") {
            let query = msi::Select::table("Media").columns(&["Cabinet"]);
            let rows = package
                .select_rows(query)
                .map_err(|e| Error::Corrupt(format!("msi: reading Media table: {e}")))?;
            let mut names = Vec::new();
            for row in rows {
                // Cabinet values: `#streamname` = embedded, plain name = external.
                // We only support embedded cabs (leading `#`); external cabs
                // (no `#`) and Null values are silently skipped.
                if let Some(stream_name) = row["Cabinet"].as_str().and_then(|c| c.strip_prefix('#'))
                {
                    names.push(stream_name.to_owned());
                }
            }
            names
        } else {
            Vec::new()
        };

        // For each embedded CAB stream: dump bytes to a NamedTempFile, then
        // open with CabHandler. We collect entries and build a routing map.
        let mut inner_readers: Vec<Box<dyn ArchiveReader>> = Vec::new();
        let mut temp_paths: Vec<tempfile::TempPath> = Vec::new();
        let mut all_entries: Vec<Entry> = Vec::new();
        // routing[outer_idx] = (cab_reader_idx, inner_idx)
        let mut routing: Vec<(usize, usize)> = Vec::new();

        // Resolve File/Component/Directory tables to real install paths. `None`
        // means the package lacks one of those tables → keep model-B behavior.
        let resolution = build_file_paths(&mut package);
        // The stream-name prefix is only a fallback uniqueness device; with
        // resolution active, resolved paths are already globally unique.
        let needs_prefix = resolution.is_none() && cab_stream_names.len() > 1;

        for (cab_idx, stream_name) in cab_stream_names.iter().enumerate() {
            // Read the CFB stream into a temp file.
            let mut stream_reader = package
                .read_stream(stream_name)
                .map_err(|e| Error::Corrupt(format!("msi: opening stream {stream_name}: {e}")))?;
            let mut temp_cab = tempfile::NamedTempFile::new()?;
            std::io::copy(&mut stream_reader, &mut temp_cab)?;
            let temp_path = temp_cab.into_temp_path();

            // Open via CabHandler.  Propagate the inner error variant unchanged
            // so that callers can distinguish Unsupported (e.g. Quantum
            // compression) from Corrupt.  Wrapping every CabHandler error into
            // Error::Corrupt would mask the variant and mislead the orchestrator.
            let mut cab_reader = CabHandler.open(Source::path(&temp_path)?, opts)?;

            // Collect entries; apply stream-name prefix when there is >1 cab.
            // Propagate the inner error variant unchanged (same rationale as the
            // open call above).
            let cab_entries = cab_reader.entries()?;

            for (inner_idx, entry) in cab_entries.iter().enumerate() {
                let mut e = entry.clone();
                // The CAB member name is the MSI `File` key. Resolve it to a real
                // install path when the resolution map has it.
                let resolved = resolution
                    .as_ref()
                    .and_then(|m| m.get(entry.path.to_string_lossy().as_ref()));
                if let Some(real) = resolved {
                    e.path = real.clone();
                    e.path_raw = real.to_string_lossy().into_owned().into_bytes();
                } else if needs_prefix {
                    // Fallback: keep the CAB member name, prefixed with the stream
                    // name so files from different cabs stay unique. `path_raw` is
                    // built from its own pre-mutation bytes — do not reorder these
                    // two lines or derive one field from the other.
                    e.path = PathBuf::from(stream_name).join(&e.path);
                    e.path_raw = [stream_name.as_bytes(), b"/", &e.path_raw].concat();
                }
                routing.push((cab_idx, inner_idx));
                all_entries.push(e);
            }

            temp_paths.push(temp_path);
            inner_readers.push(cab_reader);
        }

        Ok(Box::new(MsiReader {
            inner_readers,
            _temps: temp_paths,
            entries: all_entries,
            routing,
        }))
    }
}

/// Reader for an MSI installer. Owns one or more inner CAB readers (one per
/// embedded cab stream) plus the temp files that back them (deleted on drop).
/// Reports `FormatId::Msi`.
struct MsiReader {
    // Field order matters for drop: `inner_readers` (which hold open handles to
    // the temp cabs) must drop before `_temps` (which delete those files).
    inner_readers: Vec<Box<dyn ArchiveReader>>,
    /// Temp files for the extracted CAB bytes; kept alive until drop.
    _temps: Vec<tempfile::TempPath>,
    entries: Vec<Entry>,
    /// `routing[outer_idx] = (cab_reader_index, inner_idx)`
    routing: Vec<(usize, usize)>,
}

impl ArchiveReader for MsiReader {
    fn format(&self) -> FormatId {
        FormatId::Msi
    }

    fn entries(&mut self) -> Result<&[Entry]> {
        Ok(&self.entries)
    }

    fn read_entry(&mut self, idx: usize, out: &mut dyn Write) -> Result<()> {
        if idx >= self.routing.len() {
            return Err(Error::InvalidIndex(idx));
        }
        let (cab_idx, inner_idx) = self.routing[idx];
        self.inner_readers[cab_idx].read_entry(inner_idx, out)
    }
}

/// Extracts the install (long) directory name from a `Directory.DefaultDir`
/// value. `DefaultDir` is `[target][:source]`; each side is `[short|]long`. We
/// take the **target** side's long name. Returns `None` for `.` ("same as
/// parent" — no path segment) and for an empty value.
fn parse_defaultdir_name(default_dir: &str) -> Option<String> {
    // The target dir is everything before the first ':' (the source dir, if
    // present, follows it and is irrelevant for the install layout).
    let target = default_dir.split(':').next().unwrap_or(default_dir);
    // The long name is everything after the last '|' (the short name precedes
    // it); if there is no '|', the whole target is the name.
    let long = target.rsplit('|').next().unwrap_or(target);
    if long.is_empty() || long == "." {
        None
    } else {
        Some(long.to_owned())
    }
}

/// Extracts the long name from a `File.FileName` value (`[short|]long`).
fn parse_filename_long(file_name: &str) -> String {
    file_name.rsplit('|').next().unwrap_or(file_name).to_owned()
}

/// Resolves a `Directory` key to its root→leaf install path.
///
/// `dir_map` maps each `Directory` key to `(Directory_Parent, long name)`. The
/// walk ascends parents until it reaches the root (a row whose parent is
/// `None`, or which points to itself), pushing each non-`None` name, then
/// reverses to root→leaf order. The root row itself never contributes a
/// segment. A `visited` set plus `MAX_DIR_DEPTH` make the walk cycle-safe.
fn resolve_dir_path(
    start: &str,
    dir_map: &std::collections::HashMap<String, (Option<String>, Option<String>)>,
) -> PathBuf {
    let mut segments: Vec<String> = Vec::new();
    let mut visited: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut current = start;
    for _ in 0..MAX_DIR_DEPTH {
        if !visited.insert(current) {
            break; // cycle
        }
        let Some((parent, name)) = dir_map.get(current) else {
            break; // unknown key
        };
        match parent {
            // Non-root node: contribute its name, then ascend.
            Some(p) if p != current => {
                if let Some(n) = name {
                    segments.push(n.clone());
                }
                current = p;
            }
            // Root (null parent or self-parent): contributes no segment; stop.
            _ => break,
        }
    }
    segments.reverse();
    segments.into_iter().collect()
}

/// Builds a `File`-key → resolved-path map by joining the File, Component, and
/// Directory tables. Returns `None` when any of the three tables is absent, in
/// which case the caller keeps model-B member names. Read failures on individual
/// tables degrade to an empty contribution rather than aborting the open.
///
/// The resolved paths are NOT sanitized here: a crafted `DefaultDir`/`FileName`
/// can carry `..` or absolute components. That is safe only because every
/// on-disk write still flows through `path_safety::safe_join` downstream — never
/// make this map the sole path to disk.
fn build_file_paths(package: &mut msi::Package<std::fs::File>) -> Option<HashMap<String, PathBuf>> {
    if !(package.has_table("File")
        && package.has_table("Component")
        && package.has_table("Directory"))
    {
        return None;
    }

    // Directory: key -> (parent, long name).
    let mut dir_map: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    if let Ok(rows) = package.select_rows(msi::Select::table("Directory").columns(&[
        "Directory",
        "Directory_Parent",
        "DefaultDir",
    ])) {
        for row in rows {
            let Some(key) = row["Directory"].as_str() else {
                continue;
            };
            let parent = row["Directory_Parent"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let name = row["DefaultDir"].as_str().and_then(parse_defaultdir_name);
            dir_map.insert(key.to_owned(), (parent, name));
        }
    }

    // Component: component -> directory key.
    let mut comp_map: HashMap<String, String> = HashMap::new();
    if let Ok(rows) =
        package.select_rows(msi::Select::table("Component").columns(&["Component", "Directory_"]))
    {
        for row in rows {
            let (Some(comp), Some(dir_)) = (row["Component"].as_str(), row["Directory_"].as_str())
            else {
                continue;
            };
            comp_map.insert(comp.to_owned(), dir_.to_owned());
        }
    }

    // File: file key -> resolved path. Cache resolved directory paths.
    let mut dir_path_cache: HashMap<String, PathBuf> = HashMap::new();
    let mut file_paths: HashMap<String, PathBuf> = HashMap::new();
    if let Ok(rows) =
        package.select_rows(msi::Select::table("File").columns(&["File", "Component_", "FileName"]))
    {
        for row in rows {
            let Some(file_key) = row["File"].as_str() else {
                continue;
            };
            let Some(comp) = row["Component_"].as_str() else {
                continue;
            };
            let long_name = row["FileName"]
                .as_str()
                .map(parse_filename_long)
                .unwrap_or_else(|| file_key.to_owned());
            let dir_path = match comp_map.get(comp) {
                Some(dir_key) => dir_path_cache
                    .entry(dir_key.clone())
                    .or_insert_with(|| resolve_dir_path(dir_key, &dir_map))
                    .clone(),
                None => PathBuf::new(),
            };
            file_paths.insert(file_key.to_owned(), dir_path.join(long_name));
        }
    }

    Some(file_paths)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfb_header() -> Vec<u8> {
        let mut v = CFB_MAGIC.to_vec();
        v.extend_from_slice(&[0u8; 504]);
        v
    }

    #[test]
    fn id_is_msi() {
        assert_eq!(MsiHandler.id(), FormatId::Msi);
    }

    #[test]
    fn probe_positive_cfb_magic_and_msi_ext() {
        assert_eq!(
            MsiHandler.probe(&cfb_header(), Some("setup.msi")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_positive_case_insensitive_ext() {
        assert_eq!(
            MsiHandler.probe(&cfb_header(), Some("SETUP.MSI")),
            Confidence::MAGIC
        );
    }

    #[test]
    fn probe_negative_cfb_but_wrong_ext() {
        // CFB magic but .doc extension → NONE (don't hijack Office files).
        assert_eq!(
            MsiHandler.probe(&cfb_header(), Some("doc.doc")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_negative_non_cfb_magic() {
        // Non-CFB header + .msi name → NONE.
        assert_eq!(
            MsiHandler.probe(b"PK\x03\x04\x00\x00\x00\x00", Some("setup.msi")),
            Confidence::NONE
        );
    }

    #[test]
    fn probe_negative_no_name() {
        // CFB magic but no file name → NONE.
        assert_eq!(MsiHandler.probe(&cfb_header(), None), Confidence::NONE);
    }

    #[test]
    fn defaultdir_takes_long_target_name() {
        // `short|long` → long; `target:source` → target side.
        assert_eq!(parse_defaultdir_name("APP|MyApp"), Some("MyApp".to_owned()));
        assert_eq!(
            parse_defaultdir_name("APP|MyApp:SRC|MySrc"),
            Some("MyApp".to_owned())
        );
        assert_eq!(
            parse_defaultdir_name("ProgramFilesFolder"),
            Some("ProgramFilesFolder".to_owned())
        );
    }

    #[test]
    fn defaultdir_dot_and_empty_are_none() {
        assert_eq!(parse_defaultdir_name("."), None);
        assert_eq!(parse_defaultdir_name(""), None);
        // `.` on the target side with a source still yields no segment.
        assert_eq!(parse_defaultdir_name(".:SRC|src"), None);
    }

    #[test]
    fn filename_takes_long_name() {
        assert_eq!(parse_filename_long("app.exe"), "app.exe".to_owned());
        assert_eq!(
            parse_filename_long("APP~1.EXE|app.exe"),
            "app.exe".to_owned()
        );
    }

    use std::collections::HashMap;
    use std::path::PathBuf;

    /// Helper: build a dir_map entry.
    fn dir(parent: Option<&str>, name: Option<&str>) -> (Option<String>, Option<String>) {
        (parent.map(str::to_owned), name.map(str::to_owned))
    }

    #[test]
    fn resolve_nested_drops_root_keeps_property_folder() {
        // TARGETDIR (root, no parent, no name) → ProgramFilesFolder → MyApp.
        let mut m = HashMap::new();
        m.insert("TARGETDIR".to_owned(), dir(None, None));
        m.insert(
            "ProgramFilesFolder".to_owned(),
            dir(Some("TARGETDIR"), Some("ProgramFilesFolder")),
        );
        m.insert(
            "MyApp".to_owned(),
            dir(Some("ProgramFilesFolder"), Some("MyApp")),
        );
        assert_eq!(
            resolve_dir_path("MyApp", &m),
            PathBuf::from("ProgramFilesFolder/MyApp")
        );
    }

    #[test]
    fn resolve_dot_segment_is_skipped() {
        // A `.`-named directory contributes no segment.
        let mut m = HashMap::new();
        m.insert("TARGETDIR".to_owned(), dir(None, None));
        m.insert("DOT".to_owned(), dir(Some("TARGETDIR"), None)); // DefaultDir "." → None
        m.insert("Leaf".to_owned(), dir(Some("DOT"), Some("Leaf")));
        assert_eq!(resolve_dir_path("Leaf", &m), PathBuf::from("Leaf"));
    }

    #[test]
    fn resolve_root_itself_is_empty_path() {
        let mut m = HashMap::new();
        m.insert("TARGETDIR".to_owned(), dir(None, None));
        assert_eq!(resolve_dir_path("TARGETDIR", &m), PathBuf::new());
    }

    #[test]
    fn resolve_cycle_is_bounded_no_panic() {
        // A → B → A cycle must terminate without panic or hang.
        let mut m = HashMap::new();
        m.insert("A".to_owned(), dir(Some("B"), Some("A")));
        m.insert("B".to_owned(), dir(Some("A"), Some("B")));
        let p = resolve_dir_path("A", &m);
        // Bounded result; exact value is not important, only that it returns.
        assert!(p.components().count() <= MAX_DIR_DEPTH);
    }

    #[test]
    fn resolve_missing_key_is_empty_path() {
        let m: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
        assert_eq!(resolve_dir_path("nope", &m), PathBuf::new());
    }
}

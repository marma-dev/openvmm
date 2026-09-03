// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read-only host-directory backing for a vSMB share.
//!
//! Provides the filesystem operations the SMB2 server needs to serve a share:
//! path resolution (constrained to the share root), metadata, directory
//! enumeration, and positioned reads. This is deliberately read-only — the
//! image-layer use case — so there are no write/rename/delete paths.

use std::fs::File;
#[cfg(not(windows))]
use std::fs::Metadata;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(windows))]
use std::time::SystemTime;

/// `FILE_ATTRIBUTE_READONLY` (used by the non-Windows fallback metadata path).
#[cfg(not(windows))]
pub const ATTR_READONLY: u32 = 0x0000_0001;
/// `FILE_ATTRIBUTE_DIRECTORY`.
pub const ATTR_DIRECTORY: u32 = 0x0000_0010;
/// `FILE_ATTRIBUTE_NORMAL` (used by the non-Windows fallback metadata path).
#[cfg(not(windows))]
pub const ATTR_NORMAL: u32 = 0x0000_0080;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
pub const ATTR_REPARSE_POINT: u32 = 0x0000_0400;

/// Metadata about a file or directory, in SMB/Windows terms.
#[derive(Clone, Debug)]
pub struct FileInfo {
    /// End-of-file / logical size, in bytes.
    pub size: u64,
    /// Allocation size, in bytes (rounded up to a cluster boundary).
    pub allocation_size: u64,
    /// Windows file attributes (`FILE_ATTRIBUTE_*`).
    pub attributes: u32,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Creation time, as a Windows FILETIME (100ns ticks since 1601-01-01).
    pub creation_time: u64,
    /// Last access time (FILETIME).
    pub last_access_time: u64,
    /// Last write time (FILETIME).
    pub last_write_time: u64,
    /// Change time (FILETIME).
    pub change_time: u64,
    /// Reparse point tag, or 0 if this is not a reparse point. Meaningful only
    /// when `attributes` has `FILE_ATTRIBUTE_REPARSE_POINT`.
    pub reparse_tag: u32,
}

/// A single directory entry produced by enumeration.
#[derive(Clone, Debug)]
pub struct DirEntry {
    /// The file name (no path).
    pub name: String,
    /// The entry's metadata.
    pub info: FileInfo,
}

/// A read-only view of a host directory tree.
pub struct Backing {
    root: PathBuf,
}

impl Backing {
    /// Creates a backing rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolves an SMB relative path (using `\` or `/` separators) to a host
    /// path, rejecting any path that escapes the share root.
    pub fn resolve(&self, rel: &str) -> Option<PathBuf> {
        let mut path = self.root.clone();
        for part in rel.split(['\\', '/']) {
            match part {
                "" | "." => {}
                ".." => return None,
                _ => {
                    // Reject any component that itself contains path separators
                    // or drive/root markers via std's own parsing.
                    let candidate = Path::new(part);
                    let mut comps = candidate.components();
                    match (comps.next(), comps.next()) {
                        (Some(Component::Normal(c)), None) => path.push(c),
                        _ => return None,
                    }
                }
            }
        }
        Some(path)
    }

    /// Returns metadata for the file or directory at `rel`, without following a
    /// trailing reparse point (so junctions/symlinks are reported as reparse
    /// points, which is what layer consumers such as WCIFS need).
    pub fn stat(&self, rel: &str) -> std::io::Result<FileInfo> {
        let path = self
            .resolve(rel)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        stat_path(&path)
    }

    /// Opens a file for reading, using backup semantics on Windows so that
    /// protected layer files can be read (given `SeBackupPrivilege` on the host
    /// process). Directories return an error.
    pub fn open(&self, rel: &str) -> std::io::Result<File> {
        let path = self
            .resolve(rel)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        open_for_read(&path)
    }

    /// Reads up to `len` bytes at `offset` from the file at `rel`.
    pub fn read(&self, rel: &str, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        let mut file = self.open(rel)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        let mut filled = 0;
        while filled < len {
            let n = file.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buf.truncate(filled);
        Ok(buf)
    }

    /// Reads the raw `REPARSE_DATA_BUFFER` for the reparse point at `rel`.
    pub fn read_reparse(&self, rel: &str) -> std::io::Result<Vec<u8>> {
        let path = self
            .resolve(rel)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        #[cfg(windows)]
        {
            win::read_reparse_data(&path)
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        }
    }

    /// Reads the self-relative security descriptor bytes (owner/group/DACL/SACL)
    /// for `rel`, or `None` if unavailable.
    pub fn read_security(&self, rel: &str) -> Option<Vec<u8>> {
        let path = self.resolve(rel)?;
        #[cfg(windows)]
        {
            win::read_security_descriptor(&path)
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            None
        }
    }

    /// Lists the NTFS streams (default `::$DATA` plus any ADS) of `rel` as
    /// `(name, size)` pairs.
    pub fn list_streams(&self, rel: &str) -> Vec<(String, i64)> {
        let Some(path) = self.resolve(rel) else {
            return Vec::new();
        };
        #[cfg(windows)]
        {
            win::list_streams(&path)
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Vec::new()
        }
    }

    /// Enumerates the directory at `rel`, returning entries sorted by name.
    /// Includes `.` and `..` pseudo-entries first, matching Windows behavior.
    pub fn enumerate(&self, rel: &str) -> std::io::Result<Vec<DirEntry>> {
        let path = self
            .resolve(rel)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        let mut entries = Vec::new();

        let self_info = stat_path(&path)?;
        entries.push(DirEntry {
            name: ".".to_owned(),
            info: self_info.clone(),
        });
        entries.push(DirEntry {
            name: "..".to_owned(),
            info: self_info,
        });

        let mut children: Vec<DirEntry> = Vec::new();
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let child = entry.path();
            let info = match stat_path(&child) {
                Ok(i) => i,
                Err(_) => continue,
            };
            children.push(DirEntry { name, info });
        }
        children.sort_by_key(|e| e.name.to_ascii_lowercase());
        entries.extend(children);
        Ok(entries)
    }
}

/// Returns faithful metadata for `path` without following a trailing reparse
/// point. On Windows this reports the real file attributes (including the
/// `FILE_ATTRIBUTE_REPARSE_POINT` bit) and FILETIME timestamps; on other
/// platforms it falls back to std metadata (used for host-side tests).
fn stat_path(path: &Path) -> std::io::Result<FileInfo> {
    // `symlink_metadata` does not follow a trailing reparse point, so junctions
    // and symlinks are reported as reparse points (what WCIFS layer consumers
    // need) rather than their targets.
    let meta = std::fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let attributes = meta.file_attributes();
        let is_dir = attributes & ATTR_DIRECTORY != 0;
        let size = if is_dir { 0 } else { meta.file_size() };
        let allocation_size = size.div_ceil(4096) * 4096;
        let last_write_time = meta.last_write_time();
        let reparse_tag = if attributes & ATTR_REPARSE_POINT != 0 {
            win::reparse_tag(path).unwrap_or(0)
        } else {
            0
        };
        Ok(FileInfo {
            size,
            allocation_size,
            attributes,
            is_dir,
            creation_time: meta.creation_time(),
            last_access_time: meta.last_access_time(),
            last_write_time,
            change_time: last_write_time,
            reparse_tag,
        })
    }
    #[cfg(not(windows))]
    {
        Ok(file_info_from_meta(&meta))
    }
}

/// `FILE_FLAG_BACKUP_SEMANTICS` — lets the host read protected layer files and
/// open directories (given `SeBackupPrivilege` on the host process).
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// Windows-specific helpers that require the Win32 API. Isolated in its own
/// module that opts into `unsafe` (following the `lxutil` pattern), keeping the
/// rest of the crate `unsafe`-free.
#[cfg(windows)]
mod win {
    // UNSAFETY: calling the Win32 GetFileInformationByHandleEx API to read a
    // file's reparse tag, which has no safe std equivalent.
    #![expect(unsafe_code)]

    use std::fs::OpenOptions;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::DACL_SECURITY_INFORMATION;
    use windows::Win32::Security::GROUP_SECURITY_INFORMATION;
    use windows::Win32::Security::GetFileSecurityW;
    use windows::Win32::Security::OWNER_SECURITY_INFORMATION;
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;
    use windows::Win32::Security::SACL_SECURITY_INFORMATION;
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_TAG_INFO;
    use windows::Win32::Storage::FileSystem::FileAttributeTagInfo;
    use windows::Win32::Storage::FileSystem::FindClose;
    use windows::Win32::Storage::FileSystem::FindFirstStreamW;
    use windows::Win32::Storage::FileSystem::FindNextStreamW;
    use windows::Win32::Storage::FileSystem::FindStreamInfoStandard;
    use windows::Win32::Storage::FileSystem::GetFileInformationByHandleEx;
    use windows::Win32::Storage::FileSystem::WIN32_FIND_STREAM_DATA;
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
    use windows::core::PCWSTR;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    /// `MAXIMUM_REPARSE_DATA_BUFFER_SIZE`.
    const MAX_REPARSE_SIZE: usize = 16 * 1024;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Reads the reparse tag of the reparse point at `path`, or `None` if it
    /// cannot be opened/queried. Opens the reparse point itself (does not
    /// follow it) with backup semantics.
    pub fn reparse_tag(path: &Path) -> Option<u32> {
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .ok()?;
        let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: `info` is a valid, correctly sized FILE_ATTRIBUTE_TAG_INFO and
        // `file` owns a live handle for the duration of the call;
        // GetFileInformationByHandleEx fills `info` on success.
        let result = unsafe {
            GetFileInformationByHandleEx(
                HANDLE(file.as_raw_handle()),
                FileAttributeTagInfo,
                (&raw mut info).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        result.ok()?;
        Some(info.ReparseTag)
    }

    /// Reads the raw `REPARSE_DATA_BUFFER` for the reparse point at `path` via
    /// `FSCTL_GET_REPARSE_POINT`.
    pub fn read_reparse_data(path: &Path) -> std::io::Result<Vec<u8>> {
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let mut buf = vec![0u8; MAX_REPARSE_SIZE];
        let mut returned = 0u32;
        // SAFETY: `buf` is a valid, MAX_REPARSE_SIZE-byte output buffer and
        // `file` owns a live handle; DeviceIoControl writes `returned` bytes.
        let result = unsafe {
            DeviceIoControl(
                HANDLE(file.as_raw_handle()),
                FSCTL_GET_REPARSE_POINT,
                None,
                0,
                Some(buf.as_mut_ptr().cast()),
                buf.len() as u32,
                Some(&mut returned),
                None,
            )
        };
        result.map_err(std::io::Error::other)?;
        buf.truncate(returned as usize);
        Ok(buf)
    }

    /// Reads the self-relative security descriptor bytes for `path`
    /// (owner/group/DACL, and SACL when permitted), or `None`.
    pub fn read_security_descriptor(path: &Path) -> Option<Vec<u8>> {
        let w = wide(path);
        let full: u32 = (OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | SACL_SECURITY_INFORMATION)
            .0;
        if let Some(sd) = read_sd_with(&w, full) {
            return Some(sd);
        }
        // The SACL requires SeSecurityPrivilege; retry without it.
        let no_sacl: u32 =
            (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0;
        read_sd_with(&w, no_sacl)
    }

    fn read_sd_with(w: &[u16], info: u32) -> Option<Vec<u8>> {
        let mut needed = 0u32;
        // SAFETY: `w` is a valid NUL-terminated path; the size-probe call passes
        // a null/zero-length buffer so GetFileSecurityW reports the required
        // size in `needed` (and returns an error, which is expected).
        let _ = unsafe { GetFileSecurityW(PCWSTR(w.as_ptr()), info, None, 0, &mut needed) };
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        let mut got = 0u32;
        // SAFETY: `buf` is `needed` bytes and `w` is a valid NUL-terminated path;
        // GetFileSecurityW writes the self-relative descriptor into `buf`.
        let result = unsafe {
            GetFileSecurityW(
                PCWSTR(w.as_ptr()),
                info,
                Some(PSECURITY_DESCRIPTOR(buf.as_mut_ptr().cast())),
                buf.len() as u32,
                &mut got,
            )
        };
        if !result.as_bool() {
            return None;
        }
        buf.truncate(got as usize);
        Some(buf)
    }

    /// Lists the NTFS streams of `path` as `(name, size)` pairs, where `name`
    /// is the raw stream name (e.g. `::$DATA` or `:ads:$DATA`).
    pub fn list_streams(path: &Path) -> Vec<(String, i64)> {
        let w = wide(path);
        let mut data = WIN32_FIND_STREAM_DATA::default();
        // SAFETY: `data` is a valid WIN32_FIND_STREAM_DATA and `w` is a valid
        // NUL-terminated path; FindFirstStreamW fills `data` on success.
        let handle = match unsafe {
            FindFirstStreamW(
                PCWSTR(w.as_ptr()),
                FindStreamInfoStandard,
                (&raw mut data).cast(),
                None,
            )
        } {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        loop {
            let name = wstr_from_slice(&data.cStreamName);
            out.push((name, data.StreamSize));
            // SAFETY: `handle` is a live find handle and `data` is valid;
            // FindNextStreamW advances the enumeration.
            if unsafe { FindNextStreamW(handle, (&raw mut data).cast()) }.is_err() {
                break;
            }
        }
        // SAFETY: `handle` is a live find handle returned by FindFirstStreamW.
        let _ = unsafe { FindClose(handle) };
        out
    }

    fn wstr_from_slice(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }
}

/// Opens `path` for reading, with backup semantics on Windows.
fn open_for_read(path: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

/// Builds a [`FileInfo`] from std metadata, converting times to FILETIME and
/// setting Windows attributes. Used on non-Windows hosts (host-side tests);
/// the Windows path uses `stat_path`'s `MetadataExt` branch for faithful
/// attributes and timestamps.
#[cfg(not(windows))]
fn file_info_from_meta(meta: &Metadata) -> FileInfo {
    let is_dir = meta.is_dir();
    let size = if is_dir { 0 } else { meta.len() };
    // Round the allocation size up to a 4 KiB boundary as a reasonable default.
    let allocation_size = size.div_ceil(4096) * 4096;

    let creation_time = meta.created().map(to_filetime).unwrap_or(0);
    let last_access_time = meta.accessed().map(to_filetime).unwrap_or(0);
    let last_write_time = meta.modified().map(to_filetime).unwrap_or(0);

    let attributes = if is_dir {
        ATTR_DIRECTORY
    } else {
        ATTR_READONLY | ATTR_NORMAL
    };

    FileInfo {
        size,
        allocation_size,
        attributes,
        is_dir,
        creation_time,
        last_access_time,
        last_write_time,
        change_time: last_write_time,
        reparse_tag: 0,
    }
}

/// Number of 100ns ticks between 1601-01-01 (FILETIME epoch) and the Unix
/// epoch (1970-01-01).
#[cfg(not(windows))]
const FILETIME_UNIX_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// Converts a `SystemTime` to a Windows FILETIME (100ns ticks since 1601).
#[cfg(not(windows))]
fn to_filetime(time: SystemTime) -> u64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(dur) => {
            let ticks = dur
                .as_secs()
                .saturating_mul(10_000_000)
                .saturating_add((dur.subsec_nanos() / 100) as u64);
            ticks.saturating_add(FILETIME_UNIX_EPOCH_DIFF)
        }
        Err(_) => FILETIME_UNIX_EPOCH_DIFF,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rejects_traversal() {
        let b = Backing::new("C:\\layers");
        assert!(b.resolve("..\\secret").is_none());
        assert!(b.resolve("a\\..\\..\\b").is_none());
        assert!(b.resolve("ok\\sub\\file.txt").is_some());
    }

    #[test]
    fn resolve_ignores_dot_and_empty() {
        let b = Backing::new("root");
        let p = b.resolve(".\\a\\\\b\\.\\c").unwrap();
        assert!(p.ends_with(Path::new("a").join("b").join("c")));
    }

    #[cfg(windows)]
    #[test]
    fn reparse_symlink_detected() {
        let dir = std::env::temp_dir().join(format!("vsmb-reparse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let link = dir.join("link");
        // Directory symlink creation needs SeCreateSymbolicLinkPrivilege
        // (developer mode/admin); skip the assertion if it is unavailable.
        if std::os::windows::fs::symlink_dir(&target, &link).is_err() {
            std::fs::remove_dir_all(&dir).ok();
            return;
        }
        let b = Backing::new(&dir);
        let info = b.stat("link").unwrap();
        assert_ne!(info.attributes & ATTR_REPARSE_POINT, 0);
        assert_eq!(info.reparse_tag, 0xA000_000C); // IO_REPARSE_TAG_SYMLINK
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_and_enumerate_tempdir() {
        let dir = std::env::temp_dir().join(format!("vsmb-backing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("hello.txt");
        std::fs::write(&file, b"hello world").unwrap();

        let b = Backing::new(&dir);
        let info = b.stat("hello.txt").unwrap();
        assert_eq!(info.size, 11);
        assert!(!info.is_dir);
        // A regular file always has at least one attribute set (ARCHIVE on
        // Windows real metadata; synthesized NORMAL/READONLY elsewhere) and is
        // never a reparse point.
        assert_ne!(info.attributes, 0);
        assert_eq!(info.attributes & ATTR_DIRECTORY, 0);
        assert_eq!(info.attributes & ATTR_REPARSE_POINT, 0);
        assert_eq!(info.reparse_tag, 0);

        let data = b.read("hello.txt", 6, 5).unwrap();
        assert_eq!(&data, b"world");

        let entries = b.enumerate("").unwrap();
        assert_eq!(entries[0].name, ".");
        assert_eq!(entries[1].name, "..");
        assert!(entries.iter().any(|e| e.name == "hello.txt"));

        std::fs::remove_dir_all(&dir).ok();
    }
}

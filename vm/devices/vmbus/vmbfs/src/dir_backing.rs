// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implements a backing store for the vmbus file system that serves a host
//! directory tree read-only.
//!
//! This is used to boot a UVM whose OS files live in a host directory (the
//! `UtilityVM\Files` tree of a WCOW image layer), mirroring the way hcsshim
//! serves the boot files to the Hyper-V UEFI firmware over the vmbfs BOOT
//! instance. The vmbfs protocol is path-based (`GET_FILE_INFO` + `READ_FILE`),
//! so no directory enumeration is required — the boot loader reads files by
//! their known paths.

use crate::backing::FileError;
use crate::backing::FileInfo;
use crate::backing::VmbfsIo;
use inspect::InspectMut;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::path::PathBuf;

/// A backing store that serves files from a host directory tree, addressed by
/// path. Read-only.
#[derive(InspectMut)]
pub struct VmbfsDirBacking {
    #[inspect(with = "|x| x.display().to_string()")]
    root: PathBuf,
    // A single-entry cache of the last-opened file, so that the sequential
    // chunked reads the boot loader issues for a single file don't reopen it
    // on every request.
    #[inspect(skip)]
    open: Option<(String, File)>,
}

impl VmbfsDirBacking {
    /// Serves the contents of `root` read-only over vmbfs.
    pub fn new(root: PathBuf) -> Self {
        Self { root, open: None }
    }

    /// Resolves a guest-supplied vmbfs path (forward-slash separated, absolute)
    /// to a host path under `root`, rejecting any attempt to escape the root.
    fn resolve(&self, path: &str) -> Option<PathBuf> {
        let mut out = self.root.clone();
        for comp in path.split('/') {
            match comp {
                "" | "." => {}
                ".." => return None,
                c => {
                    // Reject anything that could reinterpret the path outside
                    // `root` (drive-relative, alternate separators, etc.).
                    if c.contains('\\') || c.contains(':') {
                        return None;
                    }
                    out.push(c);
                }
            }
        }
        Some(out)
    }
}

impl VmbfsIo for VmbfsDirBacking {
    fn file_info(&mut self, path: &str) -> Result<FileInfo, FileError> {
        let full = self.resolve(path).ok_or(FileError::NotFound)?;
        let metadata = std::fs::metadata(&full)?;
        Ok(FileInfo {
            directory: metadata.is_dir(),
            file_size: metadata.len(),
        })
    }

    fn read_file(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<(), FileError> {
        // Reuse the cached handle if this read targets the same file.
        if self.open.as_ref().map(|(p, _)| p.as_str()) != Some(path) {
            let full = self.resolve(path).ok_or(FileError::NotFound)?;
            let file = File::open(&full)?;
            self.open = Some((path.to_owned(), file));
        }
        let file = &mut self.open.as_mut().unwrap().1;
        file.seek(std::io::SeekFrom::Start(offset))?;
        file.read_exact(buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backing::VmbfsIo;

    #[test]
    fn serves_tree_by_path() {
        let dir = std::env::temp_dir().join(format!("vmbfs-dir-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("EFI/Microsoft/Boot")).unwrap();
        std::fs::write(dir.join("EFI/Microsoft/Boot/bootmgfw.efi"), b"MZ-boot-mgr").unwrap();

        let mut b = VmbfsDirBacking::new(dir.clone());

        // Directory info.
        let info = b.file_info("/EFI/Microsoft/Boot").unwrap();
        assert!(info.directory);

        // File info + read (both slash forms the device produces are '/').
        let info = b.file_info("/EFI/Microsoft/Boot/bootmgfw.efi").unwrap();
        assert!(!info.directory);
        assert_eq!(info.file_size, 11);
        let mut buf = [0u8; 2];
        b.read_file("/EFI/Microsoft/Boot/bootmgfw.efi", 0, &mut buf)
            .unwrap();
        assert_eq!(&buf, b"MZ");

        // Missing file and traversal are rejected.
        assert!(matches!(b.file_info("/nope.efi"), Err(FileError::NotFound)));
        assert!(matches!(
            b.file_info("/../secret"),
            Err(FileError::NotFound)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A minimal read-only SMB2 server for vSMB.
//!
//! This drives the connect path (NEGOTIATE, SESSION_SETUP, TREE_CONNECT) and
//! the read path (CREATE, READ, QUERY_INFO, QUERY_DIRECTORY, CLOSE). It
//! operates on decoded SMB2 segments (the vSMB transport framing is handled by
//! the caller) and produces SMB2 response byte buffers. The server is
//! unconditionally read-only, matching the image-layer use case.

use crate::backing::Backing;
use crate::backing::DirEntry;
use crate::backing::FileInfo;
use crate::smb2;
use smb2::status;
use std::collections::HashMap;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

/// A configured read-only share.
#[derive(Clone)]
pub struct Share {
    /// The host directory backing the share.
    pub root: String,
}

/// Internal per-share state: the filesystem backing. The server is
/// unconditionally read-only, so no write policy is stored here yet.
struct ShareState {
    backing: Backing,
}

/// An open file or directory handle.
struct OpenHandle {
    tree_id: u32,
    rel_path: String,
    info: FileInfo,
    /// Cached directory enumeration and cursor, for QUERY_DIRECTORY.
    dir_entries: Option<Vec<DirEntry>>,
    dir_cursor: usize,
}

/// The read-only SMB2 server state for a single vSMB connection.
pub struct Smb2Server {
    shares: HashMap<String, ShareState>,
    negotiated: bool,
    next_session_id: u64,
    next_tree_id: u32,
    next_file_id: u64,
    sessions: HashMap<u64, ()>,
    trees: HashMap<u32, String>,
    open_files: HashMap<u64, OpenHandle>,
}

impl Smb2Server {
    /// Creates a server exposing the given shares (keyed by share name,
    /// case-insensitive).
    pub fn new(shares: impl IntoIterator<Item = (String, Share)>) -> Self {
        let mut shares: HashMap<String, ShareState> = shares
            .into_iter()
            .map(|(name, share)| {
                (
                    name.to_ascii_lowercase(),
                    ShareState {
                        backing: Backing::new(share.root),
                    },
                )
            })
            .collect();

        // Expose the built-in `defaultEmptyShare` keepalive share that the guest
        // vSMB redirector opens to establish/maintain the connection (as the
        // real Hyper-V vSMB server does). It is backed by an empty host dir.
        let empty_dir = std::env::temp_dir().join(format!("vsmb-empty-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&empty_dir);
        shares
            .entry("defaultemptyshare".to_owned())
            .or_insert_with(|| ShareState {
                backing: Backing::new(empty_dir),
            });

        Self {
            shares,
            negotiated: false,
            next_session_id: 1,
            next_tree_id: 1,
            next_file_id: 1,
            sessions: HashMap::new(),
            trees: HashMap::new(),
            open_files: HashMap::new(),
        }
    }

    /// Handles one decoded SMB2 request segment, returning the response bytes
    /// to send back (already SMB2-framed, without the vSMB segment header).
    ///
    /// Supports SMB2 compound requests (MS-SMB2 2.2.1.2 / 3.3.5.2.7): the
    /// segment may chain several commands via the header `NextCommand` field,
    /// and "related" compounds reuse the FileId produced by a preceding
    /// `CREATE` (sentinel FileId `0xFFFF…`). The response is a matching
    /// compound.
    ///
    /// Returns `None` if the request could not be parsed at all (the caller
    /// should drop the connection).
    pub fn handle(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        smb2::parse_header(payload)?; // validate the first header

        let mut responses: Vec<Vec<u8>> = Vec::new();
        let mut last_create_fid: Option<[u8; 16]> = None;
        let mut off = 0usize;

        loop {
            let (header, _) = smb2::parse_header(payload.get(off..)?)?;
            let next = header.next_command.get() as usize;
            let cmd_end = if next != 0 {
                off.checked_add(next)?
            } else {
                payload.len()
            };
            if cmd_end > payload.len() || cmd_end < off + smb2::HEADER_SIZE {
                return None;
            }
            let body = &payload[off + smb2::HEADER_SIZE..cmd_end];

            // For a related compound, substitute the previous CREATE's FileId
            // wherever a command carries the sentinel FileId.
            let related = header.flags.get() & smb2::FLAGS_RELATED_OPERATIONS != 0;
            let patched;
            let body_ref: &[u8] = match (
                related.then_some(()),
                last_create_fid,
                file_id_offset(header.command.get()),
            ) {
                (Some(()), Some(fid), Some(foff))
                    if body.len() >= foff + 16 && body[foff..foff + 16] == SENTINEL_FILE_ID =>
                {
                    let mut b = body.to_vec();
                    b[foff..foff + 16].copy_from_slice(&fid);
                    patched = b;
                    &patched
                }
                _ => body,
            };

            let resp = self.dispatch(&header, body_ref);

            // Capture the FileId from a successful CREATE so later related
            // commands in the chain can reference the opened handle.
            if header.command.get() == smb2::command::CREATE {
                if let Some((h, rest)) = smb2::parse_header(&resp) {
                    if h.status.get() == status::SUCCESS && rest.len() >= 80 {
                        let mut fid = [0u8; 16];
                        fid.copy_from_slice(&rest[64..80]);
                        last_create_fid = Some(fid);
                    }
                }
            }

            responses.push(resp);
            if next == 0 {
                break;
            }
            off += next;
            if off >= payload.len() {
                break;
            }
        }

        // Assemble the compound response: 8-byte-align each non-final response
        // and set its NextCommand to the aligned distance to the following one.
        let mut out = Vec::new();
        for (i, resp) in responses.iter().enumerate() {
            let start = out.len();
            out.extend_from_slice(resp);
            if i + 1 < responses.len() {
                let aligned = out.len().next_multiple_of(8);
                out.resize(aligned, 0);
                let next_off = (out.len() - start) as u32;
                // NextCommand lives at offset 20 within the SMB2 header.
                out[start + 20..start + 24].copy_from_slice(&next_off.to_le_bytes());
            }
        }
        Some(out)
    }

    /// Dispatches a single (already de-compounded) SMB2 command to its handler,
    /// converting a handler error into an SMB2 error response.
    fn dispatch(&mut self, header: &smb2::Header, body: &[u8]) -> Vec<u8> {
        let result = match header.command.get() {
            smb2::command::NEGOTIATE => self.negotiate(header, body),
            smb2::command::SESSION_SETUP => self.session_setup(header, body),
            smb2::command::TREE_CONNECT => self.tree_connect(header, body),
            smb2::command::TREE_DISCONNECT => self.tree_disconnect(header),
            smb2::command::CREATE => self.create(header, body),
            smb2::command::READ => self.read(header, body),
            smb2::command::IOCTL => self.ioctl(header, body),
            smb2::command::QUERY_INFO => self.query_info(header, body),
            smb2::command::QUERY_DIRECTORY => self.query_directory(header, body),
            smb2::command::CLOSE => self.close(header, body),
            smb2::command::LOGOFF => Ok(self.simple_status_response(header, 4, status::SUCCESS)),
            _ => Err(status::NOT_SUPPORTED),
        };
        match result {
            Ok(bytes) => bytes,
            Err(nt_status) => self.error_response(header, nt_status),
        }
    }

    fn negotiate(&mut self, header: &smb2::Header, body: &[u8]) -> Result<Vec<u8>, u32> {
        let (req, _) = smb2::NegotiateRequest::read_from_prefix(body)
            .map_err(|_| status::INVALID_PARAMETER)?;
        let count = req.dialect_count.get() as usize;
        let byte_count = count.checked_mul(2).ok_or(status::INVALID_PARAMETER)?;
        let dialects_bytes = body
            .get(size_of::<smb2::NegotiateRequest>()..)
            .and_then(|b| b.get(..byte_count))
            .ok_or(status::INVALID_PARAMETER)?;
        let offered: Vec<u16> = dialects_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();

        // Prefer 2.0.2 to keep the server minimal (no signing/encryption/
        // leasing negotiation required).
        let chosen = if offered.contains(&smb2::DIALECT_2_0_2) {
            smb2::DIALECT_2_0_2
        } else if offered.contains(&smb2::DIALECT_2_1_0) {
            smb2::DIALECT_2_1_0
        } else {
            return Err(status::NOT_SUPPORTED);
        };

        self.negotiated = true;

        let resp = smb2::NegotiateResponse {
            structure_size: 65.into(),
            security_mode: 0.into(),
            dialect_revision: chosen.into(),
            negotiate_context_count: 0.into(),
            server_guid: *b"openvmm-vsmb\0\0\0\0",
            capabilities: 0.into(),
            // NOTE: capping these does NOT keep the redirector on the inline
            // path — bulk reads still switch to GPA-direct (DirectMap), which
            // is not yet serviced, so only small/bounded transfers work today.
            max_transact_size: (1 << 20).into(),
            max_read_size: (1 << 20).into(),
            max_write_size: (1 << 20).into(),
            system_time: 0.into(),
            server_start_time: 0.into(),
            // No security buffer (guest auth): point just past the fixed part.
            security_buffer_offset: ((smb2::HEADER_SIZE + 64) as u16).into(),
            security_buffer_length: 0.into(),
            negotiate_context_offset: 0.into(),
        };
        Ok(self.assemble(header, status::SUCCESS, resp.as_bytes(), &[]))
    }

    fn session_setup(&mut self, header: &smb2::Header, body: &[u8]) -> Result<Vec<u8>, u32> {
        let (_req, _) = smb2::SessionSetupRequest::read_from_prefix(body)
            .map_err(|_| status::INVALID_PARAMETER)?;

        // Guest-auth fast path: accept an (unauthenticated) guest session
        // regardless of the security buffer contents. This mirrors the Hyper-V
        // vSMB engine's behavior for an empty/absent security buffer.
        let session_id = if header.session_id.get() != 0 {
            header.session_id.get()
        } else {
            let id = self.next_session_id;
            self.next_session_id += 1;
            id
        };
        self.sessions.insert(session_id, ());

        let resp = smb2::SessionSetupResponse {
            structure_size: 9.into(),
            session_flags: smb2::SESSION_FLAG_IS_GUEST.into(),
            security_buffer_offset: ((smb2::HEADER_SIZE + 8) as u16).into(),
            security_buffer_length: 0.into(),
        };

        let mut out = self.assemble(header, status::SUCCESS, resp.as_bytes(), &[]);
        // Patch the session id into the response header (it is freshly minted
        // on the first setup, so it isn't present on the request header).
        let sid = session_id.to_le_bytes();
        out[40..48].copy_from_slice(&sid);
        Ok(out)
    }

    fn tree_connect(&mut self, header: &smb2::Header, body: &[u8]) -> Result<Vec<u8>, u32> {
        let (req, _) = smb2::TreeConnectRequest::read_from_prefix(body)
            .map_err(|_| status::INVALID_PARAMETER)?;
        let off = req.path_offset.get() as usize;
        let len = req.path_length.get() as usize;
        // The path offset is relative to the start of the SMB2 header.
        let start = off
            .checked_sub(smb2::HEADER_SIZE)
            .ok_or(status::INVALID_PARAMETER)?;
        let path_bytes = body
            .get(start..start.checked_add(len).ok_or(status::INVALID_PARAMETER)?)
            .ok_or(status::INVALID_PARAMETER)?;
        let path = utf16_to_string(path_bytes).ok_or(status::INVALID_PARAMETER)?;

        // Path is a UNC of the form \\server\share; take the last component.
        let share_name = path.rsplit('\\').next().unwrap_or("").to_ascii_lowercase();
        if !self.shares.contains_key(&share_name) {
            return Err(status::BAD_NETWORK_NAME);
        }

        let tree_id = self.next_tree_id;
        self.next_tree_id += 1;
        self.trees.insert(tree_id, share_name);

        let resp = smb2::TreeConnectResponse {
            structure_size: 16.into(),
            share_type: smb2::SHARE_TYPE_DISK,
            reserved: 0,
            share_flags: 0.into(),
            capabilities: 0.into(),
            // Read/execute/list access; read-only server.
            maximal_access: 0x0012_00A9.into(),
        };
        let mut out = self.assemble(header, status::SUCCESS, resp.as_bytes(), &[]);
        // Patch the freshly minted tree id into the response header.
        out[36..40].copy_from_slice(&tree_id.to_le_bytes());
        Ok(out)
    }

    fn tree_disconnect(&mut self, header: &smb2::Header) -> Result<Vec<u8>, u32> {
        let tree_id = header.tree_id.get();
        self.trees.remove(&tree_id);
        self.open_files.retain(|_, h| h.tree_id != tree_id);
        Ok(self.simple_status_response(header, 4, status::SUCCESS))
    }

    fn create(&mut self, header: &smb2::Header, body: &[u8]) -> Result<Vec<u8>, u32> {
        let tree_id = header.tree_id.get();
        let share_name = self
            .trees
            .get(&tree_id)
            .ok_or(status::INVALID_PARAMETER)?
            .clone();
        let share = self
            .shares
            .get(&share_name)
            .ok_or(status::BAD_NETWORK_NAME)?;

        let (req, _) =
            smb2::CreateRequest::read_from_prefix(body).map_err(|_| status::INVALID_PARAMETER)?;

        // Only reads are supported; reject anything but FILE_OPEN.
        if req.create_disposition.get() != smb2::FILE_OPEN {
            return Err(status::ACCESS_DENIED);
        }

        let name = read_buffer_utf16(body, req.name_offset.get(), req.name_length.get())
            .ok_or(status::INVALID_PARAMETER)?;

        let info = match share.backing.stat(&name) {
            Ok(info) => info,
            Err(err) => return Err(map_io_error(&err)),
        };

        let file_id = self.next_file_id;
        self.next_file_id += 1;
        self.open_files.insert(
            file_id,
            OpenHandle {
                tree_id,
                rel_path: name,
                info: info.clone(),
                dir_entries: None,
                dir_cursor: 0,
            },
        );

        let mut file_id_bytes = [0u8; 16];
        file_id_bytes[..8].copy_from_slice(&file_id.to_le_bytes());

        let resp = smb2::CreateResponse {
            structure_size: 89.into(),
            oplock_level: 0,
            flags: 0,
            create_action: smb2::CREATE_ACTION_OPENED.into(),
            creation_time: info.creation_time.into(),
            last_access_time: info.last_access_time.into(),
            last_write_time: info.last_write_time.into(),
            change_time: info.change_time.into(),
            allocation_size: info.allocation_size.into(),
            end_of_file: info.size.into(),
            file_attributes: info.attributes.into(),
            reserved2: 0.into(),
            file_id: file_id_bytes,
            create_contexts_offset: 0.into(),
            create_contexts_length: 0.into(),
        };
        Ok(self.assemble(header, status::SUCCESS, resp.as_bytes(), &[]))
    }

    fn read(&mut self, header: &smb2::Header, body: &[u8]) -> Result<Vec<u8>, u32> {
        let (req, _) =
            smb2::ReadRequest::read_from_prefix(body).map_err(|_| status::INVALID_PARAMETER)?;
        let file_id = file_id_u64(&req.file_id);
        let handle = self
            .open_files
            .get(&file_id)
            .ok_or(status::INVALID_PARAMETER)?;
        if handle.info.is_dir {
            return Err(status::INVALID_DEVICE_REQUEST);
        }
        let share = self
            .shares
            .get(
                self.trees
                    .get(&handle.tree_id)
                    .ok_or(status::INVALID_PARAMETER)?,
            )
            .ok_or(status::BAD_NETWORK_NAME)?;

        let length = req.length.get() as usize;
        let offset = req.offset.get();
        let data = match share.backing.read(&handle.rel_path, offset, length) {
            Ok(d) => d,
            Err(err) => return Err(map_io_error(&err)),
        };
        if data.is_empty() && length > 0 {
            return Err(status::END_OF_FILE);
        }

        // The data follows the fixed 16-byte response body, so DataOffset is
        // HEADER_SIZE + 16 from the start of the SMB2 message.
        let data_offset = (smb2::HEADER_SIZE + 16) as u8;
        let resp = smb2::ReadResponse {
            structure_size: 17.into(),
            data_offset,
            reserved: 0,
            data_length: (data.len() as u32).into(),
            data_remaining: 0.into(),
            reserved2: 0.into(),
        };
        Ok(self.assemble(header, status::SUCCESS, resp.as_bytes(), &data))
    }

    fn query_info(&mut self, header: &smb2::Header, body: &[u8]) -> Result<Vec<u8>, u32> {
        let (req, _) = smb2::QueryInfoRequest::read_from_prefix(body)
            .map_err(|_| status::INVALID_PARAMETER)?;
        let file_id = file_id_u64(&req.file_id);

        // Security-descriptor query: return the file's self-relative SD.
        if req.info_type == smb2::INFO_TYPE_SECURITY {
            let (share_name, rel) = {
                let handle = self
                    .open_files
                    .get(&file_id)
                    .ok_or(status::INVALID_PARAMETER)?;
                let share = self
                    .trees
                    .get(&handle.tree_id)
                    .ok_or(status::INVALID_PARAMETER)?
                    .clone();
                (share, handle.rel_path.clone())
            };
            let share = self
                .shares
                .get(&share_name)
                .ok_or(status::BAD_NETWORK_NAME)?;
            let sd = share
                .backing
                .read_security(&rel)
                .ok_or(status::ACCESS_DENIED)?;
            if sd.len() > req.output_buffer_length.get() as usize {
                // Client must retry with a larger buffer (MS-SMB2 3.3.5.20.3).
                return Err(status::BUFFER_TOO_SMALL);
            }
            return Ok(self.output_buffer_response(header, &sd));
        }

        if req.info_type != smb2::INFO_TYPE_FILE {
            return Err(status::NOT_SUPPORTED);
        }

        // Stream (ADS) enumeration needs the backing, not just the cached info.
        if req.file_info_class == smb2::file_info_class::STREAM {
            let (share_name, rel) = {
                let handle = self
                    .open_files
                    .get(&file_id)
                    .ok_or(status::INVALID_PARAMETER)?;
                let share = self
                    .trees
                    .get(&handle.tree_id)
                    .ok_or(status::INVALID_PARAMETER)?
                    .clone();
                (share, handle.rel_path.clone())
            };
            let share = self
                .shares
                .get(&share_name)
                .ok_or(status::BAD_NETWORK_NAME)?;
            let streams = share.backing.list_streams(&rel);
            let out = encode_stream_info(&streams);
            return Ok(self.output_buffer_response(header, &out));
        }

        let handle = self
            .open_files
            .get(&file_id)
            .ok_or(status::INVALID_PARAMETER)?;
        let info = &handle.info;

        let out = match req.file_info_class {
            smb2::file_info_class::BASIC => encode_basic_info(info),
            smb2::file_info_class::STANDARD => encode_standard_info(info),
            smb2::file_info_class::NETWORK_OPEN => encode_network_open_info(info),
            smb2::file_info_class::ATTRIBUTE_TAG => encode_attribute_tag_info(info),
            _ => return Err(status::NOT_SUPPORTED),
        };
        Ok(self.output_buffer_response(header, &out))
    }

    fn ioctl(&mut self, header: &smb2::Header, body: &[u8]) -> Result<Vec<u8>, u32> {
        let (req, _) =
            smb2::IoctlRequest::read_from_prefix(body).map_err(|_| status::INVALID_PARAMETER)?;
        let ctl_code = req.ctl_code.get();
        if ctl_code != smb2::FSCTL_GET_REPARSE_POINT {
            return Err(status::NOT_SUPPORTED);
        }
        let file_id = file_id_u64(&req.file_id);
        let (share_name, rel, is_reparse) = {
            let handle = self
                .open_files
                .get(&file_id)
                .ok_or(status::INVALID_PARAMETER)?;
            let share = self
                .trees
                .get(&handle.tree_id)
                .ok_or(status::INVALID_PARAMETER)?
                .clone();
            let is_reparse = handle.info.attributes & crate::backing::ATTR_REPARSE_POINT != 0;
            (share, handle.rel_path.clone(), is_reparse)
        };
        if !is_reparse {
            return Err(status::NOT_A_REPARSE_POINT);
        }
        let share = self
            .shares
            .get(&share_name)
            .ok_or(status::BAD_NETWORK_NAME)?;
        let data = share
            .backing
            .read_reparse(&rel)
            .map_err(|e| map_io_error(&e))?;

        // The output follows the fixed 48-byte IOCTL response body, i.e. at
        // HEADER_SIZE + 48 from the start of the SMB2 message.
        let output_offset = (smb2::HEADER_SIZE + 48) as u32;
        let resp = smb2::IoctlResponse {
            structure_size: 49.into(),
            reserved: 0.into(),
            ctl_code: ctl_code.into(),
            file_id: req.file_id,
            input_offset: output_offset.into(),
            input_count: 0.into(),
            output_offset: output_offset.into(),
            output_count: (data.len() as u32).into(),
            flags: 0.into(),
            reserved2: 0.into(),
        };
        Ok(self.assemble(header, status::SUCCESS, resp.as_bytes(), &data))
    }

    fn query_directory(&mut self, header: &smb2::Header, body: &[u8]) -> Result<Vec<u8>, u32> {
        let (req, _) = smb2::QueryDirectoryRequest::read_from_prefix(body)
            .map_err(|_| status::INVALID_PARAMETER)?;
        let info_class = req.file_information_class;
        let restart = req.flags & smb2::RESTART_SCANS != 0;
        let single_entry = req.flags & smb2::RETURN_SINGLE_ENTRY != 0;
        let max_out = req.output_buffer_length.get() as usize;
        let file_id = file_id_u64(&req.file_id);

        // Resolve the backing and populate the enumeration cursor on first use.
        let tree_id = self
            .open_files
            .get(&file_id)
            .ok_or(status::INVALID_PARAMETER)?
            .tree_id;
        let share_name = self
            .trees
            .get(&tree_id)
            .ok_or(status::INVALID_PARAMETER)?
            .clone();
        let rel = self.open_files.get(&file_id).unwrap().rel_path.clone();

        {
            let is_dir = self.open_files.get(&file_id).unwrap().info.is_dir;
            if !is_dir {
                return Err(status::INVALID_PARAMETER);
            }
        }

        let handle = self.open_files.get_mut(&file_id).unwrap();
        if handle.dir_entries.is_none() || restart {
            let share = self
                .shares
                .get(&share_name)
                .ok_or(status::BAD_NETWORK_NAME)?;
            let entries = share
                .backing
                .enumerate(&rel)
                .map_err(|e| map_io_error(&e))?;
            handle.dir_entries = Some(entries);
            handle.dir_cursor = 0;
        }

        let entries = handle.dir_entries.as_ref().unwrap();
        if handle.dir_cursor >= entries.len() {
            return Err(status::NO_MORE_FILES);
        }

        let mut out = Vec::new();
        let mut last_entry_start: Option<usize> = None;
        while handle.dir_cursor < entries.len() {
            let entry = &entries[handle.dir_cursor];
            let encoded = match encode_dir_entry(info_class, entry) {
                Some(e) => e,
                None => return Err(status::NOT_SUPPORTED),
            };
            // Each entry is 8-byte aligned. Stop if it would overflow the
            // client's output buffer (but always emit at least one).
            let aligned_len = (encoded.len() + 7) & !7;
            if !out.is_empty() && out.len() + aligned_len > max_out {
                break;
            }
            let start = out.len();
            out.extend_from_slice(&encoded);
            out.resize(start + aligned_len, 0);
            last_entry_start = Some(start);
            handle.dir_cursor += 1;
            // The Windows redirector sets SMB2_RETURN_SINGLE_ENTRY and expects
            // exactly one entry per response; emitting more would over-advance
            // the cursor and make the client skip the intervening entries.
            if single_entry {
                break;
            }
        }

        // Zero the NextEntryOffset of the final emitted entry to terminate.
        if let Some(start) = last_entry_start {
            out[start..start + 4].copy_from_slice(&0u32.to_le_bytes());
        }

        if out.is_empty() {
            return Err(status::NO_MORE_FILES);
        }
        Ok(self.output_buffer_response(header, &out))
    }

    fn close(&mut self, header: &smb2::Header, body: &[u8]) -> Result<Vec<u8>, u32> {
        let (req, _) =
            smb2::CloseRequest::read_from_prefix(body).map_err(|_| status::INVALID_PARAMETER)?;
        let file_id = file_id_u64(&req.file_id);
        let handle = self
            .open_files
            .remove(&file_id)
            .ok_or(status::INVALID_PARAMETER)?;
        let info = handle.info;

        // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB: return attributes if requested.
        let post_query = req.flags.get() & 0x0001 != 0;
        let resp = smb2::CloseResponse {
            structure_size: 60.into(),
            flags: req.flags,
            reserved: 0.into(),
            creation_time: if post_query { info.creation_time } else { 0 }.into(),
            last_access_time: if post_query { info.last_access_time } else { 0 }.into(),
            last_write_time: if post_query { info.last_write_time } else { 0 }.into(),
            change_time: if post_query { info.change_time } else { 0 }.into(),
            allocation_size: if post_query { info.allocation_size } else { 0 }.into(),
            end_of_file: if post_query { info.size } else { 0 }.into(),
            file_attributes: if post_query { info.attributes } else { 0 }.into(),
        };
        Ok(self.assemble(header, status::SUCCESS, resp.as_bytes(), &[]))
    }

    /// Builds a QUERY_INFO/QUERY_DIRECTORY-style response carrying an output
    /// buffer after the 8-byte fixed part.
    fn output_buffer_response(&self, header: &smb2::Header, out: &[u8]) -> Vec<u8> {
        let resp = smb2::OutputBufferResponse {
            structure_size: 9.into(),
            output_buffer_offset: ((smb2::HEADER_SIZE + 8) as u16).into(),
            output_buffer_length: (out.len() as u32).into(),
        };
        self.assemble(header, status::SUCCESS, resp.as_bytes(), out)
    }

    /// Builds a response with a 2-field body: `[structure_size, reserved]`.
    fn simple_status_response(
        &self,
        header: &smb2::Header,
        structure_size: u16,
        nt_status: u32,
    ) -> Vec<u8> {
        let body = [structure_size.to_le_bytes(), 0u16.to_le_bytes()].concat();
        self.assemble(header, nt_status, &body, &[])
    }

    /// Builds an SMB2 error response (MS-SMB2 2.2.2).
    fn error_response(&self, header: &smb2::Header, nt_status: u32) -> Vec<u8> {
        // ErrorResponse: StructureSize(9), ErrorContextCount(0), Reserved(0),
        // ByteCount(0), then a single reserved byte of ErrorData.
        let body: [u8; 9] = [9, 0, 0, 0, 0, 0, 0, 0, 0];
        self.assemble(header, nt_status, &body, &[])
    }

    /// Assembles a full SMB2 response: header + fixed body + trailing buffer.
    fn assemble(
        &self,
        request: &smb2::Header,
        nt_status: u32,
        body: &[u8],
        trailer: &[u8],
    ) -> Vec<u8> {
        let resp_header = smb2::Header::response_for(request, nt_status);
        let mut out = Vec::with_capacity(smb2::HEADER_SIZE + body.len() + trailer.len());
        out.extend_from_slice(resp_header.as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(trailer);
        out
    }
}

/// Decodes a little-endian UTF-16 byte slice into a `String`.
fn utf16_to_string(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Reads a UTF-16 string from an SMB2 message buffer, where `offset` is
/// relative to the start of the SMB2 header.
fn read_buffer_utf16(body: &[u8], offset: u16, length: u16) -> Option<String> {
    let start = (offset as usize).checked_sub(smb2::HEADER_SIZE)?;
    let end = start.checked_add(length as usize)?;
    let bytes = body.get(start..end)?;
    utf16_to_string(bytes)
}

/// Extracts the server's u64 file id from a 16-byte SMB2 FileId.
fn file_id_u64(file_id: &[u8; 16]) -> u64 {
    u64::from_le_bytes(file_id[..8].try_into().unwrap())
}

/// The sentinel FileId (`0xFFFF…`) used by related compound requests to mean
/// "the FileId returned by the preceding CREATE in this chain".
const SENTINEL_FILE_ID: [u8; 16] = [0xFF; 16];

/// Returns the byte offset of the FileId field within the request body for
/// commands that carry one, or `None` for commands that do not.
fn file_id_offset(command: u16) -> Option<usize> {
    match command {
        smb2::command::CLOSE => Some(8),
        smb2::command::READ => Some(16),
        smb2::command::IOCTL => Some(8),
        smb2::command::QUERY_DIRECTORY => Some(8),
        smb2::command::QUERY_INFO => Some(24),
        _ => None,
    }
}

/// Maps a std I/O error to an NT status.
fn map_io_error(err: &std::io::Error) -> u32 {
    match err.kind() {
        std::io::ErrorKind::NotFound => status::OBJECT_NAME_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => status::ACCESS_DENIED,
        _ => status::INVALID_PARAMETER,
    }
}

/// Encodes `FileBasicInformation` (MS-FSCC 2.4.7), 40 bytes.
fn encode_basic_info(info: &FileInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&info.creation_time.to_le_bytes());
    out.extend_from_slice(&info.last_access_time.to_le_bytes());
    out.extend_from_slice(&info.last_write_time.to_le_bytes());
    out.extend_from_slice(&info.change_time.to_le_bytes());
    out.extend_from_slice(&info.attributes.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out
}

/// Encodes `FileStandardInformation` (MS-FSCC 2.4.41), 24 bytes.
fn encode_standard_info(info: &FileInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&info.allocation_size.to_le_bytes());
    out.extend_from_slice(&info.size.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
    out.push(0); // DeletePending
    out.push(info.is_dir as u8); // Directory
    out.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    out
}

/// Encodes `FileNetworkOpenInformation` (MS-FSCC 2.4.29), 56 bytes.
fn encode_network_open_info(info: &FileInfo) -> Vec<u8> {
    let mut out = Vec::with_capacity(56);
    out.extend_from_slice(&info.creation_time.to_le_bytes());
    out.extend_from_slice(&info.last_access_time.to_le_bytes());
    out.extend_from_slice(&info.last_write_time.to_le_bytes());
    out.extend_from_slice(&info.change_time.to_le_bytes());
    out.extend_from_slice(&info.allocation_size.to_le_bytes());
    out.extend_from_slice(&info.size.to_le_bytes());
    out.extend_from_slice(&info.attributes.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out
}

/// Encodes `FileAttributeTagInformation` (MS-FSCC 2.4.6), 8 bytes: the file
/// attributes and (for a reparse point) the reparse tag.
fn encode_attribute_tag_info(info: &FileInfo) -> Vec<u8> {
    let reparse_tag = if info.attributes & crate::backing::ATTR_REPARSE_POINT != 0 {
        info.reparse_tag
    } else {
        0
    };
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&info.attributes.to_le_bytes());
    out.extend_from_slice(&reparse_tag.to_le_bytes());
    out
}

/// Encodes `FileStreamInformation` (MS-FSCC 2.4.40): one entry per NTFS stream
/// (the default `::$DATA` plus any alternate data streams).
fn encode_stream_info(streams: &[(String, i64)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut last_entry_start: Option<usize> = None;
    for (name, size) in streams {
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let alloc = ((*size as u64).div_ceil(4096) * 4096) as i64;
        let start = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset (patched)
        out.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes()); // StreamNameLength
        out.extend_from_slice(&size.to_le_bytes()); // StreamSize
        out.extend_from_slice(&alloc.to_le_bytes()); // StreamAllocationSize
        out.extend_from_slice(&name_utf16);
        // 8-byte align and patch the previous entry's NextEntryOffset.
        let aligned = out.len().next_multiple_of(8);
        out.resize(aligned, 0);
        if let Some(prev) = last_entry_start {
            let delta = (start - prev) as u32;
            out[prev..prev + 4].copy_from_slice(&delta.to_le_bytes());
        }
        last_entry_start = Some(start);
    }
    out
}

/// Encodes a single directory entry in the requested information class.
/// Returns `None` for unsupported classes. The `NextEntryOffset` field is set
/// to the aligned length of this entry; the caller zeroes it on the last entry.
fn encode_dir_entry(info_class: u8, entry: &DirEntry) -> Option<Vec<u8>> {
    let name_utf16: Vec<u8> = entry
        .name
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let info = &entry.info;

    // For a reparse point, the EaSize field carries the reparse tag (MS-FSCC);
    // otherwise it is the EA size (0, as we do not yet serve EAs).
    let ea_size: u32 = if info.attributes & crate::backing::ATTR_REPARSE_POINT != 0 {
        info.reparse_tag
    } else {
        0
    };

    let mut out = Vec::new();
    match info_class {
        smb2::file_info_class::DIRECTORY => {
            // FileDirectoryInformation (MS-FSCC 2.4.10): fixed 64 bytes + name.
            push_common_dir_fields(&mut out, info, name_utf16.len());
            out.extend_from_slice(&name_utf16);
        }
        smb2::file_info_class::FULL_DIRECTORY => {
            // FileFullDirectoryInformation (2.4.14): +EaSize (u32).
            push_common_dir_fields(&mut out, info, name_utf16.len());
            out.extend_from_slice(&ea_size.to_le_bytes()); // EaSize / reparse tag
            out.extend_from_slice(&name_utf16);
        }
        smb2::file_info_class::BOTH_DIRECTORY => {
            // FileBothDirectoryInformation (2.4.8): +EaSize, +ShortName block.
            push_common_dir_fields(&mut out, info, name_utf16.len());
            out.extend_from_slice(&ea_size.to_le_bytes()); // EaSize / reparse tag
            out.push(0); // ShortNameLength
            out.push(0); // Reserved
            out.extend_from_slice(&[0u8; 24]); // ShortName
            out.extend_from_slice(&name_utf16);
        }
        smb2::file_info_class::ID_BOTH_DIRECTORY => {
            // FileIdBothDirectoryInformation (2.4.17): Both + Reserved2 + FileId.
            push_common_dir_fields(&mut out, info, name_utf16.len());
            out.extend_from_slice(&ea_size.to_le_bytes()); // EaSize / reparse tag
            out.push(0); // ShortNameLength
            out.push(0); // Reserved1
            out.extend_from_slice(&[0u8; 24]); // ShortName
            out.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
            out.extend_from_slice(&0u64.to_le_bytes()); // FileId
            out.extend_from_slice(&name_utf16);
        }
        _ => return None,
    }

    // Patch NextEntryOffset (first u32) to the 8-byte-aligned entry length.
    let aligned = (out.len() + 7) & !7;
    out[0..4].copy_from_slice(&(aligned as u32).to_le_bytes());
    Some(out)
}

/// Pushes the fields common to all directory information classes up through
/// FileNameLength (56 bytes), leaving NextEntryOffset (first 4 bytes) as a
/// placeholder to be patched by the caller.
fn push_common_dir_fields(out: &mut Vec<u8>, info: &FileInfo, name_len: usize) {
    out.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset (patched later)
    out.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
    out.extend_from_slice(&info.creation_time.to_le_bytes());
    out.extend_from_slice(&info.last_access_time.to_le_bytes());
    out.extend_from_slice(&info.last_write_time.to_le_bytes());
    out.extend_from_slice(&info.change_time.to_le_bytes());
    out.extend_from_slice(&info.size.to_le_bytes()); // EndOfFile
    out.extend_from_slice(&info.allocation_size.to_le_bytes());
    out.extend_from_slice(&info.attributes.to_le_bytes());
    out.extend_from_slice(&(name_len as u32).to_le_bytes()); // FileNameLength
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Smb2Server {
        Smb2Server::new([(
            "layers".to_owned(),
            Share {
                root: "C:\\layers".to_owned(),
            },
        )])
    }

    fn request(command: u16, session_id: u64, tree_id: u32, body: &[u8]) -> Vec<u8> {
        let mut header = smb2::Header::read_from_bytes(&[0u8; smb2::HEADER_SIZE]).unwrap();
        header.protocol_id = smb2::PROTOCOL_ID;
        header.structure_size = (smb2::HEADER_SIZE as u16).into();
        header.command = command.into();
        header.message_id = 1.into();
        header.session_id = session_id.into();
        header.tree_id = tree_id.into();
        let mut out = header.as_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    fn negotiate_body(dialects: &[u16]) -> Vec<u8> {
        let req = smb2::NegotiateRequest {
            structure_size: 36.into(),
            dialect_count: (dialects.len() as u16).into(),
            security_mode: 1.into(),
            reserved: 0.into(),
            capabilities: 0.into(),
            client_guid: [0; 16],
            client_start_time: 0.into(),
        };
        let mut out = req.as_bytes().to_vec();
        for d in dialects {
            out.extend_from_slice(&d.to_le_bytes());
        }
        out
    }

    #[test]
    fn negotiate_selects_202() {
        let mut s = server();
        let req = request(
            smb2::command::NEGOTIATE,
            0,
            0,
            &negotiate_body(&[0x0202, 0x0210]),
        );
        let resp = s.handle(&req).unwrap();
        let (h, body) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), status::SUCCESS);
        let (neg, _) = smb2::NegotiateResponse::read_from_prefix(body).unwrap();
        assert_eq!(neg.dialect_revision.get(), smb2::DIALECT_2_0_2);
    }

    #[test]
    fn session_setup_grants_guest_session() {
        let mut s = server();
        let body = smb2::SessionSetupRequest {
            structure_size: 25.into(),
            flags: 0,
            security_mode: 1,
            capabilities: 0.into(),
            channel: 0.into(),
            security_buffer_offset: 0.into(),
            security_buffer_length: 0.into(),
            previous_session_id: 0.into(),
        };
        let req = request(smb2::command::SESSION_SETUP, 0, 0, body.as_bytes());
        let resp = s.handle(&req).unwrap();
        let (h, rest) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), status::SUCCESS);
        assert_ne!(h.session_id.get(), 0);
        let (ss, _) = smb2::SessionSetupResponse::read_from_prefix(rest).unwrap();
        assert_eq!(ss.session_flags.get(), smb2::SESSION_FLAG_IS_GUEST);
    }

    #[test]
    fn tree_connect_known_and_unknown() {
        let mut s = server();
        // Known share -> success with a fresh tree id.
        let path_bytes: Vec<u8> = "\\\\server\\layers"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let req_fixed = smb2::TreeConnectRequest {
            structure_size: 9.into(),
            reserved: 0.into(),
            path_offset: ((smb2::HEADER_SIZE + 8) as u16).into(),
            path_length: (path_bytes.len() as u16).into(),
        };
        let mut body = req_fixed.as_bytes().to_vec();
        body.extend_from_slice(&path_bytes);
        let resp = s
            .handle(&request(smb2::command::TREE_CONNECT, 1, 0, &body))
            .unwrap();
        let (h, _) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), status::SUCCESS);
        assert_ne!(h.tree_id.get(), 0);

        // Unknown share -> BAD_NETWORK_NAME.
        let bad_bytes: Vec<u8> = "\\\\server\\nope"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let req_fixed2 = smb2::TreeConnectRequest {
            structure_size: 9.into(),
            reserved: 0.into(),
            path_offset: ((smb2::HEADER_SIZE + 8) as u16).into(),
            path_length: (bad_bytes.len() as u16).into(),
        };
        let mut body2 = req_fixed2.as_bytes().to_vec();
        body2.extend_from_slice(&bad_bytes);
        let resp2 = s
            .handle(&request(smb2::command::TREE_CONNECT, 1, 0, &body2))
            .unwrap();
        let (h2, _) = smb2::parse_header(&resp2).unwrap();
        assert_eq!(h2.status.get(), status::BAD_NETWORK_NAME);
    }

    #[test]
    fn unsupported_command_errors() {
        let mut s = server();
        let req = request(smb2::command::WRITE, 1, 1, &[0u8; 4]);
        let resp = s.handle(&req).unwrap();
        let (h, _) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), status::NOT_SUPPORTED);
    }

    fn header_bytes(command: u16, flags: u32, session_id: u64, tree_id: u32, next: u32) -> Vec<u8> {
        let mut header = smb2::Header::read_from_bytes(&[0u8; smb2::HEADER_SIZE]).unwrap();
        header.protocol_id = smb2::PROTOCOL_ID;
        header.structure_size = (smb2::HEADER_SIZE as u16).into();
        header.command = command.into();
        header.flags = flags.into();
        header.next_command = next.into();
        header.message_id = 1.into();
        header.session_id = session_id.into();
        header.tree_id = tree_id.into();
        header.as_bytes().to_vec()
    }

    #[test]
    fn compound_create_and_query_directory() {
        let dir = std::env::temp_dir().join(format!("vsmb-compound-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        std::fs::write(dir.join("b.txt"), b"bb").unwrap();
        let mut s = Smb2Server::new([(
            "layers".to_owned(),
            Share {
                root: dir.to_string_lossy().into_owned(),
            },
        )]);
        s.sessions.insert(1, ());
        s.trees.insert(1, "layers".to_owned());

        // Command 1: CREATE the share root (empty name).
        let cr = smb2::CreateRequest {
            structure_size: 57.into(),
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0.into(),
            smb_create_flags: 0.into(),
            reserved: 0.into(),
            desired_access: 0x0012_00A9.into(),
            file_attributes: 0.into(),
            share_access: 0x07.into(),
            create_disposition: smb2::FILE_OPEN.into(),
            create_options: 0.into(),
            name_offset: ((smb2::HEADER_SIZE + 56) as u16).into(),
            name_length: 0.into(),
            create_contexts_offset: 0.into(),
            create_contexts_length: 0.into(),
        };
        let mut cr_body = cr.as_bytes().to_vec();
        cr_body.push(0); // minimum 1-byte buffer

        // Command 2: QUERY_DIRECTORY, related (sentinel FileId), restart scan.
        let qd = smb2::QueryDirectoryRequest {
            structure_size: 33.into(),
            file_information_class: smb2::file_info_class::ID_BOTH_DIRECTORY,
            flags: smb2::RESTART_SCANS,
            file_index: 0.into(),
            file_id: [0xFF; 16],
            file_name_offset: 0.into(),
            file_name_length: 0.into(),
            output_buffer_length: (64 * 1024).into(),
        };
        let qd_body = qd.as_bytes().to_vec();

        // Assemble the compound: [header1 + create][pad to 8][header2 + qd].
        let cmd1_len = smb2::HEADER_SIZE + cr_body.len();
        let cmd1_aligned = cmd1_len.next_multiple_of(8);
        let mut msg = header_bytes(smb2::command::CREATE, 0, 1, 1, cmd1_aligned as u32);
        msg.extend_from_slice(&cr_body);
        msg.resize(cmd1_aligned, 0);
        msg.extend_from_slice(&header_bytes(
            smb2::command::QUERY_DIRECTORY,
            smb2::FLAGS_RELATED_OPERATIONS,
            1,
            1,
            0,
        ));
        msg.extend_from_slice(&qd_body);

        let resp = s.handle(&msg).unwrap();

        // First response: CREATE success, with a NextCommand link.
        let (h_a, _) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h_a.command.get(), smb2::command::CREATE);
        assert_eq!(h_a.status.get(), status::SUCCESS);
        let next = h_a.next_command.get() as usize;
        assert!(next > 0);

        // Second response: QUERY_DIRECTORY success with entries.
        let (h_b, rest_b) = smb2::parse_header(&resp[next..]).unwrap();
        assert_eq!(h_b.command.get(), smb2::command::QUERY_DIRECTORY);
        assert_eq!(h_b.status.get(), status::SUCCESS);
        let (_, buf) = smb2::OutputBufferResponse::read_from_prefix(rest_b).unwrap();
        let needle: Vec<u8> = "a.txt"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert!(
            buf.windows(needle.len()).any(|w| w == needle.as_slice()),
            "compound QUERY_DIRECTORY should list a.txt"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(windows)]
    #[test]
    fn query_security_and_attribute_tag() {
        let dir = std::env::temp_dir().join(format!("vsmb-sec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.txt"), b"x").unwrap();
        let mut s = Smb2Server::new([(
            "layers".to_owned(),
            Share {
                root: dir.to_string_lossy().into_owned(),
            },
        )]);
        s.sessions.insert(1, ());
        s.trees.insert(1, "layers".to_owned());
        let info = s
            .shares
            .get("layers")
            .unwrap()
            .backing
            .stat("f.txt")
            .unwrap();
        s.open_files.insert(
            7,
            OpenHandle {
                tree_id: 1,
                rel_path: "f.txt".to_owned(),
                info,
                dir_entries: None,
                dir_cursor: 0,
            },
        );
        let mut fid = [0u8; 16];
        fid[..8].copy_from_slice(&7u64.to_le_bytes());

        // QUERY_INFO(SECURITY) returns a non-empty security descriptor.
        let q = smb2::QueryInfoRequest {
            structure_size: 41.into(),
            info_type: smb2::INFO_TYPE_SECURITY,
            file_info_class: 0,
            output_buffer_length: (64 * 1024).into(),
            input_buffer_offset: 0.into(),
            reserved: 0.into(),
            input_buffer_length: 0.into(),
            additional_information: 0x7.into(),
            flags: 0.into(),
            file_id: fid,
        };
        let resp = s
            .handle(&request(smb2::command::QUERY_INFO, 1, 1, q.as_bytes()))
            .unwrap();
        let (h, rest) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), status::SUCCESS);
        let (ob, _) = smb2::OutputBufferResponse::read_from_prefix(rest).unwrap();
        assert!(ob.output_buffer_length.get() > 0);

        // QUERY_INFO(FILE, AttributeTag) succeeds.
        let q2 = smb2::QueryInfoRequest {
            structure_size: 41.into(),
            info_type: smb2::INFO_TYPE_FILE,
            file_info_class: smb2::file_info_class::ATTRIBUTE_TAG,
            output_buffer_length: 64.into(),
            input_buffer_offset: 0.into(),
            reserved: 0.into(),
            input_buffer_length: 0.into(),
            additional_information: 0.into(),
            flags: 0.into(),
            file_id: fid,
        };
        let resp2 = s
            .handle(&request(smb2::command::QUERY_INFO, 1, 1, q2.as_bytes()))
            .unwrap();
        assert_eq!(
            smb2::parse_header(&resp2).unwrap().0.status.get(),
            status::SUCCESS
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn end_to_end_open_and_read() {
        let dir = std::env::temp_dir().join(format!("vsmb-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("layer.txt"), b"CONTAINER-LAYER-BYTES").unwrap();

        let mut s = Smb2Server::new([(
            "layers".to_owned(),
            Share {
                root: dir.to_string_lossy().into_owned(),
            },
        )]);

        // NEGOTIATE
        let resp = s
            .handle(&request(
                smb2::command::NEGOTIATE,
                0,
                0,
                &negotiate_body(&[0x0202]),
            ))
            .unwrap();
        assert_eq!(
            smb2::parse_header(&resp).unwrap().0.status.get(),
            status::SUCCESS
        );

        // SESSION_SETUP -> capture session id
        let ss_body = smb2::SessionSetupRequest {
            structure_size: 25.into(),
            flags: 0,
            security_mode: 1,
            capabilities: 0.into(),
            channel: 0.into(),
            security_buffer_offset: 0.into(),
            security_buffer_length: 0.into(),
            previous_session_id: 0.into(),
        };
        let resp = s
            .handle(&request(
                smb2::command::SESSION_SETUP,
                0,
                0,
                ss_body.as_bytes(),
            ))
            .unwrap();
        let session_id = smb2::parse_header(&resp).unwrap().0.session_id.get();
        assert_ne!(session_id, 0);

        // TREE_CONNECT -> capture tree id
        let path_bytes: Vec<u8> = "\\\\server\\layers"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let tc_fixed = smb2::TreeConnectRequest {
            structure_size: 9.into(),
            reserved: 0.into(),
            path_offset: ((smb2::HEADER_SIZE + 8) as u16).into(),
            path_length: (path_bytes.len() as u16).into(),
        };
        let mut tc_body = tc_fixed.as_bytes().to_vec();
        tc_body.extend_from_slice(&path_bytes);
        let resp = s
            .handle(&request(
                smb2::command::TREE_CONNECT,
                session_id,
                0,
                &tc_body,
            ))
            .unwrap();
        let tree_id = smb2::parse_header(&resp).unwrap().0.tree_id.get();
        assert_ne!(tree_id, 0);

        // CREATE (open layer.txt) -> capture file id and size
        let name_bytes: Vec<u8> = "layer.txt"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let cr_fixed = smb2::CreateRequest {
            structure_size: 57.into(),
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 0.into(),
            smb_create_flags: 0.into(),
            reserved: 0.into(),
            desired_access: 0x0012_00A9.into(),
            file_attributes: 0.into(),
            share_access: 0x07.into(),
            create_disposition: smb2::FILE_OPEN.into(),
            create_options: 0.into(),
            name_offset: ((smb2::HEADER_SIZE + 56) as u16).into(),
            name_length: (name_bytes.len() as u16).into(),
            create_contexts_offset: 0.into(),
            create_contexts_length: 0.into(),
        };
        let mut cr_body = cr_fixed.as_bytes().to_vec();
        cr_body.extend_from_slice(&name_bytes);
        let resp = s
            .handle(&request(
                smb2::command::CREATE,
                session_id,
                tree_id,
                &cr_body,
            ))
            .unwrap();
        let (h, rest) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), status::SUCCESS);
        let (create, _) = smb2::CreateResponse::read_from_prefix(rest).unwrap();
        assert_eq!(create.end_of_file.get(), 21);
        let file_id = create.file_id;

        // READ the file
        let rd_fixed = smb2::ReadRequest {
            structure_size: 49.into(),
            padding: 0,
            flags: 0,
            length: 21.into(),
            offset: 0.into(),
            file_id,
            minimum_count: 0.into(),
            channel: 0.into(),
            remaining_bytes: 0.into(),
            read_channel_info_offset: 0.into(),
            read_channel_info_length: 0.into(),
        };
        let mut rd_body = rd_fixed.as_bytes().to_vec();
        rd_body.push(0); // 1-byte buffer minimum
        let resp = s
            .handle(&request(smb2::command::READ, session_id, tree_id, &rd_body))
            .unwrap();
        let (h, rest) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), status::SUCCESS);
        let (read, data) = smb2::ReadResponse::read_from_prefix(rest).unwrap();
        assert_eq!(read.data_length.get(), 21);
        assert_eq!(&data[..21], b"CONTAINER-LAYER-BYTES");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn query_directory_lists_entries() {
        let dir = std::env::temp_dir().join(format!("vsmb-qd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        std::fs::write(dir.join("b.txt"), b"bb").unwrap();

        let mut s = Smb2Server::new([(
            "layers".to_owned(),
            Share {
                root: dir.to_string_lossy().into_owned(),
            },
        )]);
        // Manually seed a session, tree, and an open directory handle.
        s.sessions.insert(1, ());
        s.trees.insert(1, "layers".to_owned());
        s.open_files.insert(
            5,
            OpenHandle {
                tree_id: 1,
                rel_path: String::new(),
                info: s.shares.get("layers").unwrap().backing.stat("").unwrap(),
                dir_entries: None,
                dir_cursor: 0,
            },
        );

        let mut file_id = [0u8; 16];
        file_id[..8].copy_from_slice(&5u64.to_le_bytes());
        let qd = smb2::QueryDirectoryRequest {
            structure_size: 33.into(),
            file_information_class: smb2::file_info_class::ID_BOTH_DIRECTORY,
            flags: smb2::RESTART_SCANS,
            file_index: 0.into(),
            file_id,
            file_name_offset: 0.into(),
            file_name_length: 0.into(),
            output_buffer_length: (64 * 1024).into(),
        };
        let resp = s
            .handle(&request(
                smb2::command::QUERY_DIRECTORY,
                1,
                1,
                qd.as_bytes(),
            ))
            .unwrap();
        let (h, rest) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), status::SUCCESS);
        let (ob, buf) = smb2::OutputBufferResponse::read_from_prefix(rest).unwrap();
        assert!(ob.output_buffer_length.get() > 0);
        // The buffer should contain the UTF-16 name "a.txt" somewhere.
        let needle: Vec<u8> = "a.txt"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert!(
            buf.windows(needle.len()).any(|w| w == needle.as_slice()),
            "expected a.txt in directory listing"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn query_directory_chain_is_walkable() {
        // Regression: the guest RDR walks the NextEntryOffset chain to find
        // each entry. A broken chain makes it see only "." and ".." (which it
        // discards), yielding an empty listing even though bytes were sent.
        // Windows' FindFirstFile uses FileFullDirectoryInformation (0x02).
        let dir = std::env::temp_dir().join(format!("vsmb-qdchain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("layer.txt"), b"x").unwrap();
        std::fs::write(dir.join("hasads.txt"), b"y").unwrap();
        std::fs::create_dir_all(dir.join("realdir")).unwrap();
        // Replicate the DUT layer exactly: a junction (reparse point). For a
        // reparse entry the EaSize field carries the reparse tag, which must
        // not desync the NextEntryOffset chain.
        let _ = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                dir.join("linkdir").to_str().unwrap(),
                dir.join("realdir").to_str().unwrap(),
            ])
            .output();

        let mut s = Smb2Server::new([(
            "layers".to_owned(),
            Share {
                root: dir.to_string_lossy().into_owned(),
            },
        )]);
        s.sessions.insert(1, ());
        s.trees.insert(1, "layers".to_owned());
        s.open_files.insert(
            7,
            OpenHandle {
                tree_id: 1,
                rel_path: String::new(),
                info: s.shares.get("layers").unwrap().backing.stat("").unwrap(),
                dir_entries: None,
                dir_cursor: 0,
            },
        );

        let mut file_id = [0u8; 16];
        file_id[..8].copy_from_slice(&7u64.to_le_bytes());
        let qd = smb2::QueryDirectoryRequest {
            structure_size: 33.into(),
            file_information_class: smb2::file_info_class::FULL_DIRECTORY,
            flags: smb2::RESTART_SCANS,
            file_index: 0.into(),
            file_id,
            file_name_offset: 0.into(),
            file_name_length: 0.into(),
            output_buffer_length: (64 * 1024).into(),
        };
        let resp = s
            .handle(&request(
                smb2::command::QUERY_DIRECTORY,
                1,
                1,
                qd.as_bytes(),
            ))
            .unwrap();
        let (h, rest) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), status::SUCCESS);
        let (_, buf) = smb2::OutputBufferResponse::read_from_prefix(rest).unwrap();

        // Walk the chain exactly like the client: follow NextEntryOffset, and
        // decode each entry's name using FileNameLength. FileFullDirectory:
        // FileNameLength at 60, EaSize at 64, FileName at 68.
        let mut names = Vec::new();
        let mut off = 0usize;
        loop {
            let next = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let name_len = u32::from_le_bytes(buf[off + 60..off + 64].try_into().unwrap()) as usize;
            let name_start = off + 68;
            let name_u16: Vec<u16> = buf[name_start..name_start + name_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            names.push(String::from_utf16_lossy(&name_u16));
            if next == 0 {
                break;
            }
            off += next;
        }

        assert!(names.contains(&".".to_owned()), "names={names:?}");
        assert!(names.contains(&"..".to_owned()), "names={names:?}");
        assert!(names.contains(&"layer.txt".to_owned()), "names={names:?}");
        assert!(names.contains(&"hasads.txt".to_owned()), "names={names:?}");
        assert!(names.contains(&"realdir".to_owned()), "names={names:?}");
        assert!(names.contains(&"linkdir".to_owned()), "names={names:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn query_directory_both_dir_chain_is_walkable() {
        // FindFirstFileW uses FileBothDirectoryInformation (0x03), whose fixed
        // part is 94 bytes (adds EaSize + ShortNameLength/Reserved/ShortName).
        // Walk the chain exactly like the client to catch offset desync.
        let dir = std::env::temp_dir().join(format!("vsmb-qdboth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("layer.txt"), b"x").unwrap();
        std::fs::write(dir.join("hasads.txt"), b"y").unwrap();
        std::fs::create_dir_all(dir.join("realdir")).unwrap();

        let mut s = Smb2Server::new([(
            "layers".to_owned(),
            Share {
                root: dir.to_string_lossy().into_owned(),
            },
        )]);
        s.sessions.insert(1, ());
        s.trees.insert(1, "layers".to_owned());
        s.open_files.insert(
            9,
            OpenHandle {
                tree_id: 1,
                rel_path: String::new(),
                info: s.shares.get("layers").unwrap().backing.stat("").unwrap(),
                dir_entries: None,
                dir_cursor: 0,
            },
        );

        let mut file_id = [0u8; 16];
        file_id[..8].copy_from_slice(&9u64.to_le_bytes());
        let qd = smb2::QueryDirectoryRequest {
            structure_size: 33.into(),
            file_information_class: smb2::file_info_class::BOTH_DIRECTORY,
            flags: smb2::RESTART_SCANS,
            file_index: 0.into(),
            file_id,
            file_name_offset: 0.into(),
            file_name_length: 0.into(),
            output_buffer_length: (64 * 1024).into(),
        };
        let resp = s
            .handle(&request(
                smb2::command::QUERY_DIRECTORY,
                1,
                1,
                qd.as_bytes(),
            ))
            .unwrap();
        let (_, rest) = smb2::parse_header(&resp).unwrap();
        let (_, buf) = smb2::OutputBufferResponse::read_from_prefix(rest).unwrap();

        // FileBothDirectoryInformation: FileNameLength at 60, FileName at 94.
        let mut names = Vec::new();
        let mut off = 0usize;
        loop {
            let next = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
            let name_len = u32::from_le_bytes(buf[off + 60..off + 64].try_into().unwrap()) as usize;
            let name_start = off + 94;
            let name_u16: Vec<u16> = buf[name_start..name_start + name_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            names.push(String::from_utf16_lossy(&name_u16));
            if next == 0 {
                break;
            }
            off += next;
        }

        assert!(names.contains(&"layer.txt".to_owned()), "names={names:?}");
        assert!(names.contains(&"hasads.txt".to_owned()), "names={names:?}");
        assert!(names.contains(&"realdir".to_owned()), "names={names:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn query_directory_split_matches_client() {
        // Reproduce the real DUT scenario: FindFirstFileW passes a small output
        // buffer (0x268), forcing the 6 entries to split across responses. Walk
        // each response's chain like the client and confirm every name arrives
        // exactly once across the two responses.
        let dir = std::env::temp_dir().join(format!("vsmb-qdsplit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("layer.txt"), b"x").unwrap();
        std::fs::write(dir.join("hasads.txt"), b"y").unwrap();
        std::fs::write(dir.join("second.txt"), b"z").unwrap();
        std::fs::create_dir_all(dir.join("realdir")).unwrap();

        let mut s = Smb2Server::new([(
            "layers".to_owned(),
            Share {
                root: dir.to_string_lossy().into_owned(),
            },
        )]);
        s.sessions.insert(1, ());
        s.trees.insert(1, "layers".to_owned());
        s.open_files.insert(
            11,
            OpenHandle {
                tree_id: 1,
                rel_path: String::new(),
                info: s.shares.get("layers").unwrap().backing.stat("").unwrap(),
                dir_entries: None,
                dir_cursor: 0,
            },
        );

        let mut file_id = [0u8; 16];
        file_id[..8].copy_from_slice(&11u64.to_le_bytes());

        let decode = |buf: &[u8], names: &mut Vec<String>| {
            let mut off = 0usize;
            loop {
                let next = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
                let name_len =
                    u32::from_le_bytes(buf[off + 60..off + 64].try_into().unwrap()) as usize;
                let name_start = off + 94;
                let name_u16: Vec<u16> = buf[name_start..name_start + name_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                names.push(String::from_utf16_lossy(&name_u16));
                if next == 0 {
                    break;
                }
                off += next;
            }
        };

        let mut names = Vec::new();
        // Mirror the Windows redirector: SMB2_RETURN_SINGLE_ENTRY, one entry
        // per call, until NO_MORE_FILES.
        for i in 0..16 {
            let qd = smb2::QueryDirectoryRequest {
                structure_size: 33.into(),
                file_information_class: smb2::file_info_class::BOTH_DIRECTORY,
                flags: if i == 0 {
                    smb2::RESTART_SCANS | smb2::RETURN_SINGLE_ENTRY
                } else {
                    smb2::RETURN_SINGLE_ENTRY
                },
                file_index: 0.into(),
                file_id,
                file_name_offset: 0.into(),
                file_name_length: 0.into(),
                output_buffer_length: 0x268.into(),
            };
            let resp = s
                .handle(&request(
                    smb2::command::QUERY_DIRECTORY,
                    1,
                    1,
                    qd.as_bytes(),
                ))
                .unwrap();
            let (h, rest) = smb2::parse_header(&resp).unwrap();
            if h.status.get() != status::SUCCESS {
                break;
            }
            let (_, buf) = smb2::OutputBufferResponse::read_from_prefix(rest).unwrap();
            let before = names.len();
            decode(buf, &mut names);
            // With single-entry semantics each response carries exactly one.
            assert_eq!(names.len() - before, 1, "expected one entry per response");
        }

        // Every real name must appear exactly once across the split responses.
        for expected in ["layer.txt", "hasads.txt", "second.txt", "realdir"] {
            let n = names.iter().filter(|x| x.as_str() == expected).count();
            assert_eq!(n, 1, "{expected} appeared {n} times; names={names:?}");
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}

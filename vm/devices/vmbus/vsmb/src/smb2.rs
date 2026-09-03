// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal SMB2 wire structures for the vSMB read-only server.
//!
//! These follow the MS-SMB2 protocol. Only the subset needed to bring up a
//! read-only share is defined: NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE,
//! QUERY_INFO, QUERY_DIRECTORY, READ, and CLOSE, plus the SMB2 header and error
//! response.
//!
//! All structures are little-endian and parsed/emitted with `zerocopy`. The
//! server negotiates SMB 2.0.2 to avoid signing/encryption/leasing
//! requirements, and authenticates the guest session with an empty security
//! buffer (the guest-auth fast path the Hyper-V vSMB engine also uses).

#![allow(dead_code)]

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::little_endian::U16 as u16_le;
use zerocopy::little_endian::U32 as u32_le;
use zerocopy::little_endian::U64 as u64_le;

/// The SMB2 protocol id: `0xFE 'S' 'M' 'B'`.
pub const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// Size of the fixed SMB2 header, in bytes.
pub const HEADER_SIZE: usize = 64;

/// SMB 2.0.2 dialect revision.
pub const DIALECT_2_0_2: u16 = 0x0202;
/// SMB 2.1 dialect revision.
pub const DIALECT_2_1_0: u16 = 0x0210;
/// The "wildcard" revision the client sends to trigger multi-protocol
/// negotiation; the server responds with a concrete dialect.
pub const DIALECT_WILDCARD: u16 = 0x02FF;

/// SMB2 command codes (MS-SMB2 2.2.1).
pub mod command {
    pub const NEGOTIATE: u16 = 0x0000;
    pub const SESSION_SETUP: u16 = 0x0001;
    pub const LOGOFF: u16 = 0x0002;
    pub const TREE_CONNECT: u16 = 0x0003;
    pub const TREE_DISCONNECT: u16 = 0x0004;
    pub const CREATE: u16 = 0x0005;
    pub const CLOSE: u16 = 0x0006;
    pub const FLUSH: u16 = 0x0007;
    pub const READ: u16 = 0x0008;
    pub const WRITE: u16 = 0x0009;
    pub const IOCTL: u16 = 0x000B;
    pub const QUERY_DIRECTORY: u16 = 0x000E;
    pub const QUERY_INFO: u16 = 0x0010;
}

/// The `SMB2_FLAGS_SERVER_TO_REDIR` flag, set on all responses.
pub const FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
/// The `SMB2_FLAGS_RELATED_OPERATIONS` flag: later commands in a compound reuse
/// the FileId opened by a preceding `CREATE`.
pub const FLAGS_RELATED_OPERATIONS: u32 = 0x0000_0004;

/// Common NT status codes used by the server.
pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const PENDING: u32 = 0x0000_0103;
    pub const NO_MORE_FILES: u32 = 0x8000_0006;
    pub const END_OF_FILE: u32 = 0xC000_0011;
    pub const NOT_SUPPORTED: u32 = 0xC000_00BB;
    pub const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub const NO_SUCH_FILE: u32 = 0xC000_000F;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    pub const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    pub const ACCESS_DENIED: u32 = 0xC000_0022;
    pub const BAD_NETWORK_NAME: u32 = 0xC000_00CC;
    pub const INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
    pub const BUFFER_TOO_SMALL: u32 = 0xC000_0023;
    pub const NOT_A_REPARSE_POINT: u32 = 0xC000_0275;
}

/// The fixed 64-byte SMB2 (sync) packet header (MS-SMB2 2.2.1.2).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct Header {
    pub protocol_id: [u8; 4],
    pub structure_size: u16_le,
    pub credit_charge: u16_le,
    pub status: u32_le,
    pub command: u16_le,
    pub credit_request: u16_le,
    pub flags: u32_le,
    pub next_command: u32_le,
    pub message_id: u64_le,
    pub reserved: u32_le,
    pub tree_id: u32_le,
    pub session_id: u64_le,
    pub signature: [u8; 16],
}

impl Header {
    /// Builds a response header echoing the routing fields of a request.
    pub fn response_for(request: &Header, status: u32) -> Header {
        Header {
            protocol_id: PROTOCOL_ID,
            structure_size: (HEADER_SIZE as u16).into(),
            credit_charge: request.credit_charge,
            status: status.into(),
            command: request.command,
            // Grant a fixed credit so the client can keep issuing requests.
            credit_request: 1.into(),
            flags: FLAGS_SERVER_TO_REDIR.into(),
            next_command: 0.into(),
            message_id: request.message_id,
            reserved: 0.into(),
            tree_id: request.tree_id,
            session_id: request.session_id,
            signature: [0; 16],
        }
    }
}

/// NEGOTIATE request, fixed portion (MS-SMB2 2.2.3). Followed by
/// `dialect_count` little-endian `u16` dialects.
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct NegotiateRequest {
    pub structure_size: u16_le,
    pub dialect_count: u16_le,
    pub security_mode: u16_le,
    pub reserved: u16_le,
    pub capabilities: u32_le,
    pub client_guid: [u8; 16],
    pub client_start_time: u64_le,
}

/// NEGOTIATE response, fixed portion (MS-SMB2 2.2.4).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct NegotiateResponse {
    pub structure_size: u16_le,
    pub security_mode: u16_le,
    pub dialect_revision: u16_le,
    pub negotiate_context_count: u16_le,
    pub server_guid: [u8; 16],
    pub capabilities: u32_le,
    pub max_transact_size: u32_le,
    pub max_read_size: u32_le,
    pub max_write_size: u32_le,
    pub system_time: u64_le,
    pub server_start_time: u64_le,
    pub security_buffer_offset: u16_le,
    pub security_buffer_length: u16_le,
    pub negotiate_context_offset: u32_le,
}

/// SESSION_SETUP request, fixed portion (MS-SMB2 2.2.5).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct SessionSetupRequest {
    pub structure_size: u16_le,
    pub flags: u8,
    pub security_mode: u8,
    pub capabilities: u32_le,
    pub channel: u32_le,
    pub security_buffer_offset: u16_le,
    pub security_buffer_length: u16_le,
    pub previous_session_id: u64_le,
}

/// SESSION_SETUP response, fixed portion (MS-SMB2 2.2.6).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct SessionSetupResponse {
    pub structure_size: u16_le,
    pub session_flags: u16_le,
    pub security_buffer_offset: u16_le,
    pub security_buffer_length: u16_le,
}

/// `SMB2_SESSION_FLAG_IS_GUEST`.
pub const SESSION_FLAG_IS_GUEST: u16 = 0x0001;

/// TREE_CONNECT request, fixed portion (MS-SMB2 2.2.9). Followed by the share
/// path as UTF-16.
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct TreeConnectRequest {
    pub structure_size: u16_le,
    pub reserved: u16_le,
    pub path_offset: u16_le,
    pub path_length: u16_le,
}

/// TREE_CONNECT response (MS-SMB2 2.2.10).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct TreeConnectResponse {
    pub structure_size: u16_le,
    pub share_type: u8,
    pub reserved: u8,
    pub share_flags: u32_le,
    pub capabilities: u32_le,
    pub maximal_access: u32_le,
}

/// `SMB2_SHARE_TYPE_DISK`.
pub const SHARE_TYPE_DISK: u8 = 0x01;

/// CREATE request, fixed portion (MS-SMB2 2.2.13). Followed by the file name
/// (UTF-16) and optional create contexts.
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct CreateRequest {
    pub structure_size: u16_le,
    pub security_flags: u8,
    pub requested_oplock_level: u8,
    pub impersonation_level: u32_le,
    pub smb_create_flags: u64_le,
    pub reserved: u64_le,
    pub desired_access: u32_le,
    pub file_attributes: u32_le,
    pub share_access: u32_le,
    pub create_disposition: u32_le,
    pub create_options: u32_le,
    pub name_offset: u16_le,
    pub name_length: u16_le,
    pub create_contexts_offset: u32_le,
    pub create_contexts_length: u32_le,
}

/// CREATE response, fixed portion (MS-SMB2 2.2.14).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct CreateResponse {
    pub structure_size: u16_le,
    pub oplock_level: u8,
    pub flags: u8,
    pub create_action: u32_le,
    pub creation_time: u64_le,
    pub last_access_time: u64_le,
    pub last_write_time: u64_le,
    pub change_time: u64_le,
    pub allocation_size: u64_le,
    pub end_of_file: u64_le,
    pub file_attributes: u32_le,
    pub reserved2: u32_le,
    pub file_id: [u8; 16],
    pub create_contexts_offset: u32_le,
    pub create_contexts_length: u32_le,
}

/// `FILE_OPEN` create disposition (fail if the file does not exist).
pub const FILE_OPEN: u32 = 0x0000_0001;
/// `FILE_CREATED` / `FILE_OPENED` create actions.
pub const CREATE_ACTION_OPENED: u32 = 0x0000_0001;

/// READ request, fixed portion (MS-SMB2 2.2.19).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct ReadRequest {
    pub structure_size: u16_le,
    pub padding: u8,
    pub flags: u8,
    pub length: u32_le,
    pub offset: u64_le,
    pub file_id: [u8; 16],
    pub minimum_count: u32_le,
    pub channel: u32_le,
    pub remaining_bytes: u32_le,
    pub read_channel_info_offset: u16_le,
    pub read_channel_info_length: u16_le,
}

/// READ response, fixed portion (MS-SMB2 2.2.20). Followed by the data.
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct ReadResponse {
    pub structure_size: u16_le,
    pub data_offset: u8,
    pub reserved: u8,
    pub data_length: u32_le,
    pub data_remaining: u32_le,
    pub reserved2: u32_le,
}

/// CLOSE request (MS-SMB2 2.2.15).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct CloseRequest {
    pub structure_size: u16_le,
    pub flags: u16_le,
    pub reserved: u32_le,
    pub file_id: [u8; 16],
}

/// CLOSE response (MS-SMB2 2.2.16).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct CloseResponse {
    pub structure_size: u16_le,
    pub flags: u16_le,
    pub reserved: u32_le,
    pub creation_time: u64_le,
    pub last_access_time: u64_le,
    pub last_write_time: u64_le,
    pub change_time: u64_le,
    pub allocation_size: u64_le,
    pub end_of_file: u64_le,
    pub file_attributes: u32_le,
}

/// QUERY_INFO request, fixed portion (MS-SMB2 2.2.37).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct QueryInfoRequest {
    pub structure_size: u16_le,
    pub info_type: u8,
    pub file_info_class: u8,
    pub output_buffer_length: u32_le,
    pub input_buffer_offset: u16_le,
    pub reserved: u16_le,
    pub input_buffer_length: u32_le,
    pub additional_information: u32_le,
    pub flags: u32_le,
    pub file_id: [u8; 16],
}

/// QUERY_DIRECTORY request, fixed portion (MS-SMB2 2.2.33). Followed by the
/// search pattern (UTF-16).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct QueryDirectoryRequest {
    pub structure_size: u16_le,
    pub file_information_class: u8,
    pub flags: u8,
    pub file_index: u32_le,
    pub file_id: [u8; 16],
    pub file_name_offset: u16_le,
    pub file_name_length: u16_le,
    pub output_buffer_length: u32_le,
}

/// A variable-length response with an 8-byte fixed part used by both
/// QUERY_INFO (2.2.38) and QUERY_DIRECTORY (2.2.34): `StructureSize(9)`,
/// `OutputBufferOffset`, `OutputBufferLength`, then the buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct OutputBufferResponse {
    pub structure_size: u16_le,
    pub output_buffer_offset: u16_le,
    pub output_buffer_length: u32_le,
}

/// `SMB2_0_INFO_FILE` — QUERY_INFO `InfoType` for file information.
pub const INFO_TYPE_FILE: u8 = 0x01;
/// `SMB2_0_INFO_SECURITY` — QUERY_INFO `InfoType` for the security descriptor.
pub const INFO_TYPE_SECURITY: u8 = 0x03;

/// File information classes (MS-FSCC 2.4) used by the server.
pub mod file_info_class {
    pub const DIRECTORY: u8 = 0x01;
    pub const FULL_DIRECTORY: u8 = 0x02;
    pub const BOTH_DIRECTORY: u8 = 0x03;
    pub const BASIC: u8 = 0x04;
    pub const STANDARD: u8 = 0x05;
    pub const STREAM: u8 = 22;
    pub const ATTRIBUTE_TAG: u8 = 35;
    pub const NETWORK_OPEN: u8 = 0x22;
    pub const ID_BOTH_DIRECTORY: u8 = 0x25;
}

/// IOCTL request, fixed portion (MS-SMB2 2.2.31). Followed by the input buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct IoctlRequest {
    pub structure_size: u16_le,
    pub reserved: u16_le,
    pub ctl_code: u32_le,
    pub file_id: [u8; 16],
    pub input_offset: u32_le,
    pub input_count: u32_le,
    pub max_input_response: u32_le,
    pub output_offset: u32_le,
    pub output_count: u32_le,
    pub max_output_response: u32_le,
    pub flags: u32_le,
    pub reserved2: u32_le,
}

/// IOCTL response, fixed portion (MS-SMB2 2.2.32). Followed by the output.
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct IoctlResponse {
    pub structure_size: u16_le,
    pub reserved: u16_le,
    pub ctl_code: u32_le,
    pub file_id: [u8; 16],
    pub input_offset: u32_le,
    pub input_count: u32_le,
    pub output_offset: u32_le,
    pub output_count: u32_le,
    pub flags: u32_le,
    pub reserved2: u32_le,
}

/// `FSCTL_GET_REPARSE_POINT`.
pub const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;

/// `SMB2_RESTART_SCANS` flag on QUERY_DIRECTORY.
pub const RESTART_SCANS: u8 = 0x01;

/// `SMB2_RETURN_SINGLE_ENTRY` flag on QUERY_DIRECTORY: the client wants exactly
/// one entry per response (the Windows inbox redirector sets this).
pub const RETURN_SINGLE_ENTRY: u8 = 0x02;

/// Parses the fixed header from the front of a segment, validating the magic
/// and structure size. Returns the header and the remaining bytes.
pub fn parse_header(buf: &[u8]) -> Option<(Header, &[u8])> {
    let (header, rest) = Header::read_from_prefix(buf).ok()?;
    if header.protocol_id != PROTOCOL_ID || header.structure_size.get() as usize != HEADER_SIZE {
        return None;
    }
    Some((header, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_64_bytes() {
        assert_eq!(size_of::<Header>(), HEADER_SIZE);
    }

    #[test]
    fn negotiate_response_is_64_bytes_fixed() {
        // MS-SMB2: StructureSize field value is 65 (fixed part + 1), but the
        // fixed struct itself is 64 bytes; the security buffer follows.
        assert_eq!(size_of::<NegotiateResponse>(), 64);
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&[0, 0, 0, 0]);
        assert!(parse_header(&buf).is_none());
    }

    #[test]
    fn response_header_echoes_routing() {
        let mut req = Header::read_from_bytes(&[0u8; HEADER_SIZE]).unwrap();
        req.protocol_id = PROTOCOL_ID;
        req.structure_size = (HEADER_SIZE as u16).into();
        req.command = command::TREE_CONNECT.into();
        req.message_id = 7.into();
        req.session_id = 0x1234.into();
        req.tree_id = 9.into();
        let resp = Header::response_for(&req, status::SUCCESS);
        assert_eq!(resp.message_id.get(), 7);
        assert_eq!(resp.session_id.get(), 0x1234);
        assert_eq!(resp.tree_id.get(), 9);
        assert_eq!(resp.command.get(), command::TREE_CONNECT);
        assert_eq!(
            resp.flags.get() & FLAGS_SERVER_TO_REDIR,
            FLAGS_SERVER_TO_REDIR
        );
    }
}

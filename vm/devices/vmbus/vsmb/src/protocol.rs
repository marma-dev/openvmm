// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! vSMB wire protocol constants and structures.
//!
//! These mirror the host<->guest contract used by the inbox Windows SMB
//! redirector ("RDR"), taken from the Hyper-V `vsmbversion.h` published header.
//!
//! The transport is a VMBus **byte pipe**. A stream of *segments* flows over
//! it. Each segment is prefixed with a 4-byte, **big-endian** header:
//!
//! ```text
//! bits 31..24  segment type  (SMB = 0x00, VERSION = 0x01)
//! bits 23..0   segment length (payload byte count, excluding this header)
//! ```
//!
//! The first segment the guest sends is a VERSION segment used to negotiate
//! the protocol version and capabilities. After that, SMB2 segments flow.

#![allow(dead_code)]

use guid::Guid;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::little_endian::U32 as u32_le;

/// vSMB VMBus interface (device) type GUID. Matches `VSMB_INTERFACE_GUID` in
/// the Hyper-V source (`vsmbnet.cpp`).
pub const INTERFACE_TYPE: Guid = guid::guid!("4d12e519-17a0-4ae4-8eaa-5270fc6abdb7");

/// vSMB VMBus channel instance GUID. Matches `VSMB_INTERFACE_INSTANCE_GUID`
/// and the `\\?\VMSMB\VSMB-{dcc079ae-...}` path used by hcsshim.
pub const INSTANCE: Guid = guid::guid!("dcc079ae-60ba-4d07-847c-3493609c0870");

/// Segment header type: an SMB2 payload.
pub const SEGMENT_HEADER_TYPE_SMB: u32 = 0x0000_0000;
/// Segment header type: a version-negotiation payload.
pub const SEGMENT_HEADER_TYPE_VERSION: u32 = 0x0100_0000;
/// Mask selecting the segment type bits from the segment header.
pub const SEGMENT_HEADER_TYPE_MASK: u32 = 0xFF00_0000;

/// Returned in a version response when the requested version is unsupported.
pub const PROTOCOL_VERSION_INVALID: u32 = 0xFFFF_FFFF;
/// RS1-era pre-negotiation version.
pub const PROTOCOL_VERSION_LEGACY: u32 = 0;
/// RS2 version: supports RFG and protocol negotiation.
pub const PROTOCOL_VERSION_1: u32 = 1;
/// Highest version this host understands.
pub const PROTOCOL_VERSION_CURRENT: u32 = PROTOCOL_VERSION_1;

/// Capability flag: RDMA-v2 (the DirectMap / zero-copy channel).
pub const CAPABILITY_FLAG_RDMA_V2: u32 = 0x0000_0001;
/// All capability flags this host knows about.
pub const CAPABILITY_KNOWN_FLAGS: u32 = 0x0000_0001;

/// The maximum segment payload length this device will accept from the guest.
///
/// The wire format allows up to 24 bits (~16 MiB); we cap smaller to bound
/// guest-controlled allocations during bring-up.
pub const MAX_SEGMENT_LEN: usize = 1 << 20;

/// A version-negotiation packet. Mirrors `VSMB_SEGMENT_VERSION_PACKET`.
///
/// The fields are plain little-endian `ULONG`s (the Hyper-V source does not
/// byte-swap them; only the segment header is network byte order).
#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct VersionPacket {
    /// Guest: highest supported version. Host: accepted version, or
    /// [`PROTOCOL_VERSION_INVALID`].
    pub version_requested: u32_le,
    /// Guest: requested capability bits. Host: the subset it will support.
    pub capabilities: u32_le,
}

/// Builds the big-endian segment header value from a type and payload length.
pub fn segment_header(segment_type: u32, payload_len: usize) -> u32 {
    (payload_len as u32 & !SEGMENT_HEADER_TYPE_MASK) | (segment_type & SEGMENT_HEADER_TYPE_MASK)
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resources for the vSMB (SMB-over-VMBus) device.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
use vm_resource::ResourceId;
use vm_resource::kind::VmbusDeviceHandleKind;

/// A single share exposed to the guest by the vSMB device.
#[derive(Debug, Clone, MeshPayload)]
pub struct VsmbShare {
    /// The share name, as it appears in the guest UNC path
    /// (`\\?\VMSMB\VSMB-{instance}\<name>`).
    pub name: String,
    /// The host directory backing the share.
    pub path: String,
    /// Whether the share is read-only (image layers) or read-write (host
    /// mounts).
    pub read_only: bool,
}

/// A handle to a vSMB device.
///
/// This is an early (M0) scaffold: the device currently only performs vSMB
/// transport bring-up (channel offer + protocol version negotiation). The
/// SMB2 file-serving engine is a later milestone, at which point `shares`
/// will be served to the guest.
#[derive(MeshPayload)]
pub struct VsmbDeviceHandle {
    /// The shares to expose once the SMB2 engine is implemented.
    pub shares: Vec<VsmbShare>,
}

impl ResourceId<VmbusDeviceHandleKind> for VsmbDeviceHandle {
    const ID: &'static str = "vsmb";
}

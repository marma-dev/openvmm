// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resources for the vmbfs device.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
use std::fs::File;
use vm_resource::ResourceId;
use vm_resource::kind::VmbusDeviceHandleKind;

/// A handle to a vmbfs device for providing an IMC hive to the Windows boot
/// loader.
#[derive(MeshPayload)]
pub struct VmbfsImcDeviceHandle {
    /// The file containing the IMC hive data.
    pub file: File,
}

impl ResourceId<VmbusDeviceHandleKind> for VmbfsImcDeviceHandle {
    const ID: &'static str = "vmbfs-imc";
}

/// A handle to a vmbfs device for booting the guest over vmbfs (the BOOT
/// instance): serves a host directory tree of OS/boot files read-only, so the
/// Hyper-V UEFI firmware can load `bootmgfw.efi` and boot from it (mirroring
/// hcsshim's `Uefi.BootThis = { DeviceType: VmbFs }` for WCOW UVMs).
#[derive(MeshPayload)]
pub struct VmbfsBootDeviceHandle {
    /// The host directory whose contents are served read-only (e.g. a WCOW
    /// image layer's `UtilityVM\Files`).
    pub files_dir: String,
}

impl ResourceId<VmbusDeviceHandleKind> for VmbfsBootDeviceHandle {
    const ID: &'static str = "vmbfs-boot";
}

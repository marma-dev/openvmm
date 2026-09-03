// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provides a resolver for the vmbfs device.

use crate::VmbfsDevice;
use crate::dir_backing::VmbfsDirBacking;
use crate::protocol;
use crate::single_file_backing::VmbfsSingleFileBacking;
use std::convert::Infallible;
use vm_resource::ResolveResource;
use vm_resource::declare_static_resolver;
use vm_resource::kind::VmbusDeviceHandleKind;
use vmbfs_resources::VmbfsBootDeviceHandle;
use vmbfs_resources::VmbfsImcDeviceHandle;
use vmbus_channel::resources::ResolveVmbusDeviceHandleParams;
use vmbus_channel::resources::ResolvedVmbusDevice;
use vmbus_channel::simple::SimpleDeviceWrapper;

/// Resolver for the vmbfs device.
pub struct VmbfsResolver;

declare_static_resolver! {
    VmbfsResolver,
    (VmbusDeviceHandleKind, VmbfsImcDeviceHandle),
    (VmbusDeviceHandleKind, VmbfsBootDeviceHandle),
}

impl ResolveResource<VmbusDeviceHandleKind, VmbfsImcDeviceHandle> for VmbfsResolver {
    type Output = ResolvedVmbusDevice;
    type Error = Infallible;

    fn resolve(
        &self,
        resource: VmbfsImcDeviceHandle,
        input: ResolveVmbusDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let backing = VmbfsSingleFileBacking::new("imc.hiv", resource.file).unwrap();
        let device = VmbfsDevice::new(protocol::IMC_INSTANCE, Box::new(backing));
        Ok(SimpleDeviceWrapper::new(input.driver_source.simple(), device).into())
    }
}

impl ResolveResource<VmbusDeviceHandleKind, VmbfsBootDeviceHandle> for VmbfsResolver {
    type Output = ResolvedVmbusDevice;
    type Error = Infallible;

    fn resolve(
        &self,
        resource: VmbfsBootDeviceHandle,
        input: ResolveVmbusDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let backing = VmbfsDirBacking::new(resource.files_dir.into());
        let device = VmbfsDevice::new(protocol::BOOT_INSTANCE, Box::new(backing));
        Ok(SimpleDeviceWrapper::new(input.driver_source.simple(), device).into())
    }
}

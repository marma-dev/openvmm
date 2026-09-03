// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provides a resolver for the vSMB device.

use crate::VsmbDevice;
use std::convert::Infallible;
use vm_resource::ResolveResource;
use vm_resource::declare_static_resolver;
use vm_resource::kind::VmbusDeviceHandleKind;
use vmbus_channel::resources::ResolveVmbusDeviceHandleParams;
use vmbus_channel::resources::ResolvedVmbusDevice;
use vmbus_channel::simple::SimpleDeviceWrapper;
use vsmb_resources::VsmbDeviceHandle;

/// Resolver for the vSMB device.
pub struct VsmbResolver;

declare_static_resolver! {
    VsmbResolver,
    (VmbusDeviceHandleKind, VsmbDeviceHandle),
}

impl ResolveResource<VmbusDeviceHandleKind, VsmbDeviceHandle> for VsmbResolver {
    type Output = ResolvedVmbusDevice;
    type Error = Infallible;

    fn resolve(
        &self,
        resource: VsmbDeviceHandle,
        input: ResolveVmbusDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let device = VsmbDevice::new(resource.shares);
        Ok(SimpleDeviceWrapper::new(input.driver_source.simple(), device).into())
    }
}

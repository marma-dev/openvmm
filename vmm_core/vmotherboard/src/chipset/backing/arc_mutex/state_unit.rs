// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::VmmChipsetDevice;
use async_trait::async_trait;
use closeable_mutex::CloseableMutex;
use futures::FutureExt;
use futures::StreamExt;
use futures::task::ArcWake;
use futures::task::WakerRef;
use futures::task::waker_ref;
use inspect::InspectMut;
use state_unit::StateRequest;
use state_unit::StateUnit;
use std::sync::Arc;
use std::task::Context;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SavedStateBlob;
use vmcore::slim_event::SlimEvent;

pub struct ArcMutexChipsetDeviceUnit {
    device: Arc<CloseableMutex<dyn DynDevice>>,
    poll_event: Arc<PollEvent>,
    running: bool,
    omit_saved_state: bool,
}

impl InspectMut for ArcMutexChipsetDeviceUnit {
    fn inspect_mut(&mut self, req: inspect::Request<'_>) {
        self.device.lock().inspect_mut(req);
    }
}

/// Object-safe trait for the subset of [`VmmChipsetDevice`] that we use here.
#[async_trait]
trait DynDevice: InspectMut + Send {
    fn start(&mut self);
    async fn stop(&mut self);
    async fn reset(&mut self);
    fn poll_device(&mut self, cx: &mut Context<'_>);
    fn save(&mut self) -> Result<SavedStateBlob, SaveError>;
    fn restore(&mut self, state: SavedStateBlob) -> Result<(), RestoreError>;
}

#[async_trait]
impl<T: VmmChipsetDevice> DynDevice for T {
    fn start(&mut self) {
        self.start()
    }

    async fn stop(&mut self) {
        self.stop().await
    }

    async fn reset(&mut self) {
        self.reset().await
    }

    fn poll_device(&mut self, cx: &mut Context<'_>) {
        if let Some(poll) = self.supports_poll_device() {
            poll.poll_device(cx);
        }
    }

    fn save(&mut self) -> Result<SavedStateBlob, SaveError> {
        self.save()
    }

    fn restore(&mut self, state: SavedStateBlob) -> Result<(), RestoreError> {
        self.restore(state)
    }
}

struct PollEvent(SlimEvent);

impl ArcWake for PollEvent {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.signal();
    }
}

impl ArcMutexChipsetDeviceUnit {
    pub fn new(
        device: Arc<CloseableMutex<impl 'static + VmmChipsetDevice>>,
        omit_saved_state: bool,
    ) -> Self {
        Self {
            device,
            poll_event: Arc::new(PollEvent(SlimEvent::new())),
            running: false,
            omit_saved_state,
        }
    }

    pub async fn run(mut self, mut state_change: mesh::Receiver<StateRequest>) -> Self {
        loop {
            enum Event<'a> {
                StateChange(StateRequest),
                Poll(WakerRef<'a>),
            }

            // Wait for poll requests.
            let poll_fut = async {
                if self.running {
                    self.poll_event.0.wait().await;
                    return waker_ref(&self.poll_event);
                }
                // The device is not running. Never
                // complete this future.
                std::future::pending().await
            };

            let event = futures::select! {
                req = state_change.next() => {
                    if let Some(req) = req {
                        Event::StateChange(req)
                    } else {
                        break;
                    }
                }
                waker = poll_fut.fuse() => {
                    Event::Poll(waker)
                }
            };

            match event {
                Event::StateChange(req) => {
                    req.apply(&mut self).await;
                }
                Event::Poll(waker) => {
                    let mut device = self.device.lock();
                    device.poll_device(&mut Context::from_waker(&waker));
                }
            }
        }
        // The unit was removed. Never return a started device: dropping it
        // would abandon work it may not be able to abandon safely (for
        // example, virtio-blk's in-flight io_uring requests, whose drop aborts
        // the process). Stopping it lets it quiesce first.
        if self.running {
            self.stop().await;
        }
        self
    }
}

impl StateUnit for ArcMutexChipsetDeviceUnit {
    async fn start(&mut self) {
        self.running = true;

        // Poll the device at least once.
        let mut device = self.device.lock();
        device.start();
        device.poll_device(&mut Context::from_waker(&waker_ref(&self.poll_event)));
    }

    async fn stop(&mut self) {
        self.device.clone().close().stop().await;
        self.running = false;
        // FUTURE: consider closing the mutex while the device is stopped to
        // find bugs. This may be difficult or not worth it since it requires
        // that:
        //
        // 1. all cross-device dependencies are exactly correct.
        // 2. no device manipulation happens externally to normal VM operation
        //    (e.g., no calls are made to the device while the VM is stopped).
        //
        // These are currently not true.
    }

    async fn reset(&mut self) -> anyhow::Result<()> {
        self.device.clone().close().reset().await;
        Ok(())
    }

    async fn save(&mut self) -> Result<Option<SavedStateBlob>, SaveError> {
        if self.omit_saved_state {
            return Ok(None);
        }

        // TODO: make async
        let state = self.device.clone().close().save()?;
        Ok(Some(state))
    }

    async fn restore(&mut self, state: SavedStateBlob) -> Result<(), RestoreError> {
        // TODO: make async
        self.device.clone().close().restore(state)
    }
}

#[cfg(test)]
mod tests {
    use super::ArcMutexChipsetDeviceUnit;
    use chipset_device::ChipsetDevice;
    use closeable_mutex::CloseableMutex;
    use inspect::InspectMut;
    use mesh::rpc::Rpc;
    use mesh::rpc::RpcSend;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use state_unit::StateRequest;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use test_with_tracing::test;
    use vmcore::device_state::ChangeDeviceState;
    use vmcore::save_restore::RestoreError;
    use vmcore::save_restore::SaveError;
    use vmcore::save_restore::SaveRestore;
    use vmcore::save_restore::SavedStateNotSupported;

    #[derive(Default)]
    struct TestDevice {
        running: Arc<AtomicBool>,
        stops: Arc<AtomicUsize>,
    }

    impl ChangeDeviceState for TestDevice {
        fn start(&mut self) {
            self.running.store(true, Ordering::SeqCst);
        }

        async fn stop(&mut self) {
            self.running.store(false, Ordering::SeqCst);
            self.stops.fetch_add(1, Ordering::SeqCst);
        }

        async fn reset(&mut self) {}
    }

    impl ChipsetDevice for TestDevice {}

    impl SaveRestore for TestDevice {
        type SavedState = SavedStateNotSupported;

        fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            Err(SaveError::NotSupported)
        }

        fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
            match state {}
        }
    }

    impl InspectMut for TestDevice {
        fn inspect_mut(&mut self, req: inspect::Request<'_>) {
            req.respond();
        }
    }

    /// Runs a unit for `device`, applies `requests` in order, then closes the
    /// request channel, which is how unit removal ends the unit.
    async fn run_then_remove(device: TestDevice, requests: &[fn(Rpc<(), ()>) -> StateRequest]) {
        let unit = ArcMutexChipsetDeviceUnit::new(Arc::new(CloseableMutex::new(device)), true);
        let (send, recv) = mesh::channel();
        let control = async {
            for &request in requests {
                send.call(request, ()).await.unwrap();
            }
            drop(send);
        };
        futures::join!(unit.run(recv), control);
    }

    #[async_test]
    async fn removing_a_running_unit_stops_the_device(_driver: DefaultDriver) {
        let device = TestDevice::default();
        let (running, stops) = (device.running.clone(), device.stops.clone());
        run_then_remove(device, &[StateRequest::Start]).await;
        assert!(
            !running.load(Ordering::SeqCst),
            "removed device left running"
        );
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[async_test]
    async fn removing_a_stopped_unit_does_not_stop_again(_driver: DefaultDriver) {
        let device = TestDevice::default();
        let stops = device.stops.clone();
        run_then_remove(device, &[StateRequest::Start, StateRequest::Stop]).await;
        assert_eq!(stops.load(Ordering::SeqCst), 1);
    }

    #[async_test]
    async fn removing_a_never_started_unit_does_not_stop(_driver: DefaultDriver) {
        let device = TestDevice::default();
        let stops = device.stops.clone();
        run_then_remove(device, &[]).await;
        assert_eq!(stops.load(Ordering::SeqCst), 0);
    }
}

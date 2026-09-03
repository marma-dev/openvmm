// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! vSMB (SMB-over-VMBus) host device for OpenVMM.
//!
//! This is the **M0** milestone of a vSMB-on-OpenVMM prototype: it offers the
//! Hyper-V vSMB VMBus channel (so the inbox Windows SMB redirector binds to
//! it) and performs the vSMB **protocol version negotiation**. The goal is to
//! prove the transport seam — that an OpenVMM software-vmbus channel can carry
//! the vSMB protocol to a real Windows guest.
//!
//! The SMB2 file-serving engine (needed to actually serve read-only image
//! layers and, later, read-write host mounts) is a subsequent milestone. When
//! an SMB2 segment arrives, this device logs it and stops there.
//!
//! DirectMap / RDMA-v2 is deferred: the vSMB version negotiation masks off the
//! RDMA-v2 capability, but the pipe is still offered with the vmbus GPA-direct
//! flag set (the inbox redirector requires it; offering it off destabilizes the
//! guest). GPA-direct transfers are not yet serviced, so enumeration and small
//! reads use the inline ring-copy path, but **bulk reads/writes — for which the
//! redirector issues `SETUP_GPA_DIRECT` — currently tear the channel down**.
//! Implementing DirectMap (using the `GuestMemory` handed to `open()`) is the
//! prerequisite for full-file transfers (e.g. a real OS-layer WCIFS union).

mod backing;
mod protocol;
pub mod resolver;
mod server;
mod smb2;

use async_trait::async_trait;
use futures::io::AsyncReadExt;
use futures::io::AsyncWriteExt;
use inspect::InspectMut;
use task_control::Cancelled;
use task_control::StopTask;
use thiserror::Error;
use vmbus_async::pipe::BytePipe;
use vmbus_channel::bus::ChannelType;
use vmbus_channel::bus::OfferParams;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_channel::simple::SaveRestoreSimpleVmbusDevice;
use vmbus_channel::simple::SimpleVmbusDevice;
use vmbus_core::protocol::PipeFlags;
use vsmb_resources::VsmbShare;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

/// A vSMB device.
pub struct VsmbDevice {
    shares: Vec<VsmbShare>,
}

impl VsmbDevice {
    /// Creates a new vSMB device exposing the given shares.
    ///
    /// In M0 the shares are held for inspection only; they are not yet served
    /// (the SMB2 engine is not implemented).
    pub fn new(shares: Vec<VsmbShare>) -> Self {
        Self { shares }
    }
}

#[async_trait]
impl SimpleVmbusDevice for VsmbDevice {
    type SavedState = SavedState;
    type Runner = VsmbChannel;

    fn offer(&self) -> OfferParams {
        OfferParams {
            interface_name: "vsmb".to_owned(),
            interface_id: protocol::INTERFACE_TYPE,
            instance_id: protocol::INSTANCE,
            // vSMB is offered as a byte-mode pipe with GPA-direct enabled, to
            // match the Hyper-V offer the inbox redirector expects (offering it
            // disabled destabilizes the guest). DirectMap (GPA-direct)
            // servicing is deferred: the `BytePipe` ring-copy reader handles
            // inline DATA/PARTIAL only, so enumeration and small reads work but
            // bulk reads/writes — for which the redirector issues
            // SETUP_GPA_DIRECT — are torn down until DirectMap is implemented.
            channel_type: ChannelType::Pipe {
                message_mode: false,
                user_defined: Default::default(),
                pipe_flags: PipeFlags::new().with_gpa_direct(true),
            },
            ..Default::default()
        }
    }

    fn inspect(&mut self, req: inspect::Request<'_>, runner: Option<&mut Self::Runner>) {
        req.respond()
            .field("share_count", self.shares.len())
            .merge(runner);
    }

    fn open(
        &mut self,
        channel: vmbus_channel::RawAsyncChannel<GpadlRingMem>,
        _guest_memory: guestmem::GuestMemory,
    ) -> Result<Self::Runner, vmbus_channel::channel::ChannelOpenError> {
        let server = server::Smb2Server::new(self.shares.iter().map(|s| {
            (
                s.name.clone(),
                server::Share {
                    root: s.path.clone(),
                },
            )
        }));
        Ok(VsmbChannel {
            pipe: BytePipe::new(channel)?,
            server,
        })
    }

    async fn run(
        &mut self,
        stop: &mut StopTask<'_>,
        runner: &mut Self::Runner,
    ) -> Result<(), Cancelled> {
        stop.until_stopped(runner.process()).await
    }

    fn supports_save_restore(
        &mut self,
    ) -> Option<
        &mut dyn SaveRestoreSimpleVmbusDevice<SavedState = Self::SavedState, Runner = Self::Runner>,
    > {
        // M0: no meaningful state to preserve; the channel is revoked and
        // re-offered on restore.
        None
    }
}

/// The saved state for the vSMB device. Unused in M0 (see
/// [`SimpleVmbusDevice::supports_save_restore`]).
#[derive(mesh::payload::Protobuf, vmcore::save_restore::SavedStateRoot)]
#[mesh(package = "vsmb")]
pub struct SavedState {}

/// The runner for an open vSMB channel.
#[doc(hidden)]
#[derive(InspectMut)]
pub struct VsmbChannel {
    #[inspect(mut)]
    pipe: BytePipe<GpadlRingMem>,
    #[inspect(skip)]
    server: server::Smb2Server,
}

impl VsmbChannel {
    async fn process(&mut self) {
        match serve_connection(&mut self.pipe, &mut self.server).await {
            Ok(()) => {
                tracing::info!("vsmb channel closed");
            }
            Err(err) => {
                tracelimit::error_ratelimited!(
                    error = &err as &dyn std::error::Error,
                    "vsmb channel failed"
                );
            }
        }
    }
}

/// Serves one vSMB connection over `pipe` until the guest closes it.
///
/// This is generic over the pipe type so it can be driven both by the real
/// device runner (a [`BytePipe`] over a live vmbus ring) and by integration
/// tests (a byte pipe over a test ring). It first handles vSMB version
/// negotiation, then routes SMB2 segments into `server`.
async fn serve_connection<P>(
    pipe: &mut P,
    server: &mut server::Smb2Server,
) -> Result<(), DeviceError>
where
    P: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin,
{
    let mut negotiated = false;
    loop {
        // Read the 4-byte, big-endian segment header.
        let mut header_bytes = [0u8; 4];
        match pipe.read_exact(&mut header_bytes).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Guest closed the pipe.
                return Ok(());
            }
            Err(err) => return Err(DeviceError::Io(err)),
        }

        let header = u32::from_be_bytes(header_bytes);
        let segment_type = header & protocol::SEGMENT_HEADER_TYPE_MASK;
        let payload_len = (header & !protocol::SEGMENT_HEADER_TYPE_MASK) as usize;

        if payload_len > protocol::MAX_SEGMENT_LEN {
            return Err(DeviceError::SegmentTooLarge(payload_len));
        }

        let mut payload = vec![0u8; payload_len];
        pipe.read_exact(&mut payload)
            .await
            .map_err(DeviceError::Io)?;

        match segment_type {
            protocol::SEGMENT_HEADER_TYPE_VERSION => {
                let response = handle_version(&payload, &mut negotiated)?;
                send_segment(
                    pipe,
                    protocol::SEGMENT_HEADER_TYPE_VERSION,
                    response.as_bytes(),
                )
                .await?;
            }
            protocol::SEGMENT_HEADER_TYPE_SMB => match server.handle(&payload) {
                Some(response) => {
                    send_segment(pipe, protocol::SEGMENT_HEADER_TYPE_SMB, &response).await?;
                }
                None => {
                    tracelimit::warn_ratelimited!("vsmb: undecodable SMB2 segment; dropping");
                }
            },
            other => {
                tracelimit::warn_ratelimited!(segment_type = other, "vsmb: unknown segment type");
            }
        }
    }
}

/// Computes the version-negotiation response for a VERSION segment payload,
/// updating `negotiated` when a version is accepted.
fn handle_version(
    payload: &[u8],
    negotiated: &mut bool,
) -> Result<protocol::VersionPacket, DeviceError> {
    let request = protocol::VersionPacket::read_from_prefix(payload)
        .map_err(|_| DeviceError::ShortVersionPacket)?
        .0;
    let requested = request.version_requested.get();

    // DirectMap/RDMA-v2 is deferred, so advertise no capabilities.
    let response = version_response(requested, request.capabilities.get(), 0);

    if response.version_requested.get() == protocol::PROTOCOL_VERSION_INVALID {
        tracelimit::warn_ratelimited!(requested, "vsmb: unsupported protocol version requested");
    } else {
        *negotiated = true;
        tracing::info!(
            version = response.version_requested.get(),
            capabilities = response.capabilities.get(),
            "vsmb: protocol version negotiated"
        );
    }
    Ok(response)
}

/// Frames and writes one vSMB segment (big-endian header + payload) to `pipe`.
async fn send_segment<P>(pipe: &mut P, segment_type: u32, payload: &[u8]) -> Result<(), DeviceError>
where
    P: futures::io::AsyncWrite + Unpin,
{
    let header = protocol::segment_header(segment_type, payload.len());
    pipe.write_all(&header.to_be_bytes())
        .await
        .map_err(DeviceError::Io)?;
    pipe.write_all(payload).await.map_err(DeviceError::Io)?;
    pipe.flush().await.map_err(DeviceError::Io)?;
    Ok(())
}

#[derive(Debug, Error)]
enum DeviceError {
    #[error("vmbus pipe i/o error")]
    Io(#[source] std::io::Error),
    #[error("version packet too short")]
    ShortVersionPacket,
    #[error("segment payload too large: {0} bytes")]
    SegmentTooLarge(usize),
}

/// Computes the vSMB version-negotiation response, per the Hyper-V
/// `VSmbpNegotiateProtocolVersion` logic.
///
/// If `requested` is newer than this host understands, the response version is
/// [`protocol::PROTOCOL_VERSION_INVALID`] (the guest then steps down and
/// retries). Otherwise the version is echoed and the negotiated capabilities
/// are the intersection of the guest's request and the host's support.
fn version_response(requested: u32, guest_caps: u32, host_caps: u32) -> protocol::VersionPacket {
    if requested > protocol::PROTOCOL_VERSION_CURRENT {
        protocol::VersionPacket {
            version_requested: protocol::PROTOCOL_VERSION_INVALID.into(),
            capabilities: 0.into(),
        }
    } else {
        protocol::VersionPacket {
            version_requested: requested.into(),
            capabilities: (guest_caps & host_caps).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_header_round_trip() {
        let header = protocol::segment_header(protocol::SEGMENT_HEADER_TYPE_VERSION, 8);
        assert_eq!(
            header & protocol::SEGMENT_HEADER_TYPE_MASK,
            protocol::SEGMENT_HEADER_TYPE_VERSION
        );
        assert_eq!((header & !protocol::SEGMENT_HEADER_TYPE_MASK) as usize, 8);

        let header = protocol::segment_header(protocol::SEGMENT_HEADER_TYPE_SMB, 4096);
        assert_eq!(
            header & protocol::SEGMENT_HEADER_TYPE_MASK,
            protocol::SEGMENT_HEADER_TYPE_SMB
        );
        assert_eq!(
            (header & !protocol::SEGMENT_HEADER_TYPE_MASK) as usize,
            4096
        );
    }

    #[test]
    fn version_negotiation_accepts_v1() {
        // Guest requests v1 with RDMA-v2; host offers no capabilities (M0).
        let resp = version_response(
            protocol::PROTOCOL_VERSION_1,
            protocol::CAPABILITY_FLAG_RDMA_V2,
            0,
        );
        assert_eq!(resp.version_requested.get(), protocol::PROTOCOL_VERSION_1);
        assert_eq!(resp.capabilities.get(), 0);
    }

    #[test]
    fn version_negotiation_intersects_capabilities() {
        // Host supports RDMA-v2, guest requests it: it survives the intersection.
        let resp = version_response(
            protocol::PROTOCOL_VERSION_1,
            protocol::CAPABILITY_FLAG_RDMA_V2,
            protocol::CAPABILITY_KNOWN_FLAGS,
        );
        assert_eq!(resp.capabilities.get(), protocol::CAPABILITY_FLAG_RDMA_V2);
    }

    #[test]
    fn version_negotiation_rejects_newer_version() {
        let resp = version_response(protocol::PROTOCOL_VERSION_CURRENT + 1, 0, 0);
        assert_eq!(
            resp.version_requested.get(),
            protocol::PROTOCOL_VERSION_INVALID
        );
    }

    #[test]
    fn version_negotiation_allows_legacy() {
        let resp = version_response(protocol::PROTOCOL_VERSION_LEGACY, 0, 0);
        assert_eq!(
            resp.version_requested.get(),
            protocol::PROTOCOL_VERSION_LEGACY
        );
    }
}

/// Integration tests that drive the vSMB connection loop over a real vmbus
/// byte-pipe ring (host and guest connected in-process), exercising the async
/// segment framing and the SMB2 server end to end.
#[cfg(test)]
mod ring_tests {
    use super::*;
    use futures::io::AsyncReadExt;
    use futures::io::AsyncWriteExt;
    use pal_async::DefaultDriver;
    use pal_async::async_test;
    use pal_async::task::Spawn;
    use vmbus_async::pipe::connected_byte_pipes;
    use zerocopy::FromBytes;
    use zerocopy::IntoBytes;

    /// Sends one vSMB segment on the guest pipe and reads back the response
    /// segment, returning its (segment_type, payload).
    async fn round_trip<P>(guest: &mut P, seg_type: u32, payload: &[u8]) -> (u32, Vec<u8>)
    where
        P: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin,
    {
        let header = protocol::segment_header(seg_type, payload.len());
        guest.write_all(&header.to_be_bytes()).await.unwrap();
        guest.write_all(payload).await.unwrap();
        guest.flush().await.unwrap();

        let mut hb = [0u8; 4];
        guest.read_exact(&mut hb).await.unwrap();
        let h = u32::from_be_bytes(hb);
        let len = (h & !protocol::SEGMENT_HEADER_TYPE_MASK) as usize;
        let mut buf = vec![0u8; len];
        guest.read_exact(&mut buf).await.unwrap();
        (h & protocol::SEGMENT_HEADER_TYPE_MASK, buf)
    }

    /// Builds an SMB2 request segment payload: header + body.
    fn smb_request(command: u16, session_id: u64, tree_id: u32, body: &[u8]) -> Vec<u8> {
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

    #[async_test]
    async fn negotiate_and_read_over_ring(driver: DefaultDriver) {
        // Lay out a "layer" file on the host.
        let dir = std::env::temp_dir().join(format!("vsmb-ring-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("layer.bin"), b"RING-SERVED-LAYER").unwrap();

        let (mut host, mut guest) = connected_byte_pipes(64 * 1024);
        let mut server = server::Smb2Server::new([(
            "layers".to_owned(),
            server::Share {
                root: dir.to_string_lossy().into_owned(),
            },
        )]);

        // Run the host connection loop as a background task, exactly as the
        // device runner does, but over the test ring.
        let host_task = driver.spawn("vsmb-host", async move {
            let _ = serve_connection(&mut host, &mut server).await;
        });

        // 1) vSMB version negotiation.
        let ver = protocol::VersionPacket {
            version_requested: protocol::PROTOCOL_VERSION_1.into(),
            capabilities: 0.into(),
        };
        let (seg, resp) = round_trip(
            &mut guest,
            protocol::SEGMENT_HEADER_TYPE_VERSION,
            ver.as_bytes(),
        )
        .await;
        assert_eq!(seg, protocol::SEGMENT_HEADER_TYPE_VERSION);
        let (vresp, _) = protocol::VersionPacket::read_from_prefix(&resp).unwrap();
        assert_eq!(vresp.version_requested.get(), protocol::PROTOCOL_VERSION_1);

        // 2) SMB2 NEGOTIATE.
        let neg = smb2::NegotiateRequest {
            structure_size: 36.into(),
            dialect_count: 1.into(),
            security_mode: 1.into(),
            reserved: 0.into(),
            capabilities: 0.into(),
            client_guid: [0; 16],
            client_start_time: 0.into(),
        };
        let mut neg_body = neg.as_bytes().to_vec();
        neg_body.extend_from_slice(&smb2::DIALECT_2_0_2.to_le_bytes());
        let (_, resp) = round_trip(
            &mut guest,
            protocol::SEGMENT_HEADER_TYPE_SMB,
            &smb_request(smb2::command::NEGOTIATE, 0, 0, &neg_body),
        )
        .await;
        assert_eq!(
            smb2::parse_header(&resp).unwrap().0.status.get(),
            smb2::status::SUCCESS
        );

        // 3) SESSION_SETUP -> session id.
        let ss = smb2::SessionSetupRequest {
            structure_size: 25.into(),
            flags: 0,
            security_mode: 1,
            capabilities: 0.into(),
            channel: 0.into(),
            security_buffer_offset: 0.into(),
            security_buffer_length: 0.into(),
            previous_session_id: 0.into(),
        };
        let (_, resp) = round_trip(
            &mut guest,
            protocol::SEGMENT_HEADER_TYPE_SMB,
            &smb_request(smb2::command::SESSION_SETUP, 0, 0, ss.as_bytes()),
        )
        .await;
        let session_id = smb2::parse_header(&resp).unwrap().0.session_id.get();
        assert_ne!(session_id, 0);

        // 4) TREE_CONNECT -> tree id.
        let path_bytes: Vec<u8> = "\\\\server\\layers"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let tc = smb2::TreeConnectRequest {
            structure_size: 9.into(),
            reserved: 0.into(),
            path_offset: ((smb2::HEADER_SIZE + 8) as u16).into(),
            path_length: (path_bytes.len() as u16).into(),
        };
        let mut tc_body = tc.as_bytes().to_vec();
        tc_body.extend_from_slice(&path_bytes);
        let (_, resp) = round_trip(
            &mut guest,
            protocol::SEGMENT_HEADER_TYPE_SMB,
            &smb_request(smb2::command::TREE_CONNECT, session_id, 0, &tc_body),
        )
        .await;
        let tree_id = smb2::parse_header(&resp).unwrap().0.tree_id.get();
        assert_ne!(tree_id, 0);

        // 5) CREATE (open layer.bin) -> file id.
        let name_bytes: Vec<u8> = "layer.bin"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
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
            name_length: (name_bytes.len() as u16).into(),
            create_contexts_offset: 0.into(),
            create_contexts_length: 0.into(),
        };
        let mut cr_body = cr.as_bytes().to_vec();
        cr_body.extend_from_slice(&name_bytes);
        let (_, resp) = round_trip(
            &mut guest,
            protocol::SEGMENT_HEADER_TYPE_SMB,
            &smb_request(smb2::command::CREATE, session_id, tree_id, &cr_body),
        )
        .await;
        let (h, rest) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), smb2::status::SUCCESS);
        let (create, _) = smb2::CreateResponse::read_from_prefix(rest).unwrap();
        assert_eq!(create.end_of_file.get(), 17);
        let file_id = create.file_id;

        // 6) READ -> the layer bytes, served over the ring.
        let rd = smb2::ReadRequest {
            structure_size: 49.into(),
            padding: 0,
            flags: 0,
            length: 17.into(),
            offset: 0.into(),
            file_id,
            minimum_count: 0.into(),
            channel: 0.into(),
            remaining_bytes: 0.into(),
            read_channel_info_offset: 0.into(),
            read_channel_info_length: 0.into(),
        };
        let mut rd_body = rd.as_bytes().to_vec();
        rd_body.push(0);
        let (_, resp) = round_trip(
            &mut guest,
            protocol::SEGMENT_HEADER_TYPE_SMB,
            &smb_request(smb2::command::READ, session_id, tree_id, &rd_body),
        )
        .await;
        let (h, rest) = smb2::parse_header(&resp).unwrap();
        assert_eq!(h.status.get(), smb2::status::SUCCESS);
        let (read, data) = smb2::ReadResponse::read_from_prefix(rest).unwrap();
        assert_eq!(read.data_length.get(), 17);
        assert_eq!(&data[..17], b"RING-SERVED-LAYER");

        // Close the guest side; the host loop sees EOF and returns.
        drop(guest);
        host_task.await;
        std::fs::remove_dir_all(&dir).ok();
    }
}

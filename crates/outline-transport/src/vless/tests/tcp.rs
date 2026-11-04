use std::collections::VecDeque;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;

use super::*;
use crate::frame_io::FrameSource;

/// Hands out a fixed list of frames, then a clean EOF.
struct ScriptedSource(VecDeque<Bytes>);

#[async_trait]
impl FrameSource for ScriptedSource {
    async fn recv_frame(&mut self) -> Result<Option<Bytes>> {
        Ok(self.0.pop_front())
    }

    fn closed_cleanly(&self) -> bool {
        true
    }
}

fn reader(frames: &[&[u8]]) -> VlessTcpReader {
    let frames = frames.iter().map(|frame| Bytes::copy_from_slice(frame)).collect();
    VlessTcpReader::with_source(
        Box::new(ScriptedSource(frames)),
        UpstreamTransportGuard::new("test", "tcp"),
    )
}

fn is_ws_closed(result: Result<Bytes>) -> bool {
    result.is_err_and(|error| error.downcast_ref::<WsClosed>().is_some())
}

// The server holds the response header back to ship it with the first upstream
// bytes, so an upstream that fails before sending any closes the carrier with no
// header at all. The client must read that exactly like a header followed by a
// close: one clean end of stream, not a protocol error.
#[tokio::test]
async fn close_before_the_response_header_reads_as_a_plain_close() {
    assert!(is_ws_closed(reader(&[]).read_chunk().await));
}

#[tokio::test]
async fn close_after_a_bare_response_header_reads_as_a_plain_close() {
    assert!(is_ws_closed(reader(&[&[VLESS_VERSION, 0]]).read_chunk().await));
}

#[tokio::test]
async fn response_header_bundled_with_data_yields_the_data() {
    let mut reader = reader(&[&[VLESS_VERSION, 0, b'h', b'i'], b"there"]);
    assert_eq!(reader.read_chunk().await.unwrap(), Bytes::from_static(b"hi"));
    assert_eq!(reader.read_chunk().await.unwrap(), Bytes::from_static(b"there"));
    assert!(is_ws_closed(reader.read_chunk().await));
}

#[tokio::test]
async fn response_header_split_across_frames_is_reassembled() {
    let mut reader = reader(&[&[VLESS_VERSION], &[1], &[0xaa, b'x']]);
    assert_eq!(reader.read_chunk().await.unwrap(), Bytes::from_static(b"x"));
}

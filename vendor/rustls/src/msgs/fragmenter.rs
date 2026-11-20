use crate::Error;
use crate::enums::{ContentType, ProtocolVersion};
use crate::msgs::message::{OutboundChunks, OutboundPlainMessage, PlainMessage};
pub(crate) const MAX_FRAGMENT_LEN: usize = 16384;
pub(crate) const PACKET_OVERHEAD: usize = 1 + 2 + 2;
pub(crate) const MAX_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN + PACKET_OVERHEAD;

/// Conservative estimate of MSS application payload size (matches Go crypto/tls tcpMSSEstimate 1208 bytes,
/// minus 5 bytes record header, 1 byte TLS 1.3 content type, and 16 bytes AEAD overhead = 1186 bytes).
pub(crate) const TCP_MSS_PAYLOAD: usize = 1186;

/// Number of application data bytes before boosting TLS record size to maximum (128 KiB, matches Go crypto/tls).
pub(crate) const RECORD_SIZE_BOOST_THRESHOLD: usize = 128 * 1024;

pub struct MessageFragmenter {
    max_frag: usize,
}

impl Default for MessageFragmenter {
    fn default() -> Self {
        Self {
            max_frag: MAX_FRAGMENT_LEN,
        }
    }
}

impl MessageFragmenter {
    /// Take `msg` and fragment it into new messages with the same type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `msg`.
    pub fn fragment_message<'a>(
        &self,
        msg: &'a PlainMessage,
    ) -> impl Iterator<Item = OutboundPlainMessage<'a>> + 'a {
        self.fragment_payload(msg.typ, msg.version, msg.payload.bytes().into())
    }

    /// Take `payload` and fragment it into new messages with given type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `payload`.
    pub(crate) fn fragment_payload<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: OutboundChunks<'a>,
    ) -> impl ExactSizeIterator<Item = OutboundPlainMessage<'a>> {
        Chunker::new(payload, self.max_frag).map(move |payload| OutboundPlainMessage {
            typ,
            version,
            payload,
        })
    }

    /// Take application data `payload` and fragment it into new messages with dynamic sizing
    /// matching Go/Caddy behavior if `dynamic` is true.
    pub(crate) fn fragment_appdata_payload<'a>(
        &self,
        payload: OutboundChunks<'a>,
        dynamic: bool,
        bytes_sent: usize,
    ) -> impl ExactSizeIterator<Item = OutboundPlainMessage<'a>> {
        Chunker::new_dynamic(payload, self.max_frag, dynamic, bytes_sent).map(move |payload| {
            OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload,
            }
        })
    }

    /// Set the maximum fragment size that will be produced.
    ///
    /// This includes overhead. A `max_fragment_size` of 10 will produce TLS fragments
    /// up to 10 bytes long.
    ///
    /// A `max_fragment_size` of `None` sets the highest allowable fragment size.
    ///
    /// Returns BadMaxFragmentSize if the size is smaller than 32 or larger than 16389.
    pub fn set_max_fragment_size(&mut self, max_fragment_size: Option<usize>) -> Result<(), Error> {
        self.max_frag = match max_fragment_size {
            Some(sz @ 32..=MAX_FRAGMENT_SIZE) => sz - PACKET_OVERHEAD,
            None => MAX_FRAGMENT_LEN,
            _ => return Err(Error::BadMaxFragmentSize),
        };
        Ok(())
    }
}

/// An iterator over borrowed fragments of a payload
struct Chunker<'a> {
    payload: OutboundChunks<'a>,
    limit: usize,
    dynamic: bool,
    bytes_sent: usize,
}

impl<'a> Chunker<'a> {
    fn new(payload: OutboundChunks<'a>, limit: usize) -> Self {
        Self {
            payload,
            limit,
            dynamic: false,
            bytes_sent: 0,
        }
    }

    fn new_dynamic(
        payload: OutboundChunks<'a>,
        limit: usize,
        dynamic: bool,
        bytes_sent: usize,
    ) -> Self {
        Self {
            payload,
            limit,
            dynamic,
            bytes_sent,
        }
    }
}

impl<'a> Iterator for Chunker<'a> {
    type Item = OutboundChunks<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        let chunk_limit = if self.dynamic && self.bytes_sent < RECORD_SIZE_BOOST_THRESHOLD {
            TCP_MSS_PAYLOAD.min(self.limit)
        } else {
            self.limit
        };

        let (before, after) = self.payload.split_at(chunk_limit);
        self.payload = after;
        self.bytes_sent = self.bytes_sent.saturating_add(before.len());
        Some(before)
    }
}

impl ExactSizeIterator for Chunker<'_> {
    fn len(&self) -> usize {
        let total = self.payload.len();
        if total == 0 {
            return 0;
        }

        if !self.dynamic || self.bytes_sent >= RECORD_SIZE_BOOST_THRESHOLD {
            (total + self.limit - 1) / self.limit
        } else {
            let mut count = 0;
            let mut rem = total;
            let mut sent = self.bytes_sent;
            while rem > 0 {
                let lim = if sent < RECORD_SIZE_BOOST_THRESHOLD {
                    TCP_MSS_PAYLOAD.min(self.limit)
                } else {
                    self.limit
                };
                let chunk = rem.min(lim);
                rem -= chunk;
                sent = sent.saturating_add(chunk);
                count += 1;
            }
            count
        }
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
    use std::vec;

    use super::{MessageFragmenter, PACKET_OVERHEAD};
    use crate::enums::{ContentType, ProtocolVersion};
    use crate::msgs::base::Payload;
    use crate::msgs::message::{OutboundChunks, OutboundPlainMessage, PlainMessage};

    fn msg_eq(
        m: &OutboundPlainMessage<'_>,
        total_len: usize,
        typ: &ContentType,
        version: &ProtocolVersion,
        bytes: &[u8],
    ) {
        assert_eq!(&m.typ, typ);
        assert_eq!(&m.version, version);
        assert_eq!(m.payload.to_vec(), bytes);

        let buf = m.to_unencrypted_opaque().encode();

        assert_eq!(total_len, buf.len());
    }

    #[test]
    fn smoke() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let data: Vec<u8> = (1..70u8).collect();
        let m = PlainMessage {
            typ,
            version,
            payload: Payload::new(data),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 3);
        msg_eq(
            &q[0],
            32,
            &typ,
            &version,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27,
            ],
        );
        msg_eq(
            &q[1],
            32,
            &typ,
            &version,
            &[
                28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                49, 50, 51, 52, 53, 54,
            ],
        );
        msg_eq(
            &q[2],
            20,
            &typ,
            &version,
            &[55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69],
        );
    }

    #[test]
    fn non_fragment() {
        let m = PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 1);
        msg_eq(
            &q[0],
            PACKET_OVERHEAD + 8,
            &ContentType::Handshake,
            &ProtocolVersion::TLSv1_2,
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        );
    }

    #[test]
    fn fragment_multiple_slices() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let payload_owner: Vec<&[u8]> = vec![&[b'a'; 8], &[b'b'; 12], &[b'c'; 32], &[b'd'; 20]];
        let borrowed_payload = OutboundChunks::new(&payload_owner);
        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(37)) // 32 + packet overhead
            .unwrap();

        let fragments = frag
            .fragment_payload(typ, version, borrowed_payload)
            .collect::<Vec<_>>();
        assert_eq!(fragments.len(), 3);
        msg_eq(
            &fragments[0],
            37,
            &typ,
            &version,
            b"aaaaaaaabbbbbbbbbbbbcccccccccccc",
        );
        msg_eq(
            &fragments[1],
            37,
            &typ,
            &version,
            b"ccccccccccccccccccccdddddddddddd",
        );
        msg_eq(&fragments[2], 13, &typ, &version, b"dddddddd");
    }
}

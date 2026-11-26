use super::*;

fn record(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_record_into(payload, &mut out).expect("payload fits the u16 length field");
    out
}

fn drain(decoder: &mut UdpRecordDecoder) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(record) = decoder.next_record() {
        out.push(record.to_vec());
    }
    out
}

#[test]
fn encodes_length_prefix_big_endian() {
    assert_eq!(record(&[0xaa, 0xbb, 0xcc]), vec![0x00, 0x03, 0xaa, 0xbb, 0xcc]);
}

#[test]
fn rejects_a_payload_past_the_length_field() {
    let oversized = vec![0u8; MAX_UDP_RECORD_PAYLOAD + 1];
    let mut out = Vec::new();
    assert_eq!(
        encode_record_into(&oversized, &mut out),
        Err(UdpRecordError::PayloadTooLarge(MAX_UDP_RECORD_PAYLOAD + 1))
    );
    assert!(out.is_empty(), "a rejected payload must not leave a partial record behind");
}

#[test]
fn recovers_two_datagrams_coalesced_into_one_chunk() {
    // The XHTTP carrier hands the receiver an arbitrary slice of the byte
    // stream: two whole datagrams can arrive glued together in one chunk.
    let mut stream = record(b"first datagram");
    stream.extend_from_slice(&record(b"second"));

    let mut decoder = UdpRecordDecoder::new();
    decoder.push(&stream);

    assert_eq!(drain(&mut decoder), vec![b"first datagram".to_vec(), b"second".to_vec()]);
}

#[test]
fn recovers_a_datagram_split_across_two_chunks() {
    let stream = record(b"split across chunks");
    let (head, tail) = stream.split_at(7);

    let mut decoder = UdpRecordDecoder::new();
    decoder.push(head);
    assert!(decoder.next_record().is_none(), "an incomplete record must not be delivered");
    decoder.push(tail);

    assert_eq!(drain(&mut decoder), vec![b"split across chunks".to_vec()]);
}

#[test]
fn recovers_datagrams_from_a_stream_sliced_byte_by_byte() {
    let payloads: [&[u8]; 3] = [b"a", b"bb", b"ccc"];
    let mut stream = Vec::new();
    for payload in payloads {
        stream.extend_from_slice(&record(payload));
    }

    let mut decoder = UdpRecordDecoder::new();
    let mut decoded = Vec::new();
    for byte in &stream {
        decoder.push(std::slice::from_ref(byte));
        decoded.extend(drain(&mut decoder));
    }

    assert_eq!(decoded, payloads.iter().map(|p| p.to_vec()).collect::<Vec<_>>());
}

#[test]
fn skips_an_empty_record_without_stalling_the_stream() {
    // `len = 0` carries nothing. It is never emitted by the encoder, but a
    // peer that sends one must not wedge the decoder.
    let mut stream = vec![0x00, 0x00];
    stream.extend_from_slice(&record(b"payload"));

    let mut decoder = UdpRecordDecoder::new();
    decoder.push(&stream);

    assert_eq!(drain(&mut decoder), vec![b"payload".to_vec()]);
}

#[test]
fn buffers_at_most_one_incomplete_record() {
    // Bounded-resource guard: the length field is a `u16`, so an incomplete
    // record can never pin more than 64 KiB plus its own header.
    let mut decoder = UdpRecordDecoder::new();
    decoder.push(&[0xff, 0xff]);
    decoder.push(&vec![0u8; MAX_UDP_RECORD_PAYLOAD - 1]);

    assert!(decoder.next_record().is_none());
    assert!(decoder.buffered_len() <= MAX_UDP_RECORD_PAYLOAD + UDP_RECORD_HEADER_LEN);
}

proptest::proptest! {
    #[test]
    fn decoder_never_panics(chunks in proptest::collection::vec(proptest::prelude::any::<Vec<u8>>(), 0..8)) {
        let mut decoder = UdpRecordDecoder::new();
        for chunk in &chunks {
            decoder.push(chunk);
            while decoder.next_record().is_some() {}
        }
    }
}

#[test]
fn encode_record_round_trips_and_rejects_oversized() {
    let encoded = encode_record(b"hello").expect("small payload fits u16");
    assert_eq!(encoded.as_ref(), &[0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);

    let oversized = vec![0u8; MAX_UDP_RECORD_PAYLOAD + 1];
    assert_eq!(
        encode_record(&oversized),
        Err(UdpRecordError::PayloadTooLarge(MAX_UDP_RECORD_PAYLOAD + 1))
    );
}

#[test]
fn udp_record_stream_passthrough_when_disabled() {
    let mut stream = UdpRecordStream::new(false);
    assert!(!stream.is_enabled());
    stream.push_chunk(Bytes::from_static(b"chunk1"));
    stream.push_chunk(Bytes::from_static(b"chunk2"));
    assert_eq!(stream.pop_datagram(), Some(Bytes::from_static(b"chunk1")));
    assert_eq!(stream.pop_datagram(), Some(Bytes::from_static(b"chunk2")));
    assert_eq!(stream.pop_datagram(), None);
}

#[test]
fn udp_record_stream_reassembles_splits_and_coalesced_chunks() {
    let mut stream = UdpRecordStream::new(true);
    assert!(stream.is_enabled());

    let r1 = encode_record(b"first").unwrap();
    let r2 = encode_record(b"second-dgram").unwrap();
    let mut combined = Vec::new();
    combined.extend_from_slice(&r1);
    combined.extend_from_slice(&r2);
    let split_at = r1.len() + 3;

    stream.push_chunk(Bytes::copy_from_slice(&combined[..split_at]));
    assert_eq!(stream.pop_datagram(), Some(Bytes::from_static(b"first")));
    assert_eq!(stream.pop_datagram(), None);

    stream.push_chunk(Bytes::copy_from_slice(&combined[split_at..]));
    assert_eq!(stream.pop_datagram(), Some(Bytes::from_static(b"second-dgram")));
    assert_eq!(stream.pop_datagram(), None);
}

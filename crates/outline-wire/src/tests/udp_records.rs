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

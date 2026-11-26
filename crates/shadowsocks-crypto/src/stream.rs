//! Synchronous Shadowsocks AEAD stream chunk sealer and opener shared by the
//! client and the server.

use bytes::BytesMut;
use outline_wire::ss2022::SS2022_TCP_RESPONSE_TYPE;

use crate::aead::{AeadCipher, LEGACY_MAX_PAYLOAD_LEN, SHADOWSOCKS_TAG_LEN, StreamNonce};
use crate::error::{CryptoError, Result};

/// Output buffer abstraction for in-place AEAD chunk sealing (`Vec<u8>` and `BytesMut`).
pub trait SealBuf {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn reserve(&mut self, additional: usize);
    fn extend_from_slice(&mut self, src: &[u8]);
    fn slice_mut(&mut self, start: usize, end: usize) -> &mut [u8];
}

impl SealBuf for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn reserve(&mut self, additional: usize) {
        Vec::reserve(self, additional);
    }
    fn extend_from_slice(&mut self, src: &[u8]) {
        Vec::extend_from_slice(self, src);
    }
    fn slice_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
        &mut self[start..end]
    }
}

impl SealBuf for BytesMut {
    fn len(&self) -> usize {
        BytesMut::len(self)
    }
    fn reserve(&mut self, additional: usize) {
        BytesMut::reserve(self, additional);
    }
    fn extend_from_slice(&mut self, src: &[u8]) {
        BytesMut::extend_from_slice(self, src);
    }
    fn slice_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
        &mut self[start..end]
    }
}

fn seal_block<B: SealBuf>(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    plaintext: &[u8],
    out: &mut B,
) -> Result<()> {
    let n = nonce.next()?;
    let start = out.len();
    out.extend_from_slice(plaintext);
    let end = out.len();
    let tag = cipher.seal_in_place_separate_tag(&n, out.slice_mut(start, end))?;
    out.extend_from_slice(&tag);
    Ok(())
}

/// Seals a single `[pending_salt? || enc(len) || tag || enc(payload) || tag]` chunk into `out`.
pub fn seal_payload_chunk<B: SealBuf>(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    max_chunk_size: usize,
    pending_salt: Option<&[u8]>,
    payload: &[u8],
    out: &mut B,
) -> Result<()> {
    if payload.len() > max_chunk_size {
        return Err(CryptoError::InvalidChunkSize(payload.len()));
    }
    let salt_len = pending_salt.map_or(0, <[u8]>::len);
    out.reserve(salt_len + 2 + SHADOWSOCKS_TAG_LEN + payload.len() + SHADOWSOCKS_TAG_LEN);
    if let Some(salt) = pending_salt {
        out.extend_from_slice(salt);
    }
    let length = u16::try_from(payload.len())
        .map_err(|_| CryptoError::InvalidChunkSize(payload.len()))?
        .to_be_bytes();
    seal_block(cipher, nonce, &length, out)?;
    seal_block(cipher, nonce, payload, out)
}

/// Seals `plaintext` as legacy AEAD chunks (capped at `LEGACY_MAX_PAYLOAD_LEN`),
/// prepending `salt` before the first chunk when `*sent_salt` is `false`.
pub fn seal_legacy_chunks<B: SealBuf>(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    salt: &[u8],
    sent_salt: &mut bool,
    plaintext: &[u8],
    out: &mut B,
) -> Result<()> {
    let chunk_count = plaintext.len().div_ceil(LEGACY_MAX_PAYLOAD_LEN).max(1);
    out.reserve(
        usize::from(!*sent_salt) * salt.len()
            + plaintext.len()
            + chunk_count * (2 + 2 * SHADOWSOCKS_TAG_LEN),
    );
    for chunk in plaintext.chunks(LEGACY_MAX_PAYLOAD_LEN) {
        let prefix = if *sent_salt {
            None
        } else {
            *sent_salt = true;
            Some(salt)
        };
        seal_payload_chunk(cipher, nonce, LEGACY_MAX_PAYLOAD_LEN, prefix, chunk, out)?;
    }
    Ok(())
}

/// Seals the initial SS2022 TCP response frame (`salt || enc(resp_hdr) || enc(initial_payload)`).
pub fn seal_ss2022_response_first_frame<B: SealBuf>(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    salt: &[u8],
    request_salt: &[u8],
    now_secs: u64,
    initial_payload: &[u8],
    out: &mut B,
) -> Result<()> {
    let length = u16::try_from(initial_payload.len())
        .map_err(|_| CryptoError::InvalidChunkSize(initial_payload.len()))?
        .to_be_bytes();
    let header_pt_len = 1 + 8 + request_salt.len() + 2;
    out.reserve(
        salt.len()
            + header_pt_len
            + SHADOWSOCKS_TAG_LEN
            + initial_payload.len()
            + SHADOWSOCKS_TAG_LEN,
    );
    out.extend_from_slice(salt);
    let hdr_nonce = nonce.next()?;
    let hdr_start = out.len();
    out.extend_from_slice(&[SS2022_TCP_RESPONSE_TYPE]);
    out.extend_from_slice(&now_secs.to_be_bytes());
    out.extend_from_slice(request_salt);
    out.extend_from_slice(&length);
    let hdr_end = out.len();
    let hdr_tag =
        cipher.seal_in_place_separate_tag(&hdr_nonce, out.slice_mut(hdr_start, hdr_end))?;
    out.extend_from_slice(&hdr_tag);

    seal_block(cipher, nonce, initial_payload, out)
}

/// Opens and validates an encrypted 2-byte chunk length block (`2 + 16` bytes) in place.
pub fn open_length_block(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    max_chunk_size: usize,
    block: &mut [u8],
) -> Result<usize> {
    if block.len() != 2 + SHADOWSOCKS_TAG_LEN {
        return Err(CryptoError::InvalidLengthHeader);
    }
    let n = nonce.next()?;
    let pt = cipher
        .open_fixed_in_place(&n, block, 2)
        .map_err(|_| CryptoError::InvalidLengthHeader)?;
    let chunk_len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
    if chunk_len > max_chunk_size {
        return Err(CryptoError::InvalidChunkSize(chunk_len));
    }
    Ok(chunk_len)
}

/// Decrypts a stream payload block (`ciphertext || tag`) in place and returns the plaintext length.
pub fn open_payload_in_place(
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    buf: &mut [u8],
) -> Result<usize> {
    let n = nonce.next()?;
    cipher.decrypt_detached_in_place(&n, buf)
}

/// Incrementally drains at most one complete AEAD chunk from `buffer` into `output`.
/// Returns `Ok(false)` when more bytes are needed from the wire.
pub fn drain_chunk_from_bytes(
    buffer: &mut BytesMut,
    cipher: &AeadCipher,
    nonce: &mut StreamNonce,
    pending_chunk_len: &mut Option<usize>,
    max_chunk_size: usize,
    output: &mut Vec<u8>,
) -> Result<bool> {
    if pending_chunk_len.is_none() {
        if buffer.len() < 2 + SHADOWSOCKS_TAG_LEN {
            return Ok(false);
        }
        let mut len_block = buffer.split_to(2 + SHADOWSOCKS_TAG_LEN);
        *pending_chunk_len =
            Some(open_length_block(cipher, nonce, max_chunk_size, &mut len_block)?);
    }
    let chunk_len = pending_chunk_len.expect("set above");
    if buffer.len() < chunk_len + SHADOWSOCKS_TAG_LEN {
        return Ok(false);
    }
    let mut encrypted_payload = buffer.split_to(chunk_len + SHADOWSOCKS_TAG_LEN);
    let pt_len = open_payload_in_place(cipher, nonce, &mut encrypted_payload)?;
    output.extend_from_slice(&encrypted_payload[..pt_len]);
    *pending_chunk_len = None;
    Ok(true)
}

#[cfg(test)]
#[path = "tests/stream.rs"]
mod tests;

use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex, split};

use super::*;

#[tokio::test]
async fn copies_both_directions_and_closes() {
    // `carrier` is the pump's carrier side; `peer` stands in for the client.
    let (carrier, peer) = duplex(4096);
    // `mesh_a` is the pump's mesh side; `mesh_b` stands in for the home.
    let (mesh_a, mesh_b) = duplex(4096);
    let (mesh_recv, mesh_send) = split(mesh_a);

    let pump_task = tokio::spawn(pump(carrier, mesh_send, mesh_recv));

    let (mut peer_r, mut peer_w) = split(peer);
    let (mut home_r, mut home_w) = split(mesh_b);

    // Uplink: client → mesh.
    peer_w.write_all(b"hello-up").await.unwrap();
    let mut up = [0u8; 8];
    home_r.read_exact(&mut up).await.unwrap();
    assert_eq!(&up, b"hello-up");

    // Downlink: mesh → client.
    home_w.write_all(b"hello-dn").await.unwrap();
    let mut dn = [0u8; 8];
    peer_r.read_exact(&mut dn).await.unwrap();
    assert_eq!(&dn, b"hello-dn");

    // Close both writers → each direction hits EOF → pump completes.
    peer_w.shutdown().await.unwrap();
    home_w.shutdown().await.unwrap();
    pump_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn relays_a_large_payload_intact() {
    // A payload far larger than the duplex buffer forces many read/write
    // cycles; the bytes must arrive in order and complete (no coalescing bug).
    let (carrier, peer) = duplex(4096);
    let (mesh_a, mesh_b) = duplex(4096);
    let (mesh_recv, mesh_send) = split(mesh_a);
    let pump_task = tokio::spawn(pump(carrier, mesh_send, mesh_recv));

    let (mut peer_r, mut peer_w) = split(peer);
    let (mut home_r, mut home_w) = split(mesh_b);

    // This test exercises the uplink only; close the downlink so the pump's
    // downlink copy sees EOF and the pump can complete (it joins both
    // directions).
    home_w.shutdown().await.unwrap();

    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let writer = tokio::spawn(async move {
        peer_w.write_all(&payload).await.unwrap();
        peer_w.shutdown().await.unwrap();
    });

    let mut got = Vec::new();
    home_r.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, expected);

    // Drain the (empty) downlink to EOF so the carrier write side closes.
    let mut down = Vec::new();
    peer_r.read_to_end(&mut down).await.unwrap();
    assert!(down.is_empty());

    writer.await.unwrap();
    pump_task.await.unwrap().unwrap();
}

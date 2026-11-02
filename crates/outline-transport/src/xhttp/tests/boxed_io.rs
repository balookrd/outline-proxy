//! `BoxedIo` must forward vectored writes so h2 keeps a frame header and its
//! payload in one write (hence one TLS record).

use std::io::IoSlice;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::stream::BoxedIo;

#[tokio::test]
async fn plain_boxed_io_forwards_vectored_writes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let mut io = BoxedIo::Plain(client.unwrap());
    let mut server = server.unwrap().0;
    assert!(AsyncWrite::is_write_vectored(&io));

    let header = [1u8; 9];
    let payload = vec![7u8; 1572];
    let mut sent = 0;
    while sent < 9 + 1572 {
        let all = [IoSlice::new(&header), IoSlice::new(&payload)];
        let skip = sent.min(9);
        let first = [IoSlice::new(&header[skip..]), IoSlice::new(&payload[sent - skip..])];
        let bufs: &[IoSlice<'_>] = if sent == 0 { &all } else { &first };
        sent += io.write_vectored(bufs).await.unwrap();
    }
    io.shutdown().await.unwrap();
    let mut got = Vec::new();
    server.read_to_end(&mut got).await.unwrap();
    assert_eq!(got.len(), 9 + 1572);
    assert_eq!(&got[..9], &header);
    assert!(got[9..].iter().all(|b| *b == 7));
}

use std::net::{IpAddr, SocketAddr};
use std::{future::Future, time::Duration};

use clap::{App, Arg};

use tokio::io::Result;
use tokio::net::{TcpStream, UdpSocket};
use tokio::prelude::*;
use tokio::time;

use lru::LruCache;

use trust_china_dns::acl::AccessControl;
use trust_china_dns::socks5::*;
use trust_dns_proto::op::*;
use trust_dns_proto::rr::*;

pub async fn try_timeout<T, F>(fut: F, timeout: Option<Duration>) -> io::Result<T>
where
    F: Future<Output = Result<T>>,
{
    match timeout {
        Some(t) => time::timeout(t, fut).await?,
        None => fut.await,
    }
    .map_err(From::from)
}

async fn udp_lookup(qname: &Name, qtype: RecordType, server: SocketAddr) -> Result<Message> {
    let mut socket = UdpSocket::bind(("0.0.0.0", 0)).await?;

    let mut message = Message::new();
    let mut query = Query::new();

    query.set_query_type(qtype);
    query.set_name(qname.clone());

    message.set_id(6666);
    message.set_recursion_desired(true);
    message.add_query(query);

    let req_buffer = message.to_vec()?;
    socket.send_to(&req_buffer, server).await?;

    let mut res_buffer = vec![0; 512];
    socket.recv_from(&mut res_buffer).await?;

    Ok(Message::from_vec(&mut res_buffer)?)
}

async fn socks5_lookup(
    qname: &Name,
    qtype: RecordType,
    socks5: SocketAddr,
    ns: SocketAddr,
) -> Result<Message> {
    let mut stream = TcpStream::connect(socks5).await?;

    // 1. Handshake
    let hs = HandshakeRequest::new(vec![SOCKS5_AUTH_METHOD_NONE]);
    hs.write_to(&mut stream).await?;
    stream.flush().await?;

    let hsp = HandshakeResponse::read_from(&mut stream).await?;
    assert_eq!(hsp.chosen_method, SOCKS5_AUTH_METHOD_NONE);

    // 2. Send request header
    let addr = Address::SocketAddress(ns);
    let h = TcpRequestHeader::new(Command::TcpConnect, addr);
    h.write_to(&mut stream).await?;
    stream.flush().await?;

    let hp = TcpResponseHeader::read_from(&mut stream).await?;
    match hp.reply {
        Reply::Succeeded => (),
        r => {
            let err = io::Error::new(io::ErrorKind::Other, format!("{}", r));
            return Err(err);
        }
    }

    let mut message = Message::new();
    let mut query = Query::new();

    query.set_query_type(qtype);
    query.set_name(qname.clone());

    message.set_id(6666);
    message.set_recursion_desired(true);
    message.add_query(query);

    let req_buffer = message.to_vec()?;
    let size = req_buffer.len();
    let mut size_buffer: [u8; 2] = [((size >> 8) & 0xFF) as u8, ((size >> 0) & 0xFF) as u8];
    let mut send_buffer: [u8; 512 + 2] = [0; 512 + 2];
    send_buffer[..2].copy_from_slice(&size_buffer[..2]);
    send_buffer[2..size + 2].copy_from_slice(&req_buffer[0..size]);
    stream.write_all(&send_buffer[0..size + 2]).await?;

    stream.read_exact(&mut size_buffer[0..2]).await?;

    let mut res_buffer = vec![0; 512];
    let size = ((size_buffer[0] as usize) << 8) + (size_buffer[1] as usize);
    stream.read_exact(&mut res_buffer[0..size]).await?;

    Ok(Message::from_vec(&mut res_buffer)?)
}

async fn acl_lookup(
    acl: &AccessControl,
    local: SocketAddr,
    remote: SocketAddr,
    socks5: SocketAddr,
    qname: &Name,
    qtype: RecordType,
) -> Result<Message> {
    // Start querying name servers
    println!(
        "attempting lookup of {:?} {} with ns {} and {}",
        qtype, qname, local, remote
    );

    let ten_seconds = Some(Duration::new(5, 0));

    let local_response = try_timeout(udp_lookup(qname, qtype.clone(), local), ten_seconds).await?;
    let remote_response = try_timeout(
        socks5_lookup(qname, qtype.clone(), socks5, remote),
        ten_seconds,
    )
    .await?;

    let addr = Address::DomainNameAddress(qname.to_string(), 0);
    let qname_bypassed = acl.check_target_bypassed(&addr).await;

    let mut ip_bypassed = false;
    for rec in local_response.answers() {
        let bypassed = match rec.rdata() {
            RData::A(ref ip) => {
                let addr = Address::SocketAddress(SocketAddr::new(IpAddr::from(*ip), 0));
                acl.check_target_bypassed(&addr).await
            }
            RData::AAAA(ref ip) => {
                let addr = Address::SocketAddress(SocketAddr::new(IpAddr::from(*ip), 0));
                acl.check_target_bypassed(&addr).await
            }
            _ => false,
        };
        if bypassed {
            ip_bypassed = true;
        }
    }

    if qname_bypassed {
        println!("Pick local response");
        Ok(local_response.clone())
    } else if ip_bypassed {
        println!("Pick local response");
        Ok(local_response.clone())
    } else {
        println!("Pick remote response");
        Ok(remote_response.clone())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut reverse_resolver_cache = LruCache::new(8192);

    let matches = App::new("trust-china-dns")
        .version("0.1")
        .about("Yet another ChinaDNS in Rust")
        .author("Max Lv <max.c.lv@gmail.com>")
        .arg(
            Arg::with_name("local")
                .long("local")
                .value_name("LOCAL_DNS")
                .help("Sets a custom local DNS server")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("remote")
                .long("remote")
                .value_name("REMOTE_DNS")
                .help("Sets a custom remote DNS server")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("socks5")
                .long("socks5")
                .value_name("SOCKS5")
                .help("Sets a custom SOCKS5 proxy")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("listen")
                .long("listen")
                .value_name("LISTEN")
                .help("Sets a custom listen address")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("acl")
                .long("acl")
                .value_name("ACL")
                .help("Sets a custom ACL path")
                .takes_value(true),
        )
        .get_matches();

    let local = matches.value_of("local").unwrap_or("114.114.114.114:53");
    println!("Local DNS server: {}", local);

    let remote = matches.value_of("remote").unwrap_or("8.8.8.8:53");
    println!("Remote DNS server: {}", remote);

    let socks5 = matches.value_of("socks5").unwrap_or("127.0.0.1:1080");
    println!("SOCKS5 server: {}", socks5);

    let listen = matches.value_of("listen").unwrap_or("127.0.0.1:2053");
    println!("Listen on {}", listen);

    let acl = matches.value_of("acl").unwrap_or("bypass-china.acl");
    println!("Load ACL file: {}", acl);

    let local_addr: SocketAddr = local.parse().expect("Unable to parse local address");
    let remote_addr: SocketAddr = remote.parse().expect("Unable to parse remote address");
    let socks5_addr: SocketAddr = socks5.parse().expect("Unable to parse socks5 address");
    let listen_addr: SocketAddr = listen.parse().expect("Unable to parse listen address");

    let mut socket = UdpSocket::bind(listen_addr).await?;
    let acl = AccessControl::load_from_file(acl).expect("Failed to load ACL file");

    loop {
        let mut req_buffer: [u8; 512] = [0; 512];
        let (_, src) = match socket.recv_from(&mut req_buffer).await {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to read from UDP socket: {:?}", e);
                continue;
            }
        };

        let request = match Message::from_vec(&mut req_buffer) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to parse UDP query message: {:?}", e);
                continue;
            }
        };

        let mut message = Message::new();
        message.set_id(request.id());
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        message.set_message_type(header::MessageType::Response);

        if request.queries().is_empty() {
            message.set_response_code(response_code::ResponseCode::FormErr);
        } else {
            let question = &request.queries()[0];
            println!("Received query: {:?}", question);

            if let Ok(result) = acl_lookup(
                &acl,
                local_addr,
                remote_addr,
                socks5_addr,
                question.name(),
                question.query_type(),
            )
            .await
            {
                message.add_query(question.clone());
                message.set_response_code(result.response_code());

                for rec in result.answers() {
                    println!("Answer: {:?}", rec);
                    match rec.rdata() {
                        RData::A(ref ip) => reverse_resolver_cache
                            .put(IpAddr::from(*ip), question.name().to_ascii()),
                        RData::AAAA(ref ip) => reverse_resolver_cache
                            .put(IpAddr::from(*ip), question.name().to_ascii()),
                        _ => None,
                    };
                    message.add_answer(rec.clone());
                }
                for rec in result.additionals() {
                    println!("Additionals: {:?}", rec);
                    message.add_additional(rec.clone());
                }
            } else {
                message.set_response_code(ResponseCode::ServFail);
            }
        }

        let res_buffer = message.to_vec()?;
        match socket.send_to(&res_buffer, src).await {
            Ok(_) => {}
            Err(e) => {
                println!("Failed to send response: {:?}", e);
                continue;
            }
        };
    }
}

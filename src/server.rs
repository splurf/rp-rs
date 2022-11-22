use {
    crate::{acceptor::TlsAcceptor, config::Listener},
    hyper::{
        client::conn::handshake,
        server::conn::AddrIncoming,
        service::{make_service_fn, service_fn},
        Body, Request, Response, Server,
    },
    std::{collections::HashMap, net::SocketAddr, sync::Arc},
    tokio::{
        net::TcpStream,
        task::{spawn, JoinHandle},
    },
    tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig},
};

type Error = Box<(dyn std::error::Error + Send + Sync)>;
type Result<T> = std::result::Result<T, Error>;

async fn proxy_pass(
    req: Request<Body>,
    paths: HashMap<String, SocketAddr>,
) -> Result<Response<Body>> {
    let to = paths
        .get(&req.uri().to_string())
        .ok_or("mapping does not exist")?;
    let stream = TcpStream::connect(to).await?;
    let (mut reciprent, connection) = handshake(stream).await?;
    spawn(async move { connection.await });
    reciprent.send_request(req).await.map_err(Into::into)
}

async fn http_server(addr: SocketAddr, paths: HashMap<String, SocketAddr>) -> Result<()> {
    let incoming = AddrIncoming::bind(&addr)?;
    let service = make_service_fn(|_| {
        let paths = paths.clone();
        async move { Ok::<_, Error>(service_fn(move |req| proxy_pass(req, paths.clone()))) }
    });
    let server = Server::builder(incoming).serve(service);
    Ok(server.await?)
}

async fn https_server(
    addr: SocketAddr,
    paths: HashMap<String, SocketAddr>,
    certs: Vec<Certificate>,
    key: PrivateKey,
) -> Result<()> {
    let tls_cfg = {
        let mut cfg = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(cfg)
    };
    let incoming = AddrIncoming::bind(&addr)?;

    let service = make_service_fn(|_| {
        let paths = paths.clone();
        async move { Ok::<_, Error>(service_fn(move |req| proxy_pass(req, paths.clone()))) }
    });

    let server = Server::builder(TlsAcceptor::new(tls_cfg, incoming)).serve(service);
    Ok(server.await?)
}

pub fn init_server(cfg: Listener) -> JoinHandle<Result<()>> {
    spawn(async move {
        if let Some(ssl) = cfg.ssl() {
            https_server(
                cfg.addr(),
                cfg.paths(),
                ssl.certificates(),
                ssl.certificate_key(),
            )
            .await
        } else {
            http_server(cfg.addr(), cfg.paths()).await
        }
    })
}

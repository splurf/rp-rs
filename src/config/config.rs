use {
    super::{Error, Result},
    std::{
        collections::HashMap,
        fs::File,
        io::{BufRead, BufReader, Read},
        net::{SocketAddr, ToSocketAddrs},
    },
    tokio_rustls::rustls::{Certificate, PrivateKey},
};

fn load_file<T>(
    filename: &str,
    pemfile_fn: fn(&mut dyn BufRead) -> std::io::Result<Vec<Vec<u8>>>,
    handler: fn(Vec<Vec<u8>>) -> Result<T>,
) -> Result<T> {
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);
    let files = pemfile_fn(&mut reader)?;
    handler(files)
}

enum Directive {
    Port,
    Server,
    Paths,
    Ssl,
}

impl Directive {
    fn get(s: &str) -> Result<Self> {
        match s {
            "port" => Ok(Self::Port),
            "server" => Ok(Self::Server),
            "paths" => Ok(Self::Paths),
            "ssl" => Ok(Self::Ssl),
            _ => Err("invalid directive".into()),
        }
    }

    const fn is_singular(&self) -> bool {
        matches!(self, Self::Server)
    }
}

struct SslCfgBuilder {
    certificates: Option<Vec<Certificate>>,
    certificates_key: Option<PrivateKey>,
}

impl SslCfgBuilder {
    const fn new() -> Self {
        Self {
            certificates: None,
            certificates_key: None,
        }
    }

    fn insert(&mut self, directive: &str, path: &str) -> Result<()> {
        match directive.trim() {
            "certificate" => {
                if let None = self.certificates {
                    Ok(self.certificates =
                        Some(load_file(path.trim(), rustls_pemfile::certs, |files| {
                            Ok(files.into_iter().map(Certificate).collect())
                        })?))
                } else {
                    Err("existing ssl directive with multiple values".into())
                }
            }
            "certificate_key" => {
                if let None = self.certificates_key {
                    Ok(self.certificates_key = Some(load_file(
                        path.trim(),
                        rustls_pemfile::rsa_private_keys,
                        |files| {
                            Ok(PrivateKey(
                                files
                                    .first()
                                    .ok_or("expected a single private key")?
                                    .clone(),
                            ))
                        },
                    )?))
                } else {
                    Err("existing ssl directive with multiple values".into())
                }
            }
            _ => Err("invalid ssl directive".into()),
        }
    }

    fn build(self) -> Result<SslCfg> {
        Ok(SslCfg {
            certificates: self.certificates.ok_or("missing certificates")?,
            certificates_key: self.certificates_key.ok_or("missing certificates key")?,
        })
    }
}

pub struct SslCfg {
    certificates: Vec<Certificate>,
    certificates_key: PrivateKey,
}

impl SslCfg {
    pub fn certificates(&self) -> Vec<Certificate> {
        self.certificates.clone()
    }

    pub fn certificate_key(&self) -> PrivateKey {
        self.certificates_key.clone()
    }
}

struct ListenerBuilder {
    port: Option<u16>,
    server: Option<String>,
    paths: HashMap<String, SocketAddr>,
    ssl: SslCfgBuilder,
}

impl ListenerBuilder {
    fn new() -> Self {
        Self {
            port: None,
            server: None,
            paths: HashMap::default(),
            ssl: SslCfgBuilder::new(),
        }
    }

    fn insert(&mut self, directive: &Directive, line: &str) -> Result<()> {
        let line = line.trim().to_string();

        match directive {
            Directive::Port => self.port = Some(line.parse()?),
            Directive::Server => self.server = Some(line),
            Directive::Paths => {
                let (path, addr) = line
                    .trim()
                    .split_once("=>")
                    .ok_or("invalid paths argument")?;
                let (path, addr) = (path.trim().to_string(), addr.trim().to_string());

                if path.split_whitespace().count() == 1 && addr.split_whitespace().count() == 1 {
                    if self
                        .paths
                        .insert(
                            path,
                            addr.to_socket_addrs()?
                                .next()
                                .ok_or::<Error>("invalid address".into())?,
                        )
                        .is_some()
                    {
                        return Err("existing directive with multiple values".into());
                    }
                } else {
                    return Err("invalid arguments".into());
                }
            }
            Directive::Ssl => {
                if let Some((directive, path)) = line.split_once(":") {
                    self.ssl.insert(directive.trim(), path.trim())?
                } else {
                    return Err("invalid ssl argument(s)".into());
                }
            }
        }
        Ok(())
    }

    fn build(self) -> Result<Listener> {
        let port = self.port.ok_or("missing port directive")?;
        let server = self.server.ok_or("missing server directive")?;
        let addr = format!("{}:{}", server, port)
            .to_socket_addrs()?
            .next()
            .ok_or("invalid address")?;
        let paths = (!self.paths.is_empty())
            .then(|| self.paths)
            .ok_or("missing paths directive")?;
        let ssl = self.ssl.build().ok();
        Ok(Listener { addr, paths, ssl })
    }
}

pub struct Listener {
    addr: SocketAddr,
    paths: HashMap<String, SocketAddr>,
    ssl: Option<SslCfg>,
}

impl Listener {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn paths(&self) -> HashMap<String, SocketAddr> {
        self.paths.clone()
    }

    pub fn ssl(&self) -> Option<&SslCfg> {
        self.ssl.as_ref()
    }
}

pub struct ListenerConfig;

impl ListenerConfig {
    pub fn new() -> Result<impl Iterator<Item = Listener>> {
        let mut file = File::open("config.txt")?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)?;
        Self::parse(buf)
    }

    fn measure<'a>(buf: &'a str) -> Result<impl Iterator<Item = (usize, &'a str)>> {
        let content = buf.trim().lines().filter_map(|l| {
            let l = l.trim_end();
            (!l.is_empty()).then_some({
                if let Some(i) = l.find("//") {
                    &l[..i]
                } else {
                    l
                }
            })
        });
        //  SAFE
        let indents = content
            .clone()
            .map(|s| s.find(|c: char| !c.is_whitespace()).unwrap());

        let min = indents
            .clone()
            .filter(|i| i.clone() > 0)
            .min()
            .ok_or::<Error>("missing directives".into())?;

        indents
            .clone()
            .all(|i| i % min == 0)
            .then_some(
                indents
                    .zip(content)
                    .map(move |(depth, line)| (depth / min, &line[depth..])),
            )
            .ok_or("inconsistent indentation".into())
    }

    fn parse(buf: String) -> Result<impl Iterator<Item = Listener>> {
        let mut builder = ListenerBuilder::new();

        let measured = Self::measure(&buf)?;

        let mut listeners = Vec::new();
        let mut current = Directive::Port;

        let mut finish = |builder: ListenerBuilder| -> Result<ListenerBuilder> {
            listeners.push(builder.build()?);
            Ok(ListenerBuilder::new())
        };

        for (depth, line) in measured {
            match depth {
                0 => {
                    if builder.port.is_some() {
                        builder = finish(builder)?;
                    }
                    builder.insert(&Directive::Port, line)?
                }
                1 => {
                    let (raw, attr) = line.split_once(':').ok_or("invalid formatting")?;
                    let directive = Directive::get(raw.trim())?;

                    if directive.is_singular() {
                        builder.insert(&directive, attr)?
                    }
                    current = directive
                }
                2 => builder.insert(&current, line)?,
                _ => return Err("invalid depth".into()),
            }
        }
        finish(builder)?;
        Ok(listeners.into_iter())
    }
}

mod acceptor;
mod config;
mod server;
mod stream;

use {config::ListenerConfig, server::init_server};

#[tokio::main]
async fn main() {
    match ListenerConfig::new() {
        Ok(cfgs) => {
            let mut listeners = Vec::new();

            for cfg in cfgs {
                println!("Started : {}", cfg.addr());
                listeners.push((cfg.addr(), init_server(cfg)))
            }

            for (addr, handle) in listeners {
                match handle.await {
                    Ok(result) => {
                        if let Err(e) = result {
                            println!("{}", e)
                        }
                    }
                    Err(e) => println!("{}", e),
                }
                println!("Stopped : {}", addr)
            }
        }
        Err(e) => println!("{:?}", e),
    }
}

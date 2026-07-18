use std::io::Write;

use client::{AppEvent, Client};
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let keys = if client::identity_exists() {
        let password = read_password("password: ")?;
        client::unlock(&password)?
    } else {
        println!("no identity found — creating a new one");
        let password = read_password("new password: ")?;
        let confirm = read_password("confirm password: ")?;
        if password != confirm {
            return Err(anyhow::anyhow!("passwords do not match"));
        }
        client::create_identity(&password)?
    };

    let server = match client::resolve_server() {
        Some(s) => s,
        None => {
            let s = prompt_line("server address (host:port): ")?;
            client::save_server(&s)?;
            s
        }
    };

    let (cli, mut events) = Client::start(keys, server.clone()).await?;
    println!(
        "identity {} — connecting to {}",
        cli.my_fingerprint(),
        server
    );

    let ev_cli = cli.clone();
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            match ev {
                AppEvent::Connected { observed_address } => {
                    println!("[connected] observed as {observed_address}");
                }
                AppEvent::PeerOnline { .. } | AppEvent::PeerOffline { .. } => {}
                AppEvent::MessageArrived { peer, .. } => {
                    if let Ok(lines) = ev_cli.history(&peer) {
                        if let Some(last) = lines.last() {
                            let who = if last.from_me {
                                "you".into()
                            } else {
                                client::fingerprint(&peer)
                            };
                            println!("[msg] {who}: {}", last.text);
                        }
                    }
                }
                AppEvent::HolePunchDenied { peer, reason } => {
                    println!("[denied] {}: {reason}", client::fingerprint(&peer));
                }
                AppEvent::SessionUp { peer, direct } => {
                    println!(
                        "[session] {} connected ({})",
                        client::fingerprint(&peer),
                        if direct { "direct" } else { "relay" }
                    );
                }
                AppEvent::SessionDown { peer } => {
                    println!("[session] {} ended", client::fingerprint(&peer));
                }
                AppEvent::ConnectRetrying {
                    peer,
                    attempt,
                    delay_secs,
                } => {
                    println!(
                        "[retry] {} attempt {attempt} (next in {delay_secs}s)",
                        client::fingerprint(&peer)
                    );
                }
                AppEvent::ConnectGaveUp { peer } => {
                    println!(
                        "[gave up] {} — will retry when it comes online",
                        client::fingerprint(&peer)
                    );
                }
                AppEvent::Disconnected => println!("[disconnected]"),
                AppEvent::Error(e) => println!("[error] {e}"),
            }
        }
    });

    let sig_cli = cli.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("\nshutting down…");
            sig_cli.shutdown();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            std::process::exit(0);
        }
    });

    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    print_prompt();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        let mut parts = line.splitn(3, ' ');
        match parts.next() {
            Some("peers") => {
                for c in cli.contacts() {
                    let dot = if c.online { "🟢" } else { "⚪" };
                    let addr = c.address.as_deref().unwrap_or("");
                    println!("  {dot} {} ({}) {}", c.label(), c.fingerprint, addr);
                }
            }
            Some("alias") => match (parts.next(), parts.next()) {
                (Some(p), Some(name)) => match cli.resolve_peer(p) {
                    Some(id) => match cli.set_alias(&id, name) {
                        Ok(()) => println!("alias set: {name}"),
                        Err(e) => println!("alias failed: {e}"),
                    },
                    None => println!("no such peer"),
                },
                _ => println!("usage: alias <peer> <name>"),
            },
            Some("mykeys") => {
                let (x, v) = cli.my_keys_hex();
                println!("share these two keys with your peer so they can add you:");
                println!("  x25519:   {x}");
                println!("  verifying:{v}");
            }
            Some("server") => match parts.next() {
                None => {
                    let cur = client::resolve_server().unwrap_or_else(|| "(unset)".to_string());
                    println!("current server: {cur}");
                }
                Some(addr) => {
                    cli.set_server(addr.to_string());
                    println!("switching to {addr} …");
                }
            },
            Some("add") => match (parts.next(), parts.next()) {
                (Some(x), Some(v)) => match (parse32(x), parse32(v)) {
                    (Some(x), Some(v)) => match cli.add_peer(x, v) {
                        Ok(id) => println!("added {}", client::fingerprint(&id)),
                        Err(e) => println!("add failed: {e}"),
                    },
                    _ => println!("both keys must be 32-byte hex"),
                },
                _ => println!("usage: add <x25519_hex> <verif_hex>"),
            },
            Some("connect") => match parts.next() {
                Some(fp) => match find_peer(&cli, fp) {
                    Some(id) => cli.connect_peer(id),
                    None => println!("no such peer"),
                },
                None => println!("usage: connect <fingerprint>"),
            },
            Some("msg") => match (parts.next(), parts.next()) {
                (Some(fp), Some(text)) => match find_peer(&cli, fp) {
                    Some(id) => cli.send_message(id, text.to_string()),
                    None => println!("no such peer"),
                },
                _ => println!("usage: msg <fingerprint> <text>"),
            },
            Some("purge") => match parts.next() {
                Some(fp) => match find_peer(&cli, fp) {
                    Some(id) => {
                        cli.purge(id);
                        println!("purged conversation with {}", client::fingerprint(&id));
                    }
                    None => println!("no such peer"),
                },
                None => println!("usage: purge <peer>"),
            },
            Some("remove") => match parts.next() {
                Some(fp) => match find_peer(&cli, fp) {
                    Some(id) => {
                        cli.remove_peer(id);
                        println!("removed peer {}", client::fingerprint(&id));
                    }
                    None => println!("no such peer"),
                },
                None => println!("usage: remove <peer>"),
            },
            Some("history") => match parts.next() {
                Some(fp) => match find_peer(&cli, fp) {
                    Some(id) => match cli.history(&id) {
                        Ok(lines) => {
                            for l in lines {
                                println!(
                                    "  {}: {}",
                                    if l.from_me { "you" } else { "peer" },
                                    l.text
                                );
                            }
                        }
                        Err(e) => println!("history failed: {e}"),
                    },
                    None => println!("no such peer"),
                },
                None => println!("usage: history <fingerprint>"),
            },
            Some("help") | Some("?") => print_help(),
            Some("quit") | Some("exit") => {
                cli.shutdown();
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                break;
            }
            Some("") | None => {}
            Some(other) => println!("unknown command: {other} (try `help`)"),
        }
        print_prompt();
    }
    Ok(())
}

fn print_prompt() {
    print!("> ");
    let _ = std::io::stdout().flush();
}

fn read_password(prompt: &str) -> anyhow::Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

fn parse32(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

fn find_peer(cli: &Client, query: &str) -> Option<[u8; 32]> {
    cli.resolve_peer(query)
}
fn print_help() {
    println!("Available commands:");
    println!("  peers                           list known contacts + online status");
    println!("  mykeys                          print your two public keys to share with peers");
    println!("  server [host:port]              show, or change + persist, the relay address");
    println!("  add <x25519_hex> <verif_hex>    trust a peer by their two 32-byte keys");
    println!("  alias <peer> <name>             set a local name for a peer");
    println!("  connect <peer>                  ask the relay to broker a P2P hole-punch");
    println!("  msg <peer> <text>               send a message (P2P if live, else offline)");
    println!("  history <peer>                  print the stored conversation");
    println!("  purge <peer>                    delete the conversation (both sides)");
    println!("  remove <peer>                   remove the peer entirely (keys + chat + alias)");
    println!("  (<peer> = alias, alias prefix, or fingerprint prefix)");
    println!("  help, ?                         show this help message");
    println!("  quit, exit                      exit the application");
}

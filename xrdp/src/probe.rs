//! Background reachability checks for each connection's RDP (or gateway) port.

use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui;
use uuid::Uuid;

const INTERVAL: Duration = Duration::from_secs(30);
const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub id: Uuid,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Reach {
    Up(Duration),
    Down(String),
}

pub struct Prober {
    targets: Sender<Vec<Target>>,
    last_sent: Vec<Target>,
    results: Arc<Mutex<HashMap<Uuid, (Target, Reach)>>>,
}

impl Prober {
    pub fn new(ctx: egui::Context) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<Target>>();
        let results: Arc<Mutex<HashMap<Uuid, (Target, Reach)>>> = Arc::default();
        let shared = results.clone();
        thread::spawn(move || {
            let mut targets = Vec::new();
            loop {
                match rx.recv_timeout(INTERVAL) {
                    Ok(new) => {
                        targets = new;
                        shared
                            .lock()
                            .unwrap()
                            .retain(|_, (t, _)| targets.contains(t));
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
                // Probe in parallel so one slow host doesn't delay the rest.
                let handles: Vec<_> = targets
                    .iter()
                    .cloned()
                    .map(|t| thread::spawn(move || (check(&t.host, t.port), t)))
                    .collect();
                for h in handles {
                    if let Ok((reach, t)) = h.join() {
                        shared.lock().unwrap().insert(t.id, (t, reach));
                    }
                }
                ctx.request_repaint();
            }
        });
        Self {
            targets: tx,
            last_sent: Vec::new(),
            results,
        }
    }

    /// Sets the hosts to watch; changed targets are checked immediately.
    pub fn set_targets(&mut self, targets: Vec<Target>) {
        if targets != self.last_sent {
            self.last_sent = targets.clone();
            let _ = self.targets.send(targets);
        }
    }

    /// The latest result for a connection, unless its target has changed since.
    pub fn get(&self, id: Uuid) -> Option<Reach> {
        let results = self.results.lock().unwrap();
        let (target, reach) = results.get(&id)?;
        self.last_sent.contains(target).then(|| reach.clone())
    }
}

fn check(host: &str, port: u16) -> Reach {
    let addrs = match (host, port).to_socket_addrs() {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(_) => return Reach::Down("host name not found".into()),
    };
    let mut last_err = String::from("no addresses");
    for addr in addrs {
        let start = Instant::now();
        match TcpStream::connect_timeout(&addr, TIMEOUT) {
            Ok(_) => return Reach::Up(start.elapsed()),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => last_err = "no response".into(),
            Err(e) => last_err = e.to_string(),
        }
    }
    Reach::Down(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn detects_open_and_closed_ports() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(matches!(check("127.0.0.1", port), Reach::Up(_)));
        drop(listener);
        assert!(matches!(check("127.0.0.1", port), Reach::Down(_)));
        assert!(matches!(check("nonexistent.invalid", 3389), Reach::Down(_)));
    }
}

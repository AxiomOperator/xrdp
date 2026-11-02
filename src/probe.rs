//! Background reachability checks for each connection's RDP (or gateway) port.

use std::collections::{HashMap, HashSet};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::bus::Bus;
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
    pub fn new(bus: Bus) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<Target>>();
        let results: Arc<Mutex<HashMap<Uuid, (Target, Reach)>>> = Arc::default();
        let shared = results.clone();
        thread::spawn(move || {
            let targets: Arc<Mutex<Vec<Target>>> = Arc::default();
            let in_flight: Arc<Mutex<HashSet<Target>>> = Arc::default();
            loop {
                match rx.recv_timeout(INTERVAL) {
                    Ok(new) => {
                        shared.lock().unwrap().retain(|_, (t, _)| new.contains(t));
                        *targets.lock().unwrap() = new;
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
                // Probe in parallel and report each host as soon as it answers, so one
                // slow host doesn't delay the rest. A host still being checked from last
                // time (a hanging name lookup, say) is skipped rather than piling up.
                let current = targets.lock().unwrap().clone();
                for t in current {
                    if !in_flight.lock().unwrap().insert(t.clone()) {
                        continue;
                    }
                    let (targets, in_flight, shared, bus) = (
                        targets.clone(),
                        in_flight.clone(),
                        shared.clone(),
                        bus.clone(),
                    );
                    thread::spawn(move || {
                        let reach = check(&t.host, t.port);
                        // Results for hosts that were edited meanwhile are stale.
                        if targets.lock().unwrap().contains(&t) {
                            shared.lock().unwrap().insert(t.id, (t.clone(), reach));
                            bus.wake();
                        }
                        in_flight.lock().unwrap().remove(&t);
                    });
                }
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
    let lookup = {
        // getaddrinfo reads the environment; see `ENV_LOCK`.
        let _env = crate::ENV_LOCK
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        (host, port).to_socket_addrs()
    };
    let addrs = match lookup {
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
        // Not the freed port: a parallel test may grab it. Port 1 needs root to listen on.
        assert!(matches!(check("127.0.0.1", 1), Reach::Down(_)));
        assert!(matches!(check("nonexistent.invalid", 3389), Reach::Down(_)));
    }
}

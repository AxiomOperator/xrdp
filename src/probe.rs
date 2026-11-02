//! Background reachability checks for each connection's RDP (or gateway) port.

use std::collections::{HashMap, HashSet};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::bus::Bus;
use uuid::Uuid;

const INTERVAL: Duration = Duration::from_secs(30);
const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub id: Uuid,
    pub host: String,
    pub port: u16,
}

/// What actually gets checked: connections sharing a host or gateway share one check.
type Endpoint = (String, u16);

#[derive(Debug, Clone, PartialEq)]
pub enum Reach {
    Up(Duration),
    Down(String),
}

pub struct Prober {
    endpoints: Sender<Vec<Endpoint>>,
    paused: Arc<AtomicBool>,
    last_sent: Vec<Target>,
    by_id: HashMap<Uuid, Endpoint>,
    results: Arc<Mutex<HashMap<Endpoint, Reach>>>,
}

impl Prober {
    pub fn new(bus: Bus) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<Endpoint>>();
        let results: Arc<Mutex<HashMap<Endpoint, Reach>>> = Arc::default();
        let paused = Arc::new(AtomicBool::new(false));
        let (shared, worker_paused) = (results.clone(), paused.clone());
        thread::spawn(move || {
            let targets: Arc<Mutex<Vec<Endpoint>>> = Arc::default();
            let in_flight: Arc<Mutex<HashSet<Endpoint>>> = Arc::default();
            loop {
                match rx.recv_timeout(INTERVAL) {
                    Ok(new) => {
                        shared.lock().unwrap().retain(|e, _| new.contains(e));
                        *targets.lock().unwrap() = new;
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
                if worker_paused.load(Ordering::Relaxed) {
                    continue;
                }
                // Probe in parallel and report each host as soon as it answers, so one
                // slow host doesn't delay the rest. A host still being checked from last
                // time (a hanging name lookup, say) is skipped rather than piling up.
                let current = targets.lock().unwrap().clone();
                for e in current {
                    if !in_flight.lock().unwrap().insert(e.clone()) {
                        continue;
                    }
                    let (targets, in_flight, shared, bus) = (
                        targets.clone(),
                        in_flight.clone(),
                        shared.clone(),
                        bus.clone(),
                    );
                    thread::spawn(move || {
                        let reach = check(&e.0, e.1);
                        // Results for hosts that were edited meanwhile are stale.
                        if targets.lock().unwrap().contains(&e) {
                            shared.lock().unwrap().insert(e.clone(), reach);
                            bus.wake();
                        }
                        in_flight.lock().unwrap().remove(&e);
                    });
                }
            }
        });
        Self {
            endpoints: tx,
            paused,
            last_sent: Vec::new(),
            by_id: HashMap::new(),
            results,
        }
    }

    /// Sets the hosts to watch; changed targets are checked immediately.
    pub fn set_targets(&mut self, targets: Vec<Target>) {
        if targets != self.last_sent {
            self.by_id = targets
                .iter()
                .map(|t| (t.id, (t.host.clone(), t.port)))
                .collect();
            self.last_sent = targets;
            self.send_endpoints();
        }
    }

    /// Stops checking while nothing shows the results (the window is closed). Resuming
    /// checks right away, so the status dots are current when the window opens.
    pub fn set_paused(&self, paused: bool) {
        let was_paused = self.paused.swap(paused, Ordering::Relaxed);
        if was_paused && !paused {
            self.send_endpoints();
        }
    }

    fn send_endpoints(&self) {
        let unique: HashSet<&Endpoint> = self.by_id.values().collect();
        let _ = self.endpoints.send(unique.into_iter().cloned().collect());
    }

    /// The latest result for a connection, unless its target has changed since.
    pub fn get(&self, id: Uuid) -> Option<Reach> {
        let endpoint = self.by_id.get(&id)?;
        self.results.lock().unwrap().get(endpoint).cloned()
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

    /// Counts connections to `listener` until `want` of them were seen or time runs out,
    /// then for a moment longer to catch any extras.
    fn accepted(listener: &TcpListener) -> usize {
        listener.set_nonblocking(true).unwrap();
        let mut count = 0;
        let deadline = Instant::now() + Duration::from_millis(400);
        while Instant::now() < deadline {
            if listener.accept().is_ok() {
                count += 1;
            }
            thread::sleep(Duration::from_millis(10));
        }
        count
    }

    #[test]
    fn shared_endpoints_are_checked_once_and_pausing_stops_checks() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = |id| Target {
            id,
            host: "127.0.0.1".into(),
            port,
        };
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut prober = Prober::new(Bus::default());
        prober.set_targets(vec![target(a), target(b)]);
        assert_eq!(accepted(&listener), 1, "two connections, one check");
        assert!(matches!(prober.get(a), Some(Reach::Up(_))));
        assert_eq!(prober.get(a), prober.get(b));

        // While paused a change of target isn't checked; resuming checks at once.
        prober.set_paused(true);
        prober.set_targets(vec![target(a)]);
        assert_eq!(accepted(&listener), 0, "paused");
        prober.set_paused(false);
        assert_eq!(accepted(&listener), 1, "resumed");
    }
}

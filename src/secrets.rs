//! Password storage in the desktop keyring (Secret Service: KWallet, GNOME Keyring, ...).

use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};
use keyring::{Entry, Error};
use uuid::Uuid;

const SERVICE: &str = "xrdp-gui";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Rdp(Uuid),
    Gateway(Uuid),
    GroupGateway(String),
    GroupRdp(String),
}

impl Key {
    fn account(&self) -> String {
        match self {
            Key::Rdp(id) => format!("{id}"),
            Key::Gateway(id) => format!("{id}:gateway"),
            Key::GroupGateway(name) => format!("group:{name}:gateway"),
            Key::GroupRdp(name) => format!("group:{name}"),
        }
    }

    fn entry(&self) -> Result<Entry> {
        Entry::new(SERVICE, &self.account()).context("keyring unavailable")
    }
}

pub fn get(key: &Key) -> Result<Option<String>> {
    match key.entry()?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("reading password from keyring"),
    }
}

pub fn set(key: &Key, password: &str) -> Result<()> {
    key.entry()?
        .set_password(password)
        .context("saving password to keyring")
}

pub fn delete(key: &Key) -> Result<()> {
    match key.entry()?.delete_credential() {
        Ok(()) | Err(Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("deleting password from keyring"),
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// Runs keyring work on a background thread, one job at a time in the order given, so a
/// lookup sees every change asked for before it. The keyring may have to be unlocked
/// first, which waits for the user; the window stays responsive meanwhile.
pub struct Queue {
    jobs: Option<Sender<Job>>,
    thread: Option<JoinHandle<()>>,
}

impl Queue {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<Job>();
        let thread = thread::spawn(move || {
            for job in rx {
                job();
            }
        });
        Self {
            jobs: Some(tx),
            thread: Some(thread),
        }
    }

    pub fn run(&self, job: impl FnOnce() + Send + 'static) {
        if let Some(jobs) = &self.jobs {
            let _ = jobs.send(Box::new(job));
        }
    }
}

impl Drop for Queue {
    /// Finishes the queued work, so passwords saved just before quitting aren't lost.
    fn drop(&mut self) {
        drop(self.jobs.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn queue_runs_jobs_in_order_and_finishes_on_drop() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let queue = Queue::new();
        for i in 0..5 {
            let seen = seen.clone();
            queue.run(move || {
                thread::sleep(std::time::Duration::from_millis(5));
                seen.lock().unwrap().push(i);
            });
        }
        drop(queue);
        assert_eq!(*seen.lock().unwrap(), [0, 1, 2, 3, 4]);
    }
}

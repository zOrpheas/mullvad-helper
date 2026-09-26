// Worker: serial queue on ONE thread with its own tokio runtime.
mod base;
mod connect;
mod maint;
mod refresh;
use crate::state::{Backends, Job, Snapshot, UiMsg};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

#[derive(Clone)]
pub struct WorkerHandle {
    queue: Arc<Queue>,
}

struct Queue {
    jobs: Mutex<VecDeque<Job>>,
    cvar: Condvar,
}

pub fn spawn(be: Backends, tx: async_channel::Sender<UiMsg>) -> WorkerHandle {
    let queue = Arc::new(Queue {
        jobs: Mutex::new(VecDeque::new()),
        cvar: Condvar::new(),
    });
    let q2 = queue.clone();
    std::thread::Builder::new()
        .name("mullvad-helper-worker".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("worker runtime");
            rt.block_on(worker_loop(be, tx, q2));
        })
        .expect("spawn worker");
    WorkerHandle { queue }
}

impl WorkerHandle {
    pub fn send(&self, job: Job) {
        let mut jobs = self.queue.jobs.lock().unwrap();
        if matches!(job, Job::Refresh | Job::RefreshFull)
            && jobs
                .iter()
                .any(|j| matches!(j, Job::Refresh | Job::RefreshFull))
        {
            return;
        }
        jobs.push_back(job);
        self.queue.cvar.notify_one();
    }
}

pub(crate) struct Worker {
    pub(crate) be: Backends,
    pub(crate) tx: async_channel::Sender<UiMsg>,
    pub(crate) snap: Snapshot,
    pub(crate) ip_at: Option<Instant>,
    pub(crate) want_doctor: bool,
}

async fn worker_loop(
    be: Backends,
    tx: async_channel::Sender<UiMsg>,
    queue: Arc<Queue>,
) {
    let mut w = Worker {
        be,
        tx,
        snap: Snapshot::default(),
        ip_at: None,
        want_doctor: false,
    };
    // One password prompt per launch; every later privileged call reuses it.
    w.busy("Waiting for administrator access…");
    if let Err(e) = w.be.privs.unlock() {
        w.err(
            "Administrator access was not granted. You'll be asked again when you connect.".into(),
            Some(e),
        );
    }
    w.idle();
    w.refresh(true).await;
    loop {
        let job = {
            let mut jobs = queue.jobs.lock().unwrap();
            while jobs.is_empty() {
                jobs = queue.cvar.wait(jobs).unwrap();
            }
            jobs.pop_front().unwrap()
        };
        w.handle(job).await;
    }
}

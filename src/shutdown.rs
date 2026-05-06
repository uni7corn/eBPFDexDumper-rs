use std::sync::atomic::{AtomicU8, Ordering};

const STATE_RUNNING: u8 = 0;
const STATE_STOPPING: u8 = 1;
const STATE_FORCE: u8 = 2;

static STATE: AtomicU8 = AtomicU8::new(STATE_RUNNING);

pub fn keep_running() -> bool {
    STATE.load(Ordering::Acquire) == STATE_RUNNING
}

pub fn keep_finalizing() -> bool {
    STATE.load(Ordering::Acquire) < STATE_FORCE
}

pub fn request_stop() {
    let _ = STATE.fetch_update(Ordering::SeqCst, Ordering::Acquire, |cur| {
        if cur >= STATE_FORCE {
            None
        } else {
            Some(cur + 1)
        }
    });
}

#[allow(dead_code)]
pub fn is_stopping() -> bool {
    STATE.load(Ordering::Acquire) >= STATE_STOPPING
}

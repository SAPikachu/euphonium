use std::sync::mpsc::TryRecvError;

use mioco;
use mioco::sync::mpsc::{channel, Sender, Receiver};

pub struct Future<T: Send> {
    value: Option<T>,
    receiver: Receiver<T>,
}
impl<T: Send + 'static> Future<T> {
    fn new() -> (Self, Sender<T>) {
        let (sender, receiver) = channel::<T>();
        let ret = Future {
            receiver: receiver,
            value: None,
        };
        (ret, sender)
    }
    pub fn from_fn<F: 'static>(f: F) -> Self where F : Send + FnOnce() -> T {
        let (ret, sender) = Self::new();
        mioco::spawn(move || {
            match sender.send(f()) {
                Ok(_) => {},
                Err(_) => {
                    trace!("Future was dropped before completion.");
                },
            };
        });
        ret
    }
    pub fn is_done(&self) -> bool {
        self.value.is_some()
    }
    pub fn wait(&mut self) {
        if self.is_done() {
            return;
        }
        self.value = Some(self.receiver.recv().unwrap());
    }
    pub fn try_wait(&mut self) -> bool {
        if self.is_done() {
            return true;
        }
        match self.receiver.try_recv() {
            Ok(x) => {
                self.value = Some(x);
                true
            },
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => panic!("Future is panicked"),
        }
    }
    pub fn consume(mut self) -> T {
        self.wait();
        self.value.unwrap()
    }
    pub fn wait_any(futures: &mut [Self]) -> usize {
        assert!(!futures.is_empty());
        debug!("wait_any: Looping with {} futures", futures.len());
        loop {
            use mioco::Evented;
            for fut in futures.iter() {
                unsafe {
                    fut.receiver.select_add(mioco::RW::read());
                }
            }
            let ret = mioco::select_wait();
            trace!("select_wait: {:?}", ret);
            for (i, fut) in futures.iter_mut().enumerate() {
                if fut.try_wait() {
                    return i;
                }
            }
            debug!("wait_any: Continue looping with {} futures", futures.len());
        }
    }
}

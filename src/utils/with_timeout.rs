use std::io;
use std::net::SocketAddr;

use mio;
use mioco;
use mioco::{Evented, MioAdapter};
use mioco::timer::Timer;
use mioco::udp::UdpSocket;

fn invoke_with_timeout<T, F, TRet>(inner: &mut T, rw: mioco::RW, timer: &mut Timer, mut try_fn: F) -> io::Result<TRet> where
    T: Evented,
    F: FnMut(&mut T) -> io::Result<Option<TRet>>,
{
    loop {
        unsafe {
            timer.select_add(mioco::RW::read());
            inner.select_add(rw);
        }
        let ret = mioco::select_wait();
        if ret.id() == timer.id() {
            match timer.try_read() {
                Some(_) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"));
                },
                None => { continue; /* Spurious wakeup */ }
            }
        }
        match try_fn(inner) {
            Ok(Some(x)) => { return Ok(x); },
            Ok(None) => { /* Spurious wakeup */ },
            Err(e) => { return Err(e); },
        };
    }
}

pub struct WithTimeoutState<'a, T> where T: 'a + Evented {
    inner: &'a mut T,
    timer: Timer,
}
impl<'a, T> WithTimeoutState<'a, T> where T: 'a + Evented {
    fn invoke<F, TRet>(&mut self, rw: mioco::RW, try_fn: F) -> io::Result<TRet> where
        F: FnMut(&mut T) -> io::Result<Option<TRet>>,
    {
        invoke_with_timeout(self.inner, rw, &mut self.timer, try_fn)
    }
}
impl<'a> WithTimeoutState<'a, UdpSocket> {
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.invoke(mioco::RW::read(), move |x| x.try_recv(buf))
    }
    pub fn send(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize>  {
        self.invoke(mioco::RW::write(), move |x| x.try_send(buf, target))
    }
}
impl<'a, T> io::Read for WithTimeoutState<'a, MioAdapter<T>> where T: 'static + mio::Evented + mio::TryRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.invoke(mioco::RW::read(), move |x| x.try_read(buf))
    }
}
impl<'a, T> io::Write for WithTimeoutState<'a, MioAdapter<T>> where T: 'static + mio::Evented + mio::TryWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.invoke(mioco::RW::write(), move |x| x.try_write(buf))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
pub trait WithTimeout<'a, T> where T: 'a + Evented {
    fn with_timeout(&'a mut self, timeout_ms: i64) -> WithTimeoutState<'a, T>;
}
impl<'a, T> WithTimeout<'a, T> for T where T: 'a + Evented {
    fn with_timeout(&'a mut self, timeout_ms: i64) -> WithTimeoutState<'a, T> {
        let mut timer = Timer::new();
        timer.set_timeout(timeout_ms);
        WithTimeoutState {
            inner: self,
            timer: timer,
        }
    }
}

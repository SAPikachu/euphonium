use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use mio;
use mioco;
use mioco::{Evented, MioAdapter};
use mioco::timer::Timer;
use mioco::udp::UdpSocket;
use mioco::tcp::TcpStream;

fn invoke_with_timeout<T, F, TRet>(inner: &mut T, rw: mioco::RW, timer: &mut Timer, mut try_fn: F) -> io::Result<TRet> where
    T: Evented,
    F: FnMut(&mut T) -> io::Result<Option<TRet>>,
{
    trace!("invoke_with_timeout");
    loop {
        unsafe {
            timer.select_add(mioco::RW::read());
            inner.select_add(rw);
        }
        mioco::select_wait();
        if let Some(_) = timer.try_read() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out"));
        };
        match try_fn(inner) {
            Ok(Some(x)) => { return Ok(x); },
            Ok(None) => { /* Spurious wakeup */ },
            Err(e) => { return Err(e); },
        };
        trace!("invoke_with_timeout: Looping");
    }
}

pub trait AsTimeoutMs {
    fn as_timeout_ms(&self) -> u64;
}
impl AsTimeoutMs for i64 {
    fn as_timeout_ms(&self) -> u64 {
        *self as u64
    }
}
impl AsTimeoutMs for i32 {
    fn as_timeout_ms(&self) -> u64 {
        *self as u64
    }
}
impl AsTimeoutMs for u32 {
    fn as_timeout_ms(&self) -> u64 {
        *self as u64
    }
}
impl AsTimeoutMs for Duration {
    fn as_timeout_ms(&self) -> u64 {
        debug_assert!(self.as_secs() < u32::max_value() as u64);
        (self.as_secs() * 1000) as u64
    }
}
pub trait TcpStreamExt where Self: Sized {
    fn connect_with_timeout<TMs: AsTimeoutMs>(addr: &SocketAddr, timeout: TMs) -> io::Result<Self>;
}
impl TcpStreamExt for TcpStream {
    fn connect_with_timeout<TMs: AsTimeoutMs>(addr: &SocketAddr, timeout: TMs) -> io::Result<Self> {
        let mio_stream = try!(mio::tcp::TcpStream::connect(addr));
        let mut ret = MioAdapter::new(mio_stream);
        let mut timer = Timer::new();
        timer.set_timeout(timeout.as_timeout_ms());
        try!(invoke_with_timeout(
            &mut ret,
            mioco::RW::write(),
            &mut timer,
            |x| x.take_socket_error().map(Some)
        ));
        Ok(ret)
    }
}

pub struct WithTimeoutState<T> where T: Evented {
    inner: T,
    timer: Option<Timer>,
    timeout_ms: u64,
}
impl<T> WithTimeoutState<T> where T: Evented {
    fn create_timer(&self) -> Timer {
        let mut timer = Timer::new();
        timer.set_timeout(self.timeout_ms);
        timer
    }
    fn invoke<F, TRet>(&mut self, rw: mioco::RW, try_fn: F) -> io::Result<TRet> where
        F: FnMut(&mut T) -> io::Result<Option<TRet>>,
    {
        let mut timer = match self.timer {
            Some(_) => None,
            None => Some(self.create_timer()),
        };
        invoke_with_timeout(&mut self.inner, rw, timer.as_mut().or(self.timer.as_mut()).unwrap(), try_fn)
    }
}
impl WithTimeoutState<UdpSocket> {
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.invoke(mioco::RW::read(), move |x| x.try_recv(buf))
    }
    pub fn send(&mut self, buf: &[u8], target: &SocketAddr) -> io::Result<usize>  {
        self.invoke(mioco::RW::write(), move |x| x.try_send(buf, target))
    }
}
impl<T> io::Read for WithTimeoutState<MioAdapter<T>> where T: 'static + mio::Evented + mio::TryRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.invoke(mioco::RW::read(), move |x| x.try_read(buf))
    }
}
impl<T> io::Write for WithTimeoutState<MioAdapter<T>> where T: 'static + mio::Evented + mio::TryWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.invoke(mioco::RW::write(), move |x| x.try_write(buf))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
pub trait WithTimeout<T> where T: Evented, Self: Sized {
    fn with_timeout_core(self, timeout_ms: u64, reset_before_invoke: bool) -> WithTimeoutState<T>;
    fn with_timeout<TMs: AsTimeoutMs>(self, timeout: TMs) -> WithTimeoutState<T> {
        self.with_timeout_core(timeout.as_timeout_ms(), false)
    }
    fn with_resetting_timeout<TMs: AsTimeoutMs>(self, timeout: TMs) -> WithTimeoutState<T> {
        self.with_timeout_core(timeout.as_timeout_ms(), true)
    }
}
impl<T> WithTimeout<T> for T where T: Evented {
    fn with_timeout_core(self, timeout_ms: u64, reset_before_invoke: bool) -> WithTimeoutState<T> {
        let mut ret = WithTimeoutState {
            inner: self,
            timer: None,
            timeout_ms: timeout_ms,
        };
        if ! reset_before_invoke {
            ret.timer = Some(ret.create_timer());
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};

    use mioco::tcp::TcpStream;

    use ::mioco_config_start;
    use super::*;

    #[test]
    fn connect_with_timeout_success() {
        mioco_config_start(|| {
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
            TcpStream::connect_with_timeout(&target, 5000)
        }).unwrap().unwrap();
    }
    #[test]
    #[should_panic(expected = "refused")]
    fn connect_with_timeout_refused() {
        mioco_config_start(|| {
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 65534);
            TcpStream::connect_with_timeout(&target, 5000)
        }).unwrap().unwrap();
    }
    #[test]
    #[should_panic(expected = "TimedOut")]
    fn connect_with_timeout_timeout() {
        mioco_config_start(|| {
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(202, 96, 128, 68)), 65534);
            TcpStream::connect_with_timeout(&target, 10)
        }).unwrap().unwrap();
    }
}

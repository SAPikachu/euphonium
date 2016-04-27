use std::io;
use std::net::SocketAddr;

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

pub trait TcpStreamExt where Self: Sized {
    fn connect_with_timeout(addr: &SocketAddr, timeout_ms: i64) -> io::Result<Self>;
}
impl TcpStreamExt for TcpStream {
    fn connect_with_timeout(addr: &SocketAddr, timeout_ms: i64) -> io::Result<Self> {
        let mio_stream = try!(mio::tcp::TcpStream::connect(addr));
        let mut ret = MioAdapter::new(mio_stream);
        let mut timer = Timer::new();
        timer.set_timeout(timeout_ms);
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
    timeout_ms: i64,
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
    fn with_timeout_core(self, timeout_ms: i64, reset_before_invoke: bool) -> WithTimeoutState<T>;
    fn with_timeout(self, timeout_ms: i64) -> WithTimeoutState<T> {
        self.with_timeout_core(timeout_ms, false)
    }
    fn with_resetting_timeout(self, timeout_ms: i64) -> WithTimeoutState<T> {
        self.with_timeout_core(timeout_ms, true)
    }
}
impl<T> WithTimeout<T> for T where T: Evented {
    fn with_timeout_core(self, timeout_ms: i64, reset_before_invoke: bool) -> WithTimeoutState<T> {
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
            TcpStream::connect_with_timeout(&target, 5000).unwrap();
        }).unwrap();
    }
    #[test]
    #[should_panic(expected = "refused")]
    fn connect_with_timeout_refused() {
        mioco_config_start(|| {
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 65534);
            TcpStream::connect_with_timeout(&target, 5000).unwrap();
        }).unwrap();
    }
    #[test]
    #[should_panic(expected = "TimedOut")]
    fn connect_with_timeout_timeout() {
        mioco_config_start(|| {
            let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(202, 96, 128, 68)), 65534);
            TcpStream::connect_with_timeout(&target, 10).unwrap();
        }).unwrap();
    }
}

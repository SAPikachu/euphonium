use std::fmt::{Display, Formatter, Result as FmtResult};

use trust_dns::op::{Query, Message, MessageType};

pub struct DisplayWrapper<'a, T: ?Sized>(&'a T) where T: 'static;
pub trait AsDisplay {
    fn as_disp(&self) -> DisplayWrapper<Self> {
        DisplayWrapper(self)
    }
}
impl<'a, T: 'static + ?Sized> AsDisplay for T where DisplayWrapper<'a, T>: Display {}

impl<'a> Display for DisplayWrapper<'a, Query> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let q = self.0;
        write!(f, "{} {:?} {:?}", q.name(), q.query_type(), q.query_class())
    }
}
impl<'a> Display for DisplayWrapper<'a, Message> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let msg = self.0;
        match msg.message_type() {
            MessageType::Query if msg.queries().is_empty() => write!(
                f, "[{}] (no query)", msg.id(),
            ),
            MessageType::Query => write!(
                f, "[{}] {}", msg.id(), msg.queries()[0].as_disp(),
            ),
            MessageType::Response => write!(
                f,
                "[{}] {:?} {}/{}/{}",
                msg.id(),
                msg.response_code(),
                msg.answers().len(),
                msg.name_servers().len(),
                msg.additionals().len(),
            )
        }
    }
}


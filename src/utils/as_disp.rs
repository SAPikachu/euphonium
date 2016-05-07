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
        write!(f, "{} {:?} {:?}", q.get_name(), q.get_query_type(), q.get_query_class())
    }
}
impl<'a> Display for DisplayWrapper<'a, Message> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let msg = self.0;
        match msg.get_message_type() {
            MessageType::Query if msg.get_queries().is_empty() => write!(
                f, "[{}] (no query)", msg.get_id(),
            ),
            MessageType::Query => write!(
                f, "[{}] {}", msg.get_id(), msg.get_queries()[0].as_disp(),
            ),
            MessageType::Response => write!(
                f,
                "[{}] {:?} {}/{}/{}",
                msg.get_id(),
                msg.get_response_code(),
                msg.get_answers().len(),
                msg.get_name_servers().len(),
                msg.get_additional().len(),
            )
        }
    }
}


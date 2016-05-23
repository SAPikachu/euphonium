#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct JsonRpcRequest {
    pub method: String,
    pub params: Vec<String>,
    id: u32,
}
impl JsonRpcRequest {
    pub fn new(method: String) -> Self {
        JsonRpcRequest {
            id: 42,
            params: Vec::new(),
            method: method,
        }
    }
    pub fn result(&self, msg: String) -> JsonRpcResponse {
        JsonRpcResponse {
            id: self.id,
            error: None,
            result: Some(msg),
        }
    }
    pub fn error(&self, msg: String) -> JsonRpcResponse {
        JsonRpcResponse {
            id: self.id,
            result: None,
            error: Some(msg),
        }
    }
}
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct JsonRpcResponse {
    id: u32,
    pub result: Option<String>,
    pub error: Option<String>,
}


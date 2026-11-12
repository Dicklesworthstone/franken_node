#![no_main]
#![forbid(unsafe_code)]

use frankenengine_node::security::remote_cap::{RemoteCap, RemoteScope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let _ = serde_json::from_slice::<RemoteCap>(data);
    if let Ok(scope) = serde_json::from_slice::<RemoteScope>(data) {
        let _ = scope.allows_endpoint("https://api.example.com/v1/status");
    }
});

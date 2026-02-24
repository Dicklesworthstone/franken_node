use anyhow::{Result, Context};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, Mutex};
use crate::storage::frankensqlite_adapter::{FrankensqliteAdapter, PersistenceClass};

pub struct TelemetryBridge {
    socket_path: String,
    adapter: Arc<Mutex<FrankensqliteAdapter>>,
}

impl TelemetryBridge {
    pub fn new(socket_path: &str, adapter: Arc<Mutex<FrankensqliteAdapter>>) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            adapter,
        }
    }

    /// Spawns a background thread to listen for telemetry events emitted by `franken_engine`.
    /// Events are read from a Unix Domain Socket to minimize IPC overhead.
    pub fn start_listener(&self) -> Result<()> {
        let socket_path = self.socket_path.clone();
        let adapter_clone = Arc::clone(&self.adapter);

        // Ensure the old socket is removed before binding
        if Path::new(&socket_path).exists() {
            std::fs::remove_file(&socket_path)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let adapter_inner = Arc::clone(&adapter_clone);
                        thread::spawn(move || {
                            Self::handle_connection(stream, &adapter_inner);
                        });
                    }
                    Err(e) => {
                        eprintln!("Error accepting telemetry connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    fn handle_connection(stream: UnixStream, adapter: &Arc<Mutex<FrankensqliteAdapter>>) {
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            match line {
                Ok(event_json) => {
                    let key = format!("telemetry_{}", uuid::Uuid::new_v4());
                    if let Ok(mut db) = adapter.lock() {
                        let _ = db.write(PersistenceClass::AuditLog, &key, event_json.as_bytes());
                    }
                }
                Err(e) => {
                    eprintln!("Error reading telemetry stream: {}", e);
                    break;
                }
            }
        }
    }
}
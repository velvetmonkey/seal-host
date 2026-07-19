// SPDX-License-Identifier: Apache-2.0
//! A single owner for client stdout, preserving newline frame atomicity.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

enum Command {
    Frame(Vec<u8>, mpsc::SyncSender<Result<(), String>>),
    Shutdown,
}

#[derive(Clone)]
pub struct OutputSender {
    tx: mpsc::SyncSender<Command>,
    failed: Arc<AtomicBool>,
}

impl OutputSender {
    pub fn send_frame(&self, frame: &[u8]) -> Result<(), String> {
        if !frame.ends_with(b"\n") {
            return Err("refusing unterminated client-output frame".into());
        }
        if self.failed.load(Ordering::Acquire) {
            return Err("client stdout transport is dead".into());
        }
        let (ack_tx, ack_rx) = mpsc::sync_channel(0);
        self.tx
            .send(Command::Frame(frame.to_vec(), ack_tx))
            .map_err(|_| "client stdout writer stopped".to_string())?;
        ack_rx
            .recv()
            .map_err(|_| "client stdout writer stopped before acknowledgement".to_string())?
    }

    pub fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
}

pub struct OutputQueue {
    sender: OutputSender,
    join: Option<std::thread::JoinHandle<()>>,
}

impl OutputQueue {
    pub fn stdout() -> Self {
        Self::with_writer(std::io::stdout())
    }

    fn with_writer<W: Write + Send + 'static>(mut writer: W) -> Self {
        let (tx, rx) = mpsc::sync_channel::<Command>(64);
        let failed = Arc::new(AtomicBool::new(false));
        let writer_failed = failed.clone();
        let join = std::thread::spawn(move || {
            let mut terminal_error: Option<String> = None;
            while let Ok(command) = rx.recv() {
                match command {
                    Command::Frame(frame, ack) => {
                        let result = match &terminal_error {
                            Some(error) => Err(error.clone()),
                            None => writer
                                .write_all(&frame)
                                .and_then(|_| writer.flush())
                                .map_err(|error| format!("client stdout write failed: {error}")),
                        };
                        if let Err(error) = &result {
                            terminal_error = Some(error.clone());
                            writer_failed.store(true, Ordering::Release);
                        }
                        let _ = ack.send(result);
                    }
                    Command::Shutdown => break,
                }
            }
        });
        Self {
            sender: OutputSender { tx, failed },
            join: Some(join),
        }
    }

    pub fn sender(&self) -> OutputSender {
        self.sender.clone()
    }

    pub fn shutdown(mut self) {
        let _ = self.sender.tx.send(Command::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for OutputQueue {
    fn drop(&mut self) {
        let _ = self.sender.tx.send(Command::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn concurrent_frames_never_interleave() {
        let writer = SharedWriter::default();
        let observed = writer.0.clone();
        let queue = OutputQueue::with_writer(writer);
        let left = queue.sender();
        let right = queue.sender();
        let a = std::thread::spawn(move || left.send_frame(b"aaaa\n").unwrap());
        let b = std::thread::spawn(move || right.send_frame(b"bbbb\n").unwrap());
        a.join().unwrap();
        b.join().unwrap();
        queue.shutdown();
        let bytes = observed.lock().unwrap().clone();
        assert!(bytes == b"aaaa\nbbbb\n" || bytes == b"bbbb\naaaa\n");
    }

    #[test]
    fn unterminated_frame_is_refused() {
        let queue = OutputQueue::with_writer(Vec::<u8>::new());
        assert!(queue.sender().send_frame(b"partial").is_err());
    }

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_failure_is_sticky_and_reported() {
        let queue = OutputQueue::with_writer(BrokenWriter);
        let sender = queue.sender();
        assert!(sender.send_frame(b"one\n").is_err());
        assert!(sender.has_failed());
        assert!(sender.send_frame(b"two\n").is_err());
    }
}

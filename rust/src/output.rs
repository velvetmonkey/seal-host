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

    use std::collections::HashSet;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Condvar;
    use std::time::{Duration, Instant};

    const SATURATION_SENDERS: usize = 96;
    const SATURATION_FRAMES_PER_SENDER: usize = 32;

    fn saturation_frame(sender: usize, seq: usize) -> Vec<u8> {
        format!("s{sender:03} q{seq:04}\n").into_bytes()
    }

    type WriteLog = Arc<Mutex<Vec<(Vec<u8>, Instant)>>>;

    /// Blocks every write until the gate opens, then logs (frame, when).
    #[derive(Clone)]
    struct StallWriter {
        gate: Arc<(Mutex<bool>, Condvar)>,
        log: WriteLog,
    }

    impl StallWriter {
        fn new() -> Self {
            Self {
                gate: Arc::new((Mutex::new(false), Condvar::new())),
                log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn open(&self) {
            *self.gate.0.lock().unwrap() = true;
            self.gate.1.notify_all();
        }
    }

    impl Write for StallWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let (lock, condvar) = &*self.gate;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = condvar.wait(open).unwrap();
            }
            drop(open);
            self.log
                .lock()
                .unwrap()
                .push((bytes.to_vec(), Instant::now()));
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// send_frame acks only after the writer has written and flushed the
    /// frame, so with the writer stalled NO send may complete, no matter how
    /// far past the 64-slot channel capacity the senders push. Once the
    /// writer drains, every frame must come out exactly once, newline-atomic,
    /// in per-sender order.
    #[test]
    fn saturated_queue_blocks_every_sender_until_drain_and_loses_nothing() {
        let writer = StallWriter::new();
        let queue = OutputQueue::with_writer(writer.clone());
        let completed = Arc::new(AtomicUsize::new(0));

        let senders: Vec<_> = (0..SATURATION_SENDERS)
            .map(|id| {
                let sender = queue.sender();
                let completed = completed.clone();
                std::thread::spawn(move || {
                    let mut latencies = Vec::with_capacity(SATURATION_FRAMES_PER_SENDER);
                    for seq in 0..SATURATION_FRAMES_PER_SENDER {
                        let frame = saturation_frame(id, seq);
                        let started = Instant::now();
                        sender.send_frame(&frame).unwrap();
                        latencies.push(started.elapsed());
                        completed.fetch_add(1, Ordering::Release);
                    }
                    latencies
                })
            })
            .collect();

        let stall = Duration::from_millis(500);
        std::thread::sleep(stall);
        // Read before opening the gate; assert only after the writer is
        // released, so a failure cannot deadlock the join in shutdown.
        let completed_during_stall = completed.load(Ordering::Acquire);

        let released = Instant::now();
        writer.open();
        let latencies: Vec<Duration> = senders
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect();
        queue.shutdown();
        assert_eq!(
            completed_during_stall, 0,
            "a send_frame call completed while the writer was stalled: the \
             ack no longer proves the frame reached the client transport"
        );

        let log = writer.log.lock().unwrap();
        let total = SATURATION_SENDERS * SATURATION_FRAMES_PER_SENDER;
        assert_eq!(log.len(), total, "frames lost or duplicated in the queue");
        let unique: HashSet<&[u8]> = log.iter().map(|(frame, _)| frame.as_slice()).collect();
        assert_eq!(unique.len(), total, "duplicate frames written");
        let mut last_seq = vec![None::<usize>; SATURATION_SENDERS];
        for (frame, _) in log.iter() {
            assert_eq!(frame.last(), Some(&b'\n'), "frame split across writes");
            let text = std::str::from_utf8(frame).unwrap();
            let sender: usize = text[1..4].parse().unwrap();
            let seq: usize = text[6..10].parse().unwrap();
            assert!(unique.contains(saturation_frame(sender, seq).as_slice()));
            assert!(
                last_seq[sender].is_none_or(|previous| seq > previous),
                "sender {sender} frames reordered"
            );
            last_seq[sender] = Some(seq);
        }
        let drain = log.last().unwrap().1.duration_since(released);
        let mean = latencies.iter().sum::<Duration>() / latencies.len() as u32;
        let max = latencies.iter().max().unwrap();
        eprintln!(
            "saturation: {SATURATION_SENDERS} senders x {SATURATION_FRAMES_PER_SENDER} frames \
             = {total} frames through the 64-slot queue; 0 of {total} sends completed during a \
             {stall:?} writer stall; drain took {drain:?} \
             ({:.0} frames/s); send_frame round trip mean {mean:?}, max {max:?}",
            total as f64 / drain.as_secs_f64()
        );
    }

    /// Full-throughput fan-out with a fast writer: the numbers half of the
    /// saturation evidence, without an artificial stall.
    #[test]
    fn sender_fanout_full_throughput_preserves_every_frame() {
        const SENDERS: usize = 64;
        const FRAMES: usize = 256;
        let writer = SharedWriter::default();
        let observed = writer.0.clone();
        let queue = OutputQueue::with_writer(writer);
        let started = Instant::now();
        let handles: Vec<_> = (0..SENDERS)
            .map(|id| {
                let sender = queue.sender();
                std::thread::spawn(move || {
                    let mut latencies = Vec::with_capacity(FRAMES);
                    for seq in 0..FRAMES {
                        let frame = saturation_frame(id, seq);
                        let sent = Instant::now();
                        sender.send_frame(&frame).unwrap();
                        latencies.push(sent.elapsed());
                    }
                    latencies
                })
            })
            .collect();
        let latencies: Vec<Duration> = handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect();
        let elapsed = started.elapsed();
        queue.shutdown();

        let bytes = observed.lock().unwrap().clone();
        let lines: Vec<&[u8]> = bytes.split_inclusive(|byte| *byte == b'\n').collect();
        let total = SENDERS * FRAMES;
        assert_eq!(lines.len(), total, "frames lost, duplicated, or merged");
        let unique: HashSet<&[u8]> = lines.iter().copied().collect();
        assert_eq!(unique.len(), total, "duplicate or interleaved frames");
        let mut last_seq = vec![None::<usize>; SENDERS];
        for line in &lines {
            let text = std::str::from_utf8(line).unwrap();
            let sender: usize = text[1..4].parse().unwrap();
            let seq: usize = text[6..10].parse().unwrap();
            assert!(
                last_seq[sender].is_none_or(|previous| seq > previous),
                "sender {sender} frames reordered"
            );
            last_seq[sender] = Some(seq);
        }
        let mean = latencies.iter().sum::<Duration>() / latencies.len() as u32;
        let max = latencies.iter().max().unwrap();
        eprintln!(
            "throughput: {SENDERS} senders x {FRAMES} frames = {total} frames in {elapsed:?} \
             ({:.0} frames/s); send_frame round trip mean {mean:?}, max {max:?}",
            total as f64 / elapsed.as_secs_f64()
        );
    }

    /// Accepts a fixed number of writes, then fails every later one.
    #[derive(Clone)]
    struct DyingWriter {
        remaining: Arc<Mutex<usize>>,
        log: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Write for DyingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut remaining = self.remaining.lock().unwrap();
            if *remaining == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ));
            }
            *remaining -= 1;
            self.log.lock().unwrap().push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Writer death under saturation load fails closed: exactly the frames
    /// the writer accepted were acked Ok, every later send on every sender
    /// errors, and no sender sees an Ok after its first Err.
    #[test]
    fn writer_death_under_load_acks_exactly_the_delivered_frames() {
        const ACCEPTED: usize = 100;
        let writer = DyingWriter {
            remaining: Arc::new(Mutex::new(ACCEPTED)),
            log: Arc::new(Mutex::new(Vec::new())),
        };
        let log = writer.log.clone();
        let queue = OutputQueue::with_writer(writer);
        let handles: Vec<_> = (0..SATURATION_SENDERS)
            .map(|id| {
                let sender = queue.sender();
                std::thread::spawn(move || {
                    (0..SATURATION_FRAMES_PER_SENDER)
                        .map(|seq| {
                            let frame = saturation_frame(id, seq);
                            let delivered = sender.send_frame(&frame).is_ok();
                            (frame, delivered)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let results: Vec<Vec<(Vec<u8>, bool)>> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(queue.sender().has_failed());
        assert!(queue.sender().send_frame(b"late\n").is_err());
        queue.shutdown();

        let written: HashSet<Vec<u8>> = log.lock().unwrap().iter().cloned().collect();
        let acked: HashSet<Vec<u8>> = results
            .iter()
            .flatten()
            .filter(|(_, delivered)| *delivered)
            .map(|(frame, _)| frame.clone())
            .collect();
        assert_eq!(
            log.lock().unwrap().len(),
            written.len(),
            "duplicate frames written"
        );
        assert_eq!(
            acked, written,
            "acked and delivered frame sets diverge: an Ok ack no longer \
             proves delivery, or a delivered frame was reported lost"
        );
        assert_eq!(acked.len(), ACCEPTED);
        for sender_results in &results {
            let first_err = sender_results
                .iter()
                .position(|(_, delivered)| !delivered)
                .unwrap_or(sender_results.len());
            assert!(
                sender_results[first_err..]
                    .iter()
                    .all(|(_, delivered)| !delivered),
                "a sender saw an Ok after an Err: failure is not sticky in order"
            );
        }
        eprintln!(
            "writer death: {} sends offered, {ACCEPTED} accepted by the transport, \
             {ACCEPTED} acked Ok, {} refused; ack set == delivered set",
            SATURATION_SENDERS * SATURATION_FRAMES_PER_SENDER,
            SATURATION_SENDERS * SATURATION_FRAMES_PER_SENDER - ACCEPTED
        );
    }
}

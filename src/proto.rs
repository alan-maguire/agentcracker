//! Host <-> guest protocol over vsock, and the constrained file stream used
//! to move files across the boundary (home seed in, changes and agent state
//! out).
//!
//! Transport.  All connections are opened by the guest towards the host
//! (CID 2).  Firecracker forwards a guest connection to vsock port `P` to
//! the unix socket `<uds_path>_P` on the host, where agentcracker listens.
//! Two ports are used:
//!
//! - [`PORT_CONTROL`]: one connection per boot, carrying the framed
//!   control protocol below;
//! - [`PORT_PROXY`]: one connection per proxied TCP connection (see
//!   `crate::proxy`).
//!
//! Frames.  Each frame is a type byte, a big-endian u32 length, then that
//! many bytes (at most 16 MiB).  On the control connection:
//!
//! ```text
//! host -> guest   CONFIG                    json GuestConfig
//!                 SEED* SEED_END            home seed, as a file stream
//! guest -> host   READY                     the command is starting
//!                 STDOUT* STDERR*           command output
//! host -> guest   STDIN* RESIZE STDIN_EOF   at any time while it runs
//! guest -> host   EXIT                      i32 exit status
//!                 EXPORT* EXPORT_END        project upper layer (file stream)
//!                 STATE* STATE_END          agent state (file stream)
//!                 DONE                      about to power off
//! guest -> host   ERROR                     utf-8 message, if anything fails;
//!                                           the guest then powers off
//! ```
//!
//! File stream.  A deliberately tiny tar replacement (see [`StreamWriter`]
//! and [`StreamReader`]): directories, regular files, symlinks, deletions
//! (overlay whiteouts) and opaque directories, with permission bits only -
//! no owners, devices, xattrs or hard links - and every path checked with
//! [`safe_rel_path`] as it is read.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

use crate::util::{Result, safe_rel_path};

/// vsock port of the control connection (the host listens on `v.sock_1024`).
pub const PORT_CONTROL: u32 = 1024;
/// vsock port of egress proxy connections (the host listens on `v.sock_1025`).
pub const PORT_PROXY: u32 = 1025;
/// vsock port the guest listens on for extra commands in a running session
/// (`agentcracker shell` on a running session).  The host connects through
/// Firecracker's vsock socket (`CONNECT 1026`); the guest accepts only
/// connections from the host (CID 2).  The conversation is one
/// [`M_EXEC`] request, then the same STDIN/RESIZE/STDIN_EOF/STOP frames
/// from the host and READY/STDOUT/STDERR/ERROR/EXIT frames from the guest
/// as on the control connection.
pub const PORT_EXEC: u32 = 1026;
/// Address of the proxy listener inside the guest, which `HTTPS_PROXY`
/// points at.
pub const GUEST_PROXY_ADDR: &str = "127.0.0.1:3128";

// frame types (see the module docs for the conversation)
/// host to guest: the [`GuestConfig`], as JSON.  Always the first frame.
pub const M_CONFIG: u8 = 1;
/// host to guest: a chunk of the home seed file stream.
pub const M_SEED: u8 = 2;
/// host to guest: end of the home seed.
pub const M_SEED_END: u8 = 3;
/// host to guest: terminal input for the command.
pub const M_STDIN: u8 = 4;
/// host to guest: new terminal size, `rows: u16, cols: u16`, big-endian.
pub const M_RESIZE: u8 = 5;
/// host to guest: end of input (Ctrl-D on a pty, closes stdin otherwise).
pub const M_STDIN_EOF: u8 = 6;
/// host to guest: stop the command (SIGTERM to its process group, SIGKILL
/// 5 s later if it is still there); it then exits and is exported normally.
pub const M_STOP: u8 = 7;
/// host to guest, first frame on a [`PORT_EXEC`] connection: an
/// [`ExecRequest`], as JSON.
pub const M_EXEC: u8 = 8;
/// guest to host: setup is done and the command is starting.
pub const M_READY: u8 = 10;
/// guest to host: something failed (UTF-8 message); the guest then powers off.
pub const M_ERROR: u8 = 11;
/// guest to host: command output (all of it, when the command has a pty).
pub const M_STDOUT: u8 = 12;
/// guest to host: the command's exit status, an `i32`, big-endian.
pub const M_EXIT: u8 = 13;
/// guest to host: a chunk of the project upper layer file stream.
pub const M_EXPORT: u8 = 14;
/// guest to host: end of the project upper layer stream.
pub const M_EXPORT_END: u8 = 15;
/// guest to host: a chunk of the agent state file stream.
pub const M_STATE: u8 = 16;
/// guest to host: end of the agent state stream.
pub const M_STATE_END: u8 = 17;
/// guest to host: everything is sent; the guest is about to power off.
pub const M_DONE: u8 = 18;
/// guest to host: command stderr (only when it is not on a pty).
pub const M_STDERR: u8 = 19;

/// Largest frame payload accepted (16 MiB).  A larger length means a
/// corrupt or hostile stream.
const MAX_FRAME: usize = 1 << 24;

/// A command to run in an already-running session (see [`PORT_EXEC`]).  It
/// runs like the session's command: same root, user, environment and
/// directory.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ExecRequest {
    /// Program and arguments.
    pub cmd: Vec<String>,
    /// Give it a terminal (the requester is on one).
    pub tty: bool,
    /// Terminal rows.
    pub rows: u16,
    /// Terminal columns.
    pub cols: u16,
    /// The requester's `TERM`, if set.
    pub term: Option<String>,
}

/// Everything acinit needs to set up the guest, sent as JSON in the CONFIG
/// frame.  Built by `vm::boot` from the host's view of the user, the
/// project and the toolchains.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GuestConfig {
    /// Session id (informational).
    pub session: String,
    /// Project directory: mounted at the same path in the guest, and the
    /// command's working directory.
    pub cwd: String,
    /// The invoking user's uid; the command runs as this user.
    pub uid: u32,
    /// The invoking user's primary gid.
    pub gid: u32,
    /// User name (informational: the guest's passwd comes from the base image).
    pub user: String,
    /// Home directory path, created in the guest and filled from the seed.
    pub home: String,
    /// The command and its arguments.  `cmd[0]` is looked up in `path` unless
    /// it contains a `/`.
    pub cmd: Vec<String>,
    /// The complete environment of the command; nothing is inherited from acinit.
    pub env: Vec<(String, String)>,
    /// The `$PATH` used to look up `cmd[0]`.
    pub path: String,
    /// Whether the host side is a terminal: if so the command gets a pty,
    /// otherwise pipes.
    pub tty: bool,
    /// Initial terminal height.
    pub rows: u16,
    /// Initial terminal width.
    pub cols: u16,
    /// Absolute host paths of the toolchain directories in the tools image.
    pub tools: Vec<String>,
    /// Host owner and mode of the ancestor directories of `cwd` and of each
    /// tool: `(path, uid, gid, mode)`.  acinit recreates them faithfully.
    pub dirs: Vec<(String, u32, u32, u32)>,
    /// Whether to start the guest-side proxy listener.
    pub net: bool,
    /// Paths (relative to `$HOME`) exported back to the host on exit.
    pub state_paths: Vec<String>,
    /// Host wall-clock time, Unix seconds; the guest clock is set from it.
    pub time: u64,
    /// Guest block device holding usr.img.
    pub dev_usr: String,
    /// Guest block device holding tools.img.
    pub dev_tools: String,
    /// Guest block device holding the project snapshot.
    pub dev_lower: String,
    /// Guest block device of the writable scratch disk.
    pub dev_scratch: String,
    /// Guest block device holding the project delta layer, if any (stacked
    /// above `dev_lower`).
    #[serde(default)]
    pub dev_lower_delta: Option<String>,
    /// Guest block device of the project's build cache, mounted as
    /// `$HOME/.cache`, if the session has it (see [`crate::buildcache`]).
    #[serde(default)]
    pub dev_cache: Option<String>,
    /// `--branch`, on the session's first boot: `(name, commit)`.  acinit
    /// creates branch `name` at `commit` in the project's repository and
    /// checks it out (by writing `.git/refs/heads/<name>` and `.git/HEAD`),
    /// so the agent's commits go on it.
    #[serde(default)]
    pub git_branch: Option<(String, String)>,
    /// Booting test kernels is on (`boot = true`): `/dev/kvm` is made
    /// usable by the user, and removed otherwise.
    #[serde(default)]
    pub boot: bool,
    /// Files acinit writes into `$HOME` on every boot, as the user: what the
    /// agent is told about its environment (see [`crate::guidance`]).
    #[serde(default)]
    pub agent_files: Vec<AgentFile>,
}

/// One file acinit writes into the guest's home (see [`crate::guidance`]).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentFile {
    /// Path relative to `$HOME`.
    pub path: String,
    /// The contents; `None` removes the file (and its directory, if that
    /// is then empty).
    pub content: Option<String>,
    /// Replace only agentcracker's marked section of the file, keeping the
    /// rest, instead of the whole file.
    pub block: bool,
}

/// Write one frame: type `t`, the length of `data` as a big-endian u32,
/// then `data`.
///
/// The frame is sent with a single `write_all`, so threads sharing a locked
/// connection never interleave partial frames.  `w`: the connection;
/// `data` must be at most [`MAX_FRAME`] bytes for the peer to accept it.
/// Returns any I/O error.
pub fn write_frame(w: &mut impl Write, t: u8, data: &[u8]) -> io::Result<()> {
    let mut buf = Vec::with_capacity(5 + data.len());
    buf.push(t);
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
    w.write_all(&buf)
}

/// Read one frame from `r`, blocking until it is complete.
///
/// Returns `(type, payload)`.  Errors on EOF or an I/O failure, and with
/// `InvalidData` if the announced length exceeds [`MAX_FRAME`] (the
/// connection cannot be resynchronised after that).
pub fn read_frame(r: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr)?;
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data)?;
    Ok((hdr[0], data))
}

/// Adapts a frame transport into a byte sink.
///
/// Bytes written are buffered and sent as frames of type `t` (about 64 KiB
/// each), and [`FrameWriter::finish`] sends the empty end-marker frame
/// `end`.  Used to send a file stream as EXPORT* EXPORT_END or STATE*
/// STATE_END.
pub struct FrameWriter<W: Write> {
    w: W,
    t: u8,
    end: u8,
    buf: Vec<u8>,
}

impl<W: Write> FrameWriter<W> {
    /// Wrap transport `w`.  Data frames get type `t`, the final marker type
    /// `end`.  Returns the writer.
    pub fn new(w: W, t: u8, end: u8) -> Self {
        FrameWriter { w, t, end, buf: Vec::with_capacity(1 << 16) }
    }
    /// Send any buffered data, then the end-marker frame.  Returns the
    /// underlying transport, or an I/O error.
    pub fn finish(mut self) -> io::Result<W> {
        self.flush()?;
        write_frame(&mut self.w, self.end, &[])?;
        Ok(self.w)
    }
}

impl<W: Write> Write for FrameWriter<W> {
    /// Buffer `data`, sending a frame once 64 KiB or more is buffered.  Returns
    /// `data.len()` (everything is always accepted), or an I/O error from
    /// sending.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= 1 << 16 {
            self.flush()?;
        }
        Ok(data.len())
    }
    /// Send whatever is buffered as one frame, then flush the transport.
    /// Returns any I/O error.
    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            write_frame(&mut self.w, self.t, &self.buf)?;
            self.buf.clear();
        }
        self.w.flush()
    }
}

// ---------------------------------------------------------------------------
// File stream: a deliberately tiny tar replacement.
//
//   'D' path mode                directory
//   'F' path mode size data      regular file
//   'L' path target              symlink
//   'X' path                     deletion (overlay whiteout)
//   'O' path mode                opaque directory (replaces lower dir)
//   'E'                          end
//
// path/target: u32 length + bytes; mode: u32; size: u64. Only permission
// bits survive; no owners, no devices, no xattrs.
// ---------------------------------------------------------------------------

/// One record of a file stream, as returned by [`StreamReader::next`].
/// Paths are relative and already validated; modes are permission bits only.
#[derive(Debug, Clone, PartialEq)]
pub enum Entry {
    /// A directory, created if missing.
    Dir { path: Vec<u8>, mode: u32 },
    /// A regular file of `size` bytes.  Its data follows in the stream; read it
    /// with [`StreamReader::data_to`], or let the next `next` skip it.
    File { path: Vec<u8>, mode: u32, size: u64 },
    /// A symlink to `target`.  The target is not validated: readers only ever
    /// create the link, never follow it.
    Symlink { path: Vec<u8>, target: Vec<u8> },
    /// The path was deleted (an overlay whiteout in the upper layer).
    Delete { path: Vec<u8> },
    /// A directory that replaced the lower directory of the same name: nothing
    /// the lower layer had beneath it survives.
    Opaque { path: Vec<u8>, mode: u32 },
}

impl Entry {
    /// Returns the entry's path, relative to the stream's root.
    pub fn path(&self) -> &[u8] {
        match self {
            Entry::Dir { path, .. }
            | Entry::File { path, .. }
            | Entry::Symlink { path, .. }
            | Entry::Delete { path }
            | Entry::Opaque { path, .. } => path,
        }
    }
}

/// Encoder for the file stream format.
///
/// Each method writes one record straight to `w`; nothing is buffered here,
/// so wrap `w` in a `BufWriter` when writing many small records.
///
/// Encoding: a tag byte, then fields - paths and symlink targets as a
/// big-endian u32 length plus bytes, modes as a big-endian u32, file sizes
/// as a big-endian u64 followed by the data:
///
/// ```text
/// 'D' path mode             directory
/// 'F' path mode size data   regular file
/// 'L' path target           symlink
/// 'X' path                  deletion (overlay whiteout)
/// 'O' path mode             opaque directory (replaces the lower dir)
/// 'E'                       end of stream
/// ```
pub struct StreamWriter<W: Write> {
    /// The underlying writer, public so it can be recovered after
    /// [`StreamWriter::end`].
    pub w: W,
}

impl<W: Write> StreamWriter<W> {
    /// Start a stream on `w`.  Returns the writer.
    pub fn new(w: W) -> Self {
        StreamWriter { w }
    }
    /// Write a length-prefixed byte string: a big-endian u32 length, then `b`.
    fn bytes(&mut self, b: &[u8]) -> io::Result<()> {
        self.w.write_all(&(b.len() as u32).to_be_bytes())?;
        self.w.write_all(b)
    }
    /// Record directory `path` with permission bits `mode` (bits above 0o7777
    /// are dropped).  Returns any I/O error.
    pub fn dir(&mut self, path: &[u8], mode: u32) -> io::Result<()> {
        self.w.write_all(b"D")?;
        self.bytes(path)?;
        self.w.write_all(&(mode & 0o7777).to_be_bytes())
    }
    /// Record opaque directory `path` (see [`Entry::Opaque`]) with permission
    /// bits `mode`.  Returns any I/O error.
    pub fn opaque(&mut self, path: &[u8], mode: u32) -> io::Result<()> {
        self.w.write_all(b"O")?;
        self.bytes(path)?;
        self.w.write_all(&(mode & 0o7777).to_be_bytes())
    }
    /// Record that `path` was deleted.  Returns any I/O error.
    pub fn delete(&mut self, path: &[u8]) -> io::Result<()> {
        self.w.write_all(b"X")?;
        self.bytes(path)
    }
    /// Record symlink `path` pointing at `target`.  Returns any I/O error.
    pub fn symlink(&mut self, path: &[u8], target: &[u8]) -> io::Result<()> {
        self.w.write_all(b"L")?;
        self.bytes(path)?;
        self.bytes(target)
    }
    /// Record regular file `path` with permission bits `mode`, followed by
    /// exactly `size` bytes read from `src`.
    ///
    /// If `src` runs out early (the file shrank after it was stat()ed) the rest
    /// is zero-padded, and extra data is not read, so the stream stays
    /// well-formed whatever happens to the file.  Returns any I/O error.
    pub fn file(&mut self, path: &[u8], mode: u32, size: u64, src: &mut impl Read) -> io::Result<()> {
        self.w.write_all(b"F")?;
        self.bytes(path)?;
        self.w.write_all(&(mode & 0o7777).to_be_bytes())?;
        self.w.write_all(&size.to_be_bytes())?;
        let n = io::copy(&mut src.take(size), &mut self.w)?;
        if n < size {
            io::copy(&mut io::repeat(0).take(size - n), &mut self.w)?;
        }
        Ok(())
    }
    /// Write the end-of-stream marker and flush the writer.  Returns any I/O
    /// error.
    pub fn end(&mut self) -> io::Result<()> {
        self.w.write_all(b"E")?;
        self.w.flush()
    }
}

/// Decoder for the file stream format.
///
/// Call [`StreamReader::next`] for each entry; for a file, optionally call
/// [`StreamReader::data_to`] to consume its data (otherwise the next `next`
/// skips it).  Every path is validated with [`safe_rel_path`], and a bad
/// path or tag is an error, so a hostile stream cannot name anything
/// outside the directory it is extracted into.
pub struct StreamReader<R: Read> {
    r: R,
    pending: u64,
    /// Bytes consumed so far.  Right after `next` returns a file entry, this is
    /// the offset of the file's data in the stream, so callers can later read
    /// the content directly from the stream file.
    pub offset: u64,
}

impl<R: Read> StreamReader<R> {
    /// Start decoding `r`, at offset 0.  Returns the reader.
    pub fn new(r: R) -> Self {
        StreamReader { r, pending: 0, offset: 0 }
    }
    /// Fill `buf` from the stream, advancing `offset`.  Errors on EOF.
    fn exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.r.read_exact(buf)?;
        self.offset += buf.len() as u64;
        Ok(())
    }
    /// Read a big-endian u32.
    fn u32(&mut self) -> io::Result<u32> {
        let mut b = [0u8; 4];
        self.exact(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }
    /// Read a big-endian u64.
    fn u64(&mut self) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.exact(&mut b)?;
        Ok(u64::from_be_bytes(b))
    }
    /// Read a length-prefixed byte string.  Lengths above 4096 are rejected as
    /// corrupt.
    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let n = self.u32()? as usize;
        if n > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "stream: path too long"));
        }
        let mut v = vec![0u8; n];
        self.exact(&mut v)?;
        Ok(v)
    }
    /// Read a length-prefixed path, rejecting it with `InvalidData` unless
    /// [`safe_rel_path`] accepts it.
    fn path(&mut self) -> io::Result<Vec<u8>> {
        let p = self.bytes()?;
        if safe_rel_path(&p).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("stream: unsafe path {:?}", String::from_utf8_lossy(&p)),
            ));
        }
        Ok(p)
    }

    /// Read the next entry header.
    ///
    /// Unread data of the previous file entry is skipped first.  Returns
    /// `Ok(Some(entry))`, or `Ok(None)` at the end marker.  Errors on EOF
    /// before the end marker, an unknown tag, or an unsafe path.
    pub fn next(&mut self) -> io::Result<Option<Entry>> {
        if self.pending > 0 {
            let n = self.pending;
            self.pending = 0;
            let got = io::copy(&mut (&mut self.r).take(n), &mut io::sink())?;
            self.offset += got;
            if got < n {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        let mut tag = [0u8; 1];
        self.exact(&mut tag)?;
        Ok(Some(match tag[0] {
            b'D' => Entry::Dir { path: self.path()?, mode: self.u32()? & 0o7777 },
            b'O' => Entry::Opaque { path: self.path()?, mode: self.u32()? & 0o7777 },
            b'X' => Entry::Delete { path: self.path()? },
            b'L' => Entry::Symlink { path: self.path()?, target: self.bytes()? },
            b'F' => {
                let path = self.path()?;
                let mode = self.u32()? & 0o7777;
                let size = self.u64()?;
                self.pending = size;
                Entry::File { path, mode, size }
            }
            b'E' => return Ok(None),
            t => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("stream: bad tag {t:#x}"),
                ));
            }
        }))
    }

    /// Copy the data of the file entry just returned by `next` into `w`.
    ///
    /// Returns the number of bytes copied (the entry's size); errors if the
    /// stream ends early.  If the last entry was not a file, nothing is copied.
    pub fn data_to(&mut self, w: &mut impl Write) -> io::Result<u64> {
        let n = self.pending;
        self.pending = 0;
        let got = io::copy(&mut (&mut self.r).take(n), w)?;
        self.offset += got;
        if got < n {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(got)
    }
}

/// Encode the host file or directory tree at `src` into stream `sw`, with
/// paths prefixed by `prefix` (e.g. `src` = `~/.claude/commands`, `prefix`
/// = `.claude/commands`).  `prefix` must itself be acceptable to
/// [`safe_rel_path`], or readers will reject the stream.
///
/// Directories are walked in sorted order.  Symlinks are recorded as
/// symlinks, never followed.  Regular files are streamed with their size at
/// stat time.  Anything else is skipped, as are entries that vanish or
/// cannot be opened, and a missing `src` writes nothing.
///
/// Returns an error only if the stream cannot be written or a symlink
/// cannot be read.
pub fn stream_tree<W: Write>(sw: &mut StreamWriter<W>, src: &std::path::Path, prefix: &[u8]) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let md = match std::fs::symlink_metadata(src) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    let ft = md.file_type();
    if ft.is_symlink() {
        let t = std::fs::read_link(src)?;
        sw.symlink(prefix, t.as_os_str().as_bytes())?;
    } else if ft.is_file() {
        if let Ok(mut f) = std::fs::File::open(src) {
            sw.file(prefix, md.permissions().mode(), md.len(), &mut f)?;
        }
    } else if ft.is_dir() {
        sw.dir(prefix, md.permissions().mode())?;
        let mut names: Vec<_> = match std::fs::read_dir(src) {
            Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.file_name()).collect(),
            Err(_) => return Ok(()),
        };
        names.sort();
        for n in names {
            let mut p = prefix.to_vec();
            p.push(b'/');
            p.extend_from_slice(n.as_bytes());
            stream_tree(sw, &src.join(&n), &p)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream from raw parts: each record is a tag and its fields.
    fn raw(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }
    fn s(b: &[u8]) -> Vec<u8> {
        [&(b.len() as u32).to_be_bytes()[..], b].concat()
    }
    fn all(stream: &[u8]) -> io::Result<Vec<Entry>> {
        let mut r = StreamReader::new(stream);
        let mut v = vec![];
        while let Some(e) = r.next()? {
            v.push(e);
        }
        Ok(v)
    }
    fn invalid(stream: &[u8]) -> String {
        let e = all(stream).expect_err("a bad stream is refused");
        format!("{:?} {e}", e.kind())
    }

    #[test]
    fn a_stream_round_trips() {
        let mut w = StreamWriter::new(Vec::new());
        w.dir(b"d", 0o40755).unwrap();
        w.file(b"d/f", 0o104755, 3, &mut &b"abc"[..]).unwrap();
        w.symlink(b"d/l", b"../../anywhere").unwrap();
        w.delete(b"gone").unwrap();
        w.opaque(b"o", 0o700).unwrap();
        w.end().unwrap();
        let mut r = StreamReader::new(&w.w[..]);
        assert_eq!(r.next().unwrap(), Some(Entry::Dir { path: b"d".to_vec(), mode: 0o755 }), "type bits are dropped");
        assert_eq!(r.next().unwrap(), Some(Entry::File { path: b"d/f".to_vec(), mode: 0o4755, size: 3 }));
        let mut data = vec![];
        r.data_to(&mut data).unwrap();
        assert_eq!(data, b"abc");
        assert_eq!(r.next().unwrap(), Some(Entry::Symlink { path: b"d/l".to_vec(), target: b"../../anywhere".to_vec() }));
        assert_eq!(r.next().unwrap(), Some(Entry::Delete { path: b"gone".to_vec() }));
        assert_eq!(r.next().unwrap(), Some(Entry::Opaque { path: b"o".to_vec(), mode: 0o700 }));
        assert_eq!(r.next().unwrap(), None);
    }

    #[test]
    fn unsafe_paths_are_refused_in_every_record() {
        for p in [&b"../x"[..], b"/etc/passwd", b"a/../../b", b"a//b", b"", b"a\0b", b"./a"] {
            let m = 0o644u32.to_be_bytes();
            for rec in [
                raw(&[b"D", &s(p), &m, b"E"]),
                raw(&[b"O", &s(p), &m, b"E"]),
                raw(&[b"X", &s(p), b"E"]),
                raw(&[b"L", &s(p), &s(b"t"), b"E"]),
                raw(&[b"F", &s(p), &m, &0u64.to_be_bytes(), b"E"]),
            ] {
                assert!(invalid(&rec).contains("unsafe path"), "{:?} in {:?}", String::from_utf8_lossy(p), rec[0] as char);
            }
        }
    }

    #[test]
    fn malformed_streams_are_errors_not_panics() {
        let m = 0o644u32.to_be_bytes();
        // no end marker, or cut off anywhere
        let good = raw(&[b"F", &s(b"f"), &m, &3u64.to_be_bytes(), b"abc", b"E"]);
        assert_eq!(all(&good).unwrap().len(), 1);
        for n in 0..good.len() {
            assert!(all(&good[..n]).is_err(), "cut at {n} accepted");
        }
        // an unknown tag
        assert!(invalid(b"Z").contains("bad tag"));
        // a length over the limit, for a path and for a symlink target
        assert!(invalid(&raw(&[b"D", &5000u32.to_be_bytes()])).contains("too long"));
        assert!(invalid(&raw(&[b"L", &s(b"l"), &u32::MAX.to_be_bytes()])).contains("too long"));
        // a file claiming more data than there is: an error, without
        // allocating its size
        assert!(invalid(&raw(&[b"F", &s(b"f"), &m, &u64::MAX.to_be_bytes(), b"abc"])).contains("UnexpectedEof"));
        let huge = raw(&[b"F", &s(b"f"), &m, &u64::MAX.to_be_bytes(), b"abc"]);
        let mut r = StreamReader::new(&huge[..]);
        r.next().unwrap();
        assert!(r.data_to(&mut io::sink()).is_err());
    }

    #[test]
    fn oversized_frames_are_refused() {
        let mut hdr = vec![1u8];
        hdr.extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
        let e = read_frame(&mut &hdr[..]).expect_err("refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let mut buf = vec![];
        write_frame(&mut buf, 7, b"hi").unwrap();
        assert_eq!(read_frame(&mut &buf[..]).unwrap(), (7, b"hi".to_vec()));
        assert!(read_frame(&mut &buf[..buf.len() - 1]).is_err(), "a short frame is an error");
    }
}

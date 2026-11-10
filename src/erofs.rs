//! A minimal EROFS image writer.
//!
//! Every read-only layer handed to the guest (base root, /usr, toolchains,
//! project snapshot) is built with this module rather than `mkfs.erofs`.
//! That avoids a dependency, and lets file data be reflinked straight from
//! the host.
//!
//! Images are uncompressed: extended (64-byte) inodes, every file,
//! directory and symlink stored FLAT_PLAIN (block aligned, no tail packing),
//! no xattrs.  Block alignment means file data can be copied into the image
//! with `copy_file_range()`, which reflinks on btrfs/XFS - snapshotting a
//! large /usr costs metadata, not data.
//!
//! Layout, in 4 KiB blocks:
//!
//! ```text
//! block 0      superblock at byte 1024
//! block 1..    inode table (meta_blkaddr = 1); a nid is the index of a
//!              32-byte slot, and each extended inode takes two slots
//! then         directory and symlink data blocks
//! then         regular file data, each file starting on a block boundary
//! ```
//!
//! Usage: build an in-memory [`Tree`] - by hand with [`Tree::add`] and the
//! [`Node`] constructors, or from a host directory with [`Tree::walk_into`]
//! - then serialise it with [`write_image`].  Hard links within a walked
//! tree are preserved; owner, mode and mtime are kept; xattrs, ACLs and
//! sparse holes are not.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::util::{Context, Excludes, Result};

/// Filesystem block size.  Must not exceed the guest's page size.
const BLKSZ: u64 = 4096;
/// log2 of [`BLKSZ`], as stored in the superblock.
const BLKBITS: u8 = 12;
/// EROFS superblock magic (`EROFS_SUPER_MAGIC_V1`).
const MAGIC: u32 = 0xE0F5_E1E2;
/// nid of the root directory.  The slots before it stay unused so that no
/// inode gets nid 0 (ino 0 is special to some tools).
const FIRST_NID: u64 = 2;
/// Files smaller than this are copied with plain writes rather than
/// `copy_file_range`: a reflink has a fixed per-call cost, and btrfs stores
/// small files inline, where they cannot be reflinked at all.
const REFLINK_MIN: u64 = 64 * 1024;

/// Where a regular file's data comes from when the image is written.
pub enum Content {
    /// Copied from this host file at write time (reflinked when large enough).
    Path(PathBuf),
    /// Held in memory (generated files such as `/etc/passwd`).
    Bytes(Vec<u8>),
}

/// What a [`Node`] is.
pub enum Kind {
    /// Directory: entry name to node index in [`Tree::nodes`].  A `BTreeMap`,
    /// so entries come out sorted, as EROFS requires.
    Dir(BTreeMap<Vec<u8>, usize>),
    /// Regular file: where its data comes from, and its size in bytes.  The
    /// size recorded here is what the inode says, whatever happens to the
    /// source later (see [`copy_into`]).
    File(Content, u64),
    /// Symbolic link with this target.
    Symlink(Vec<u8>),
    /// Device node, FIFO or socket: an inode without data.  Holds the host
    /// `rdev` (meaningful for devices only).
    Special(u64),
}

/// One inode of an image under construction.
pub struct Node {
    /// What the node is, and its content.
    pub kind: Kind,
    /// Full `st_mode`, including the `S_IFMT` type bits.
    pub mode: u32,
    /// Owner uid as stored in the image.
    pub uid: u32,
    /// Owner gid as stored in the image.
    pub gid: u32,
    /// Modification time, seconds since the epoch (negative values are stored
    /// as 0).
    pub mtime: i64,
    /// Nanosecond part of the modification time.
    pub mtime_ns: u32,
}

impl Node {
    /// A new, empty directory node.
    ///
    /// `mode`: permission bits (anything above 0o7777 is ignored; the type bits
    /// are added); `uid`, `gid`: owner.  Returns the node, with mtime 0.
    pub fn dir(mode: u32, uid: u32, gid: u32) -> Node {
        Node { kind: Kind::Dir(BTreeMap::new()), mode: libc::S_IFDIR | (mode & 0o7777), uid, gid, mtime: 0, mtime_ns: 0 }
    }
    /// A regular file node whose contents are `data`.
    ///
    /// `mode`: permission bits; `uid`, `gid`: owner.  Returns the node, with
    /// mtime 0.
    pub fn bytes(data: Vec<u8>, mode: u32, uid: u32, gid: u32) -> Node {
        let n = data.len() as u64;
        Node { kind: Kind::File(Content::Bytes(data), n), mode: libc::S_IFREG | (mode & 0o7777), uid, gid, mtime: 0, mtime_ns: 0 }
    }
    /// A symlink node pointing at `target`, which is stored verbatim.  Mode
    /// 0777, owned by `uid`:`gid`, mtime 0.  Returns the node.
    pub fn symlink(target: &[u8], uid: u32, gid: u32) -> Node {
        Node { kind: Kind::Symlink(target.to_vec()), mode: libc::S_IFLNK | 0o777, uid, gid, mtime: 0, mtime_ns: 0 }
    }
}

/// One entry of the manifest recorded while walking a tree.
///
/// It is used twice: hashed into the cache key of a project snapshot, and
/// saved with the session as `manifest.json`, so that at review time
/// agentcracker can tell what the agent changed and whether the host
/// changed the same entry after the snapshot was taken.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq)]
pub struct ManifestEntry {
    /// Path relative to the walk root, lossily converted to UTF-8 (for display
    /// and keys only; use `raw` to touch the file).
    pub path: String,
    /// Exact path bytes relative to the walk root.  Serialised as hex so that
    /// names which are not UTF-8 survive JSON.
    #[serde(with = "serde_bytes_hex")]
    pub raw: Vec<u8>,
    /// Full `st_mode` at snapshot time.
    pub mode: u32,
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// Modification time in nanoseconds since the epoch.
    pub mtime_ns: i128,
    /// Inode number.  Catches edits that replace a file by renaming a new one
    /// over it while keeping size and mtime.
    pub ino: u64,
}

const MANIFEST_MAGIC: &[u8; 8] = b"ACMANIF1";

/// Write `m` to `path` in a compact binary form (JSON for a 100k-file tree
/// costs a quarter of a second to write and more to read back).
pub fn write_manifest(path: &Path, m: &[ManifestEntry]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut w = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&tmp)?);
    w.write_all(MANIFEST_MAGIC)?;
    w.write_all(&(m.len() as u64).to_le_bytes())?;
    for e in m {
        w.write_all(&(e.raw.len() as u32).to_le_bytes())?;
        w.write_all(&e.raw)?;
        w.write_all(&e.mode.to_le_bytes())?;
        w.write_all(&e.size.to_le_bytes())?;
        w.write_all(&(e.mtime_ns as i64).to_le_bytes())?;
        w.write_all(&e.ino.to_le_bytes())?;
    }
    w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Read a manifest written by [`write_manifest`].
pub fn read_manifest(path: &Path) -> std::io::Result<Vec<ManifestEntry>> {
    let d = std::fs::read(path)?;
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt manifest");
    if d.len() < 16 || &d[..8] != MANIFEST_MAGIC {
        return Err(bad());
    }
    let take = |at: &mut usize, n: usize| -> std::io::Result<&[u8]> {
        let s = d.get(*at..*at + n).ok_or_else(bad)?;
        *at += n;
        Ok(s)
    };
    let mut at = 8;
    let n = u64::from_le_bytes(take(&mut at, 8)?.try_into().unwrap()) as usize;
    let mut v = Vec::with_capacity(n.min(1 << 24));
    for _ in 0..n {
        let len = u32::from_le_bytes(take(&mut at, 4)?.try_into().unwrap()) as usize;
        let raw = take(&mut at, len)?.to_vec();
        let mode = u32::from_le_bytes(take(&mut at, 4)?.try_into().unwrap());
        let size = u64::from_le_bytes(take(&mut at, 8)?.try_into().unwrap());
        let mtime_ns = i64::from_le_bytes(take(&mut at, 8)?.try_into().unwrap()) as i128;
        let ino = u64::from_le_bytes(take(&mut at, 8)?.try_into().unwrap());
        v.push(ManifestEntry { path: String::from_utf8_lossy(&raw).into_owned(), raw, mode, size, mtime_ns, ino });
    }
    Ok(v)
}

/// Serde helpers that store a byte vector as a lowercase hex string.
mod serde_bytes_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    /// Serialise `v` as a hex string with serializer `s`.  Returns the
    /// serializer's result.
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let h: String = v.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&h)
    }
    /// Parse a hex string from deserializer `d` back into bytes.  Returns the
    /// bytes, or an error for a non-hex digit; an odd trailing digit is
    /// ignored.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// An in-memory directory tree, to be written as an image.
///
/// Nodes live in a flat vector and refer to each other by index; index 0 is
/// the root directory.  A node may be the child of several directories
/// (hard links).
pub struct Tree {
    /// All nodes; index 0 is the root.
    pub nodes: Vec<Node>,
}

/// Counters from [`Tree::walk_into`], for status messages.
#[derive(Default, Debug)]
pub struct WalkStats {
    /// Regular files added (hard links counted once).
    pub files: u64,
    /// Their total size in bytes.
    pub bytes: u64,
    /// Paths left out because they could not be read (permission denied, or
    /// gone by the time they were reached).
    pub skipped: Vec<PathBuf>,
}

impl Tree {
    /// A tree containing only a root directory, with permission bits `mode`,
    /// owned by `uid`:`gid`.  Returns the tree.
    pub fn new(mode: u32, uid: u32, gid: u32) -> Tree {
        Tree { nodes: vec![Node::dir(mode, uid, gid)] }
    }

    /// Add `node` to the tree as entry `name` of directory `parent`.
    ///
    /// `parent`: index of a directory node (if it is not a directory, the node
    /// is still stored but unreachable); `name`: the entry name, which must not
    /// contain `/`.  An existing entry with the same name is replaced in the
    /// directory; its node stays in the vector, unreferenced.
    ///
    /// Returns the new node's index.
    pub fn add(&mut self, parent: usize, name: &[u8], node: Node) -> usize {
        let id = self.nodes.len();
        self.nodes.push(node);
        if let Kind::Dir(ch) = &mut self.nodes[parent].kind {
            ch.insert(name.to_vec(), id);
        }
        id
    }

    /// Look up entry `name` in directory `parent`.
    ///
    /// Returns the entry's node index, or `None` if there is no such entry or
    /// `parent` is not a directory.
    pub fn child(&self, parent: usize, name: &[u8]) -> Option<usize> {
        match &self.nodes[parent].kind {
            Kind::Dir(ch) => ch.get(name).copied(),
            _ => None,
        }
    }

    /// Create (or find) the directory chain `path` below the root, like
    /// `mkdir -p`.  See [`Tree::mkdir_p_at`] for the parameters and result.
    pub fn mkdir_p(&mut self, path: &Path, mode: u32, uid: u32, gid: u32) -> usize {
        self.mkdir_p_at(0, path, mode, uid, gid)
    }

    /// Create (or find) the directory chain `path` below node `at`, like
    /// `mkdir -p`.
    ///
    /// `path`: relative path (a leading `/` is ignored).  Directories created
    /// on the way get permission bits `mode` and owner `uid`:`gid`; existing
    /// ones are left unchanged.  If an existing entry on the way is not a
    /// directory, what is created beneath it is unreachable - callers only use
    /// this on trees they built themselves.
    ///
    /// Returns the index of the last directory of the chain (`at` itself for an
    /// empty path).
    pub fn mkdir_p_at(&mut self, at: usize, path: &Path, mode: u32, uid: u32, gid: u32) -> usize {
        let mut cur = at;
        for c in path.components() {
            let name = c.as_os_str().as_bytes();
            if name == b"/" || name.is_empty() {
                continue;
            }
            cur = match self.child(cur, name) {
                Some(n) => n,
                None => self.add(cur, name, Node::dir(mode, uid, gid)),
            };
        }
        cur
    }

    /// Recursively add the host directory `src` to the tree, attached at node `at`.
    ///
    /// `at` (normally a freshly added directory) takes `src`'s own mode, owner
    /// and mtime.  Beneath it every entry is added with its host metadata:
    /// directories; symlinks, with their target copied verbatim; regular files,
    /// by path (their data is read later, by [`write_image`]); and FIFOs,
    /// sockets and devices, as inodes only.  Hard links within the walk become
    /// one node.  Symlinks are never followed.
    ///
    /// - `excludes`: entries matching it (by path relative to `src`) are
    ///   skipped, together with everything beneath them.
    /// - `owner`: `Some((uid, gid))` forces that owner on every node (used for
    ///   `/etc`, which is root-owned in the guest); `None` keeps host owners.
    /// - `manifest`: if given, gets a [`ManifestEntry`] for every entry that is
    ///   not excluded (but not for `src` itself), in walk order.
    /// - `stats`: updated with file counts and with the paths skipped because
    ///   they could not be read; unreadable entries are skipped, not fatal.
    ///
    /// Returns an error only if `src` itself cannot be stat()ed.
    pub fn walk_into(
        &mut self,
        at: usize,
        src: &Path,
        excludes: &Excludes,
        owner: Option<(u32, u32)>,
        mut manifest: Option<&mut Vec<ManifestEntry>>,
        stats: &mut WalkStats,
    ) -> Result<()> {
        let md = std::fs::metadata(src).ctx(format!("stat {}", src.display()))?;
        // the attachment point takes the source dir's attributes
        {
            let n = &mut self.nodes[at];
            n.mode = libc::S_IFDIR | (md.mode() & 0o7777);
            let (u, g) = owner.unwrap_or((md.uid(), md.gid()));
            n.uid = u;
            n.gid = g;
            n.mtime = md.mtime();
            n.mtime_ns = md.mtime_nsec() as u32;
        }
        // stat everything in parallel, then build the tree in sorted path
        // order so that node order, hard-link resolution and the manifest
        // (whose hash is a cache key) never depend on thread timing
        let mut scans = scan_parallel(src, excludes);
        scans.sort_by(|a, b| a.rel.as_os_str().as_bytes().cmp(b.rel.as_os_str().as_bytes()));
        let mut dir_ids: HashMap<PathBuf, usize> = HashMap::new();
        dir_ids.insert(PathBuf::new(), at);
        let mut links: HashMap<(u64, u64), usize> = HashMap::new();
        for scan in scans {
            if scan.unreadable {
                stats.skipped.push(src.join(&scan.rel));
                continue;
            }
            let Some(&dir_node) = dir_ids.get(&scan.rel) else { continue };
            for e in scan.entries {
                let relp = scan.rel.join(&e.name);
                let path = src.join(&relp);
                let Some(md) = e.md else {
                    stats.skipped.push(path);
                    continue;
                };
                let ft = md.file_type();
                let (uid, gid) = owner.unwrap_or((md.uid(), md.gid()));
                let mode = md.mode();
                let mk = |kind| Node { kind, mode, uid, gid, mtime: md.mtime(), mtime_ns: md.mtime_nsec() as u32 };
                if let Some(m) = manifest.as_deref_mut() {
                    m.push(ManifestEntry {
                        path: relp.to_string_lossy().into_owned(),
                        raw: relp.as_os_str().as_bytes().to_vec(),
                        mode,
                        size: if ft.is_dir() { 0 } else { md.size() },
                        mtime_ns: md.mtime() as i128 * 1_000_000_000 + md.mtime_nsec() as i128,
                        ino: md.ino(),
                    });
                }
                let nb = e.name.as_bytes();
                if ft.is_dir() {
                    let id = self.add(dir_node, nb, mk(Kind::Dir(BTreeMap::new())));
                    dir_ids.insert(relp, id);
                } else if ft.is_symlink() {
                    self.add(dir_node, nb, mk(Kind::Symlink(e.link.unwrap_or_default())));
                } else if ft.is_file() {
                    if md.nlink() > 1 {
                        if let Some(&id) = links.get(&(md.dev(), md.ino())) {
                            if let Kind::Dir(ch) = &mut self.nodes[dir_node].kind {
                                ch.insert(nb.to_vec(), id);
                            }
                            continue;
                        }
                    }
                    if !e.readable {
                        stats.skipped.push(path);
                        continue;
                    }
                    stats.files += 1;
                    stats.bytes += md.size();
                    let id = self.add(dir_node, nb, mk(Kind::File(Content::Path(path), md.size())));
                    if md.nlink() > 1 {
                        links.insert((md.dev(), md.ino()), id);
                    }
                } else {
                    // fifos, sockets, device nodes: keep the inode, no data
                    self.add(dir_node, nb, mk(Kind::Special(md.rdev())));
                }
            }
        }
        Ok(())
    }
}

impl Tree {
    /// A copy of this tree holding only the entries whose paths (relative
    /// to the root) are in `keep`, plus the directories leading to them,
    /// with their attributes.  Kept directories bring their attributes, not
    /// their contents.  Each path in `whiteouts` becomes an overlayfs
    /// whiteout (a 0:0 character device) in its parent directory, which must
    /// exist in this tree.
    ///
    /// Used for a project delta layer: stacked over an older snapshot it
    /// yields the current tree.
    pub fn subset(&self, keep: &HashSet<Vec<u8>>, whiteouts: &[Vec<u8>]) -> Tree {
        // every proper ancestor of a wanted path must be present
        let mut want: HashSet<&[u8]> = HashSet::new();
        for p in keep.iter().chain(whiteouts.iter()) {
            let mut end = p.len();
            while let Some(i) = p[..end].iter().rposition(|&b| b == b'/') {
                if !want.insert(&p[..i]) {
                    break;
                }
                end = i;
            }
        }
        let root = &self.nodes[0];
        let mut out = Tree { nodes: vec![Node { kind: Kind::Dir(BTreeMap::new()), ..root.clone_attrs() }] };
        let mut stack: Vec<(usize, usize, Vec<u8>)> = vec![(0, 0, Vec::new())];
        let mut by_path: HashMap<Vec<u8>, usize> = HashMap::new();
        by_path.insert(Vec::new(), 0);
        while let Some((src, dst, rel)) = stack.pop() {
            let Kind::Dir(ch) = &self.nodes[src].kind else { continue };
            for (name, &id) in ch {
                let mut p = rel.clone();
                if !p.is_empty() {
                    p.push(b'/');
                }
                p.extend_from_slice(name);
                let kept = keep.contains(&p);
                let is_dir = matches!(self.nodes[id].kind, Kind::Dir(_));
                if !kept && !(is_dir && want.contains(p.as_slice())) {
                    continue;
                }
                let n = &self.nodes[id];
                let node = match &n.kind {
                    Kind::Dir(_) => Node { kind: Kind::Dir(BTreeMap::new()), ..n.clone_attrs() },
                    Kind::File(Content::Path(pp), sz) => Node { kind: Kind::File(Content::Path(pp.clone()), *sz), ..n.clone_attrs() },
                    Kind::File(Content::Bytes(b), sz) => Node { kind: Kind::File(Content::Bytes(b.clone()), *sz), ..n.clone_attrs() },
                    Kind::Symlink(t) => Node { kind: Kind::Symlink(t.clone()), ..n.clone_attrs() },
                    Kind::Special(r) => Node { kind: Kind::Special(*r), ..n.clone_attrs() },
                };
                let nid = out.add(dst, name, node);
                if is_dir {
                    by_path.insert(p.clone(), nid);
                    stack.push((id, nid, p));
                }
            }
        }
        for w in whiteouts {
            let (parent, name) = match w.iter().rposition(|&b| b == b'/') {
                Some(i) => (&w[..i], &w[i + 1..]),
                None => (&w[..0], &w[..]),
            };
            if let Some(&pid) = by_path.get(parent) {
                out.add(pid, name, Node { kind: Kind::Special(0), mode: libc::S_IFCHR, uid: 0, gid: 0, mtime: 0, mtime_ns: 0 });
            }
        }
        out
    }
}

impl Node {
    /// This node's attributes with a placeholder kind (to be replaced).
    fn clone_attrs(&self) -> Node {
        Node { kind: Kind::Special(0), mode: self.mode, uid: self.uid, gid: self.gid, mtime: self.mtime, mtime_ns: self.mtime_ns }
    }
}

/// One directory as seen by [`scan_parallel`].
struct DirScan {
    /// Path relative to the scan root ("" for the root).
    rel: PathBuf,
    /// The directory could not be listed.
    unreadable: bool,
    /// Its entries (excluded ones left out), sorted by name.
    entries: Vec<ScanEntry>,
}

struct ScanEntry {
    name: std::ffi::OsString,
    /// `None` when the entry vanished or could not be stat()ed.
    md: Option<std::fs::Metadata>,
    /// Symlink target.
    link: Option<Vec<u8>>,
    /// For regular files: can we open it for reading?
    readable: bool,
}

/// List and lstat every directory under `root` (minus `excludes`) using a
/// few threads; on large trees this is most of the cost of a snapshot.
fn scan_parallel(root: &Path, excludes: &Excludes) -> Vec<DirScan> {
    use std::sync::{Condvar, Mutex};
    struct Q {
        todo: Vec<PathBuf>,
        busy: usize,
        out: Vec<DirScan>,
    }
    let q = Mutex::new(Q { todo: vec![PathBuf::new()], busy: 0, out: Vec::new() });
    let cv = Condvar::new();
    let euid = unsafe { libc::geteuid() };
    // files we own with the owner read bit set (nearly all of a project)
    // need no access() call; for the rest group membership, ACLs and root
    // make the mode bits inconclusive, so ask the kernel
    let readable = |path: &Path, md: &std::fs::Metadata| -> bool {
        if md.uid() == euid && md.mode() & 0o400 != 0 {
            return true;
        }
        let c = cstr_path(path);
        unsafe { libc::access(c.as_ptr(), libc::R_OK) == 0 }
    };
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 8);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let rel = {
                    let mut g = q.lock().unwrap();
                    loop {
                        if let Some(r) = g.todo.pop() {
                            g.busy += 1;
                            break r;
                        }
                        if g.busy == 0 {
                            cv.notify_all();
                            return;
                        }
                        g = cv.wait(g).unwrap();
                    }
                };
                let dir = root.join(&rel);
                let mut scan = DirScan { rel: rel.clone(), unreadable: false, entries: Vec::new() };
                let mut subdirs = Vec::new();
                match std::fs::read_dir(&dir) {
                    Err(_) => scan.unreadable = true,
                    Ok(rd) => {
                        for ent in rd.filter_map(|e| e.ok()) {
                            let name = ent.file_name();
                            let path = dir.join(&name);
                            let relp = rel.join(&name);
                            let md = std::fs::symlink_metadata(&path).ok();
                            if let Some(md) = &md {
                                if excludes.matches(&relp, md.is_dir()) {
                                    continue;
                                }
                            }
                            let mut e = ScanEntry { name, md, link: None, readable: false };
                            if let Some(md) = &e.md {
                                let ft = md.file_type();
                                if ft.is_dir() {
                                    subdirs.push(relp);
                                } else if ft.is_symlink() {
                                    e.link = std::fs::read_link(&path).ok().map(|t| t.as_os_str().as_bytes().to_vec());
                                } else if ft.is_file() {
                                    e.readable = readable(&path, md);
                                }
                            }
                            scan.entries.push(e);
                        }
                    }
                }
                scan.entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
                let mut g = q.lock().unwrap();
                g.todo.extend(subdirs);
                g.out.push(scan);
                g.busy -= 1;
                cv.notify_all();
            });
        }
    });
    q.into_inner().unwrap().out
}

/// Convert path `p` into a C string for a libc call; see [`crate::util::cstr`].
fn cstr_path(p: &Path) -> std::ffi::CString {
    crate::util::cstr(p.as_os_str())
}

/// Map an `st_mode` to the file type code stored in EROFS directory
/// entries (1 regular, 2 directory, 3 char device, 4 block device, 5 FIFO,
/// 6 socket, 7 symlink; 0 unknown).
///
/// `mode`: full mode, including type bits.  Returns the code.
fn file_type(mode: u32) -> u8 {
    match mode & libc::S_IFMT {
        libc::S_IFREG => 1,
        libc::S_IFDIR => 2,
        libc::S_IFCHR => 3,
        libc::S_IFBLK => 4,
        libc::S_IFIFO => 5,
        libc::S_IFSOCK => 6,
        libc::S_IFLNK => 7,
        _ => 0,
    }
}

/// Encode a host `dev_t` in the kernel's 32-bit "new" format
/// (`new_encode_dev()` in `include/linux/kdev_t.h`), which is what EROFS
/// stores for device inodes.
///
/// `dev`: the host device number.  Returns the encoded value.
fn new_encode_dev(dev: u64) -> u32 {
    let major = libc::major(dev) as u32;
    let minor = libc::minor(dev) as u32;
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

/// Returns the number of [`BLKSZ`] blocks needed for `n` bytes, rounded up
/// (0 for 0).
fn blocks(n: u64) -> u64 {
    n.div_ceil(BLKSZ)
}

/// Serialise directory entries into EROFS directory blocks.
///
/// `entries`: `(name, nid, file type)` triples, sorted by name and
/// including `.` and `..`.  Each block holds a run of 12-byte dirents
/// followed by their names.  An entry never straddles two blocks, and the
/// last name in a block runs to the first NUL or the end of the block,
/// which is why the unused tail of each block is zero-filled.
///
/// Returns the blocks, concatenated (a multiple of [`BLKSZ`] bytes).
fn dir_blocks(entries: &[(Vec<u8>, u64, u8)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        // how many fit in this block
        let mut used = 0usize;
        let mut j = i;
        while j < entries.len() && used + 12 + entries[j].0.len() <= BLKSZ as usize {
            used += 12 + entries[j].0.len();
            j += 1;
        }
        let blk_start = out.len();
        out.resize(blk_start + BLKSZ as usize, 0);
        let n = j - i;
        let mut nameoff = 12 * n;
        for (k, (name, nid, ft)) in entries[i..j].iter().enumerate() {
            let d = blk_start + 12 * k;
            out[d..d + 8].copy_from_slice(&nid.to_le_bytes());
            out[d + 8..d + 10].copy_from_slice(&(nameoff as u16).to_le_bytes());
            out[d + 10] = *ft;
            out[blk_start + nameoff..blk_start + nameoff + name.len()].copy_from_slice(name);
            nameoff += name.len();
        }
        i = j;
    }
    out
}

/// The error for a tree over EROFS's 2^32 blocks (16 TiB): its total size
/// and its largest files, by apparent size - a project holding sparse disk
/// images (a VM's, or kept test sessions) gets there long before its disk
/// usage does.
fn too_large(tree: &Tree, order: &[usize]) -> String {
    use crate::util::human_bytes;
    // each node's (parent, name), to spell out paths
    let mut up: Vec<Option<(usize, &[u8])>> = vec![None; tree.nodes.len()];
    for &d in order {
        if let Kind::Dir(ch) = &tree.nodes[d].kind {
            for (name, &c) in ch {
                up[c].get_or_insert((d, name.as_slice()));
            }
        }
    }
    let path = |mut i: usize| {
        let mut parts = Vec::new();
        while let Some((p, name)) = up[i] {
            parts.push(crate::util::safe_text(name, false));
            i = p;
        }
        parts.reverse();
        parts.join("/")
    };
    let mut files: Vec<(u64, usize)> = order
        .iter()
        .filter_map(|&i| match &tree.nodes[i].kind {
            Kind::File(_, size) => Some((*size, i)),
            _ => None,
        })
        .collect();
    let total: u64 = files.iter().map(|f| f.0).sum();
    files.sort_unstable_by(|a, b| b.cmp(a));
    let largest: Vec<String> = files.iter().take(3).map(|&(size, i)| format!("{} {}", path(i), human_bytes(size))).collect();
    format!(
        "image too large: its files add up to {} (apparent size, sparse files at their full length; the limit is 16T); largest: {}",
        human_bytes(total),
        largest.join(", ")
    )
}

/// Write `tree` as an EROFS image at `out`, atomically.
///
/// Steps: assign nids breadth-first from the root (so the entries of a
/// directory sit close together); compute link counts; lay out directory
/// and symlink blocks, then file data; build the inode table and the
/// superblock; and write it all to a temporary file next to `out`, which is
/// renamed into place at the end.  On any error the temporary file is
/// removed and `out` is left untouched.
///
/// File data is written in two phases: large files are reflinked first, in
/// offset order (interleaving clones with dirty pages of the same file makes
/// btrfs flush on every clone), then everything else - superblock, inodes,
/// directories, small files - with ordinary writes from up to 8 threads.
/// Data that can no longer be read (the file vanished or shrank since the
/// walk) is left as zeros rather than failing the image.
///
/// Returns the image size in bytes.  Errors on I/O failure, or if the image
/// would need more than 2^32 blocks (16 TiB).
pub fn write_image(tree: &Tree, out: &Path) -> Result<u64> {
    let n_nodes = tree.nodes.len();
    // 1. assign nids in BFS order; count links; find parents of directories
    let mut nid = vec![u64::MAX; n_nodes];
    let mut nlink = vec![0u32; n_nodes];
    let mut parent = vec![0usize; n_nodes];
    let mut order = Vec::with_capacity(n_nodes);
    let mut q = VecDeque::from([0usize]);
    nid[0] = FIRST_NID;
    order.push(0);
    while let Some(d) = q.pop_front() {
        if let Kind::Dir(ch) = &tree.nodes[d].kind {
            for &c in ch.values() {
                nlink[c] += 1;
                if nid[c] == u64::MAX {
                    nid[c] = FIRST_NID + 2 * order.len() as u64;
                    order.push(c);
                    if matches!(tree.nodes[c].kind, Kind::Dir(_)) {
                        parent[c] = d;
                        q.push_back(c);
                    }
                }
            }
        }
    }
    for &i in &order {
        if let Kind::Dir(ch) = &tree.nodes[i].kind {
            let subdirs = ch.values().filter(|&&c| matches!(tree.nodes[c].kind, Kind::Dir(_))).count();
            nlink[i] = 2 + subdirs as u32;
        }
    }
    let total_slots = FIRST_NID + 2 * order.len() as u64;
    let meta_blocks = blocks(total_slots * 32);
    let mut next_blk = 1 + meta_blocks;

    // 2. directory + symlink payloads, then file data
    let mut blkaddr = vec![0u32; n_nodes];
    let mut isize = vec![0u64; n_nodes];
    let mut small: Vec<(u64, Vec<u8>)> = Vec::new(); // (byte offset, data)
    for &i in &order {
        match &tree.nodes[i].kind {
            Kind::Dir(ch) => {
                let mut ents: Vec<(Vec<u8>, u64, u8)> = Vec::with_capacity(ch.len() + 2);
                ents.push((b".".to_vec(), nid[i], 2));
                ents.push((b"..".to_vec(), nid[parent[i]], 2));
                for (name, &c) in ch {
                    ents.push((name.clone(), nid[c], file_type(tree.nodes[c].mode)));
                }
                ents.sort_by(|a, b| a.0.cmp(&b.0));
                let data = dir_blocks(&ents);
                blkaddr[i] = next_blk as u32;
                isize[i] = data.len() as u64;
                next_blk += blocks(data.len() as u64);
                small.push((blkaddr[i] as u64 * BLKSZ, data));
            }
            Kind::Symlink(t) => {
                blkaddr[i] = next_blk as u32;
                isize[i] = t.len() as u64;
                next_blk += blocks(t.len() as u64).max(1);
                small.push((blkaddr[i] as u64 * BLKSZ, t.clone()));
            }
            _ => {}
        }
    }
    let mut files: Vec<usize> = Vec::new();
    for &i in &order {
        if let Kind::File(_, size) = &tree.nodes[i].kind {
            isize[i] = *size;
            if *size > 0 {
                blkaddr[i] = next_blk as u32;
                next_blk += blocks(*size);
                files.push(i);
            }
        }
    }
    if next_blk > u32::MAX as u64 {
        crate::bail!("{}", too_large(tree, &order));
    }

    // 3. inode table
    let mut meta = vec![0u8; (meta_blocks * BLKSZ) as usize];
    for (idx, &i) in order.iter().enumerate() {
        let n = &tree.nodes[i];
        let off = ((FIRST_NID + 2 * idx as u64) * 32) as usize;
        let ino = &mut meta[off..off + 64];
        ino[0..2].copy_from_slice(&1u16.to_le_bytes()); // extended, FLAT_PLAIN
        ino[4..6].copy_from_slice(&(n.mode as u16).to_le_bytes());
        ino[8..16].copy_from_slice(&isize[i].to_le_bytes());
        let iu = match n.kind {
            Kind::Special(rdev) => new_encode_dev(rdev),
            _ => blkaddr[i],
        };
        ino[16..20].copy_from_slice(&iu.to_le_bytes());
        ino[20..24].copy_from_slice(&(idx as u32 + 1).to_le_bytes());
        ino[24..28].copy_from_slice(&n.uid.to_le_bytes());
        ino[28..32].copy_from_slice(&n.gid.to_le_bytes());
        ino[32..40].copy_from_slice(&(n.mtime.max(0) as u64).to_le_bytes());
        ino[40..44].copy_from_slice(&n.mtime_ns.to_le_bytes());
        ino[44..48].copy_from_slice(&nlink[i].max(1).to_le_bytes());
    }

    // 4. superblock
    let mut sb = [0u8; 128];
    sb[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    sb[12] = BLKBITS;
    sb[14..16].copy_from_slice(&(FIRST_NID as u16).to_le_bytes());
    sb[16..24].copy_from_slice(&(order.len() as u64).to_le_bytes());
    sb[24..32].copy_from_slice(&crate::util::now().to_le_bytes());
    sb[36..40].copy_from_slice(&(next_blk as u32).to_le_bytes());
    sb[40..44].copy_from_slice(&1u32.to_le_bytes()); // meta_blkaddr
    let uuid = crate::util::random_hex(16);
    for k in 0..16 {
        sb[48 + k] = u8::from_str_radix(&uuid[2 * k..2 * k + 2], 16).unwrap_or(0);
    }
    sb[64..75].copy_from_slice(b"agentcrackr");

    // 5. write it out
    let tmp = out.with_extension(format!("tmp{}", std::process::id()));
    let f = File::create(&tmp).ctx(format!("create {}", tmp.display()))?;
    let res = (|| -> Result<()> {
        // Phase 1: reflink large files, in offset order, before any buffered
        // write: interleaving clones with dirty pages in the same file makes
        // btrfs flush on every clone.
        let (big, rest): (Vec<usize>, Vec<usize>) = files.iter().partition(|&&i| {
            matches!(&tree.nodes[i].kind, Kind::File(Content::Path(_), size) if *size >= REFLINK_MIN)
        });
        for &i in &big {
            let Kind::File(Content::Path(p), size) = &tree.nodes[i].kind else { continue };
            copy_into(&f, p, blkaddr[i] as u64 * BLKSZ, *size)?;
        }
        // Phase 2: everything else as plain writes, spread over a few threads.
        f.write_all_at(&sb, 1024)?;
        f.write_all_at(&meta, BLKSZ)?;
        for (off, data) in &small {
            f.write_all_at(data, *off)?;
        }
        let nthreads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(8);
        let chunk = rest.len().div_ceil(nthreads).max(1);
        let errors: Vec<String> = std::thread::scope(|sc| {
            let hs: Vec<_> = rest
                .chunks(chunk)
                .map(|part| {
                    let f = &f;
                    let blkaddr = &blkaddr;
                    sc.spawn(move || -> Result<()> {
                        for &i in part {
                            let Kind::File(content, size) = &tree.nodes[i].kind else { continue };
                            let off = blkaddr[i] as u64 * BLKSZ;
                            match content {
                                Content::Bytes(b) => f.write_all_at(b, off)?,
                                Content::Path(p) => copy_into(f, p, off, *size)?,
                            }
                        }
                        Ok(())
                    })
                })
                .collect();
            hs.into_iter().filter_map(|h| h.join().ok().and_then(|r| r.err()).map(|e| e.0)).collect()
        });
        if let Some(e) = errors.into_iter().next() {
            crate::bail!("{e}");
        }
        f.set_len(next_blk * BLKSZ)?;
        Ok(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(f);
    std::fs::rename(&tmp, out).ctx(format!("rename {}", out.display()))?;
    Ok(next_blk * BLKSZ)
}

/// Copy `size` bytes of host file `src` into `dst` at byte offset `off`.
///
/// Files of at least [`REFLINK_MIN`] bytes go through `copy_file_range(2)`,
/// which shares extents (a reflink) on btrfs and XFS when source and
/// destination are on the same filesystem and the offsets are block
/// aligned.  Where it is unsupported (other filesystems, across
/// filesystems, old kernels) the copy continues with [`copy_slow`] from
/// where it stopped.  Smaller files always use plain reads and writes.
///
/// If `src` can no longer be opened, or is shorter than `size`, the missing
/// bytes are left as a hole (zeros): the inode already records `size`, so
/// the image stays consistent.
///
/// Returns an error only for real I/O failures.
fn copy_into(dst: &File, src: &Path, off: u64, size: u64) -> Result<()> {
    let s = match File::open(src) {
        Ok(f) => f,
        Err(_) => return Ok(()), // vanished/unreadable since the walk: zeros
    };
    // Reflinking has a per-call cost (and btrfs keeps small files inline,
    // where it cannot reflink at all): plain copies win for small files.
    if size < REFLINK_MIN {
        return copy_slow(&s, dst, 0, off, size);
    }
    let mut src_off: i64 = 0;
    let mut dst_off: i64 = off as i64;
    let mut left = size;
    while left > 0 {
        let n = unsafe {
            libc::copy_file_range(
                s.as_raw_fd(),
                &mut src_off,
                dst.as_raw_fd(),
                &mut dst_off,
                left.min(1 << 30) as usize,
                0,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EXDEV) | Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {
                    return copy_slow(&s, dst, src_off as u64, dst_off as u64, left);
                }
                Some(libc::EINTR) => continue,
                _ => return Err(e.into()),
            }
        }
        if n == 0 {
            break;
        }
        left -= n as u64;
    }
    Ok(())
}

/// Copy up to `left` bytes from `s` at offset `so` to `d` at offset `doff`,
/// with positioned reads and writes through a buffer of up to 1 MiB.
///
/// Stops early, without error, at the end of the source file.  Returns an
/// error on an I/O failure.
fn copy_slow(s: &File, d: &File, mut so: u64, mut doff: u64, mut left: u64) -> Result<()> {
    let mut buf = vec![0u8; left.min(1 << 20) as usize];
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n = s.read_at(&mut buf[..want], so)?;
        if n == 0 {
            break;
        }
        d.write_all_at(&buf[..n], doff)?;
        so += n as u64;
        doff += n as u64;
        left -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_image_too_large_names_its_largest_files() {
        let mut t = Tree::new(0o755, 0, 0);
        let d = t.mkdir_p(Path::new("build/tests"), 0o755, 0, 0);
        let sparse = |n: u64| Node { kind: Kind::File(Content::Path("/nonexistent".into()), n), ..Node::bytes(vec![], 0o644, 0, 0) };
        for i in 0..300 {
            t.add(d, format!("scratch{i}.img").as_bytes(), sparse(64 << 30));
        }
        t.add(0, b"small", Node::bytes(b"x".to_vec(), 0o644, 0, 0));
        let out = std::env::temp_dir().join(format!("acr-erofs-test-{}.img", std::process::id()));
        let e = write_image(&t, &out).err().expect("an image over 16T is refused").0;
        assert!(e.contains("add up to 19T"), "{e}");
        assert!(e.contains("largest: build/tests/scratch"), "{e}");
        assert!(!out.exists());
    }
}

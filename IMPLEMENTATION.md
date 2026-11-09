# agentcracker implementation guide

This document describes how agentcracker works today, as code: the pieces,
how a session flows through them, the formats they share, where the
security boundaries are, and a guide to the source files.  `README.md`
covers the design, its rationale and the alternatives considered.  This
file covers the mechanics.

Every source file opens with a module comment, and every function, type
and constant has a doc comment covering its behaviour, parameters and
return value.  To browse them as HTML:

```
cargo doc --document-private-items --open
```

## Contents

1. [The pieces](#1-the-pieces)
2. [Building and installing](#2-building-and-installing)
3. [The life of a session](#3-the-life-of-a-session)
4. [Files on disk](#4-files-on-disk)
5. [Protocol and stream formats](#5-protocol-and-stream-formats)
6. [Security boundaries](#6-security-boundaries)
7. [Source guide](#7-source-guide)
8. [Tests](#8-tests)
9. [Debugging and development aids](#9-debugging-and-development-aids)
10. [Making changes](#10-making-changes)

## 1. The pieces

```
 host                                             guest (Firecracker microVM)
 ----------------------------------------------   --------------------------------------
 agentcracker (src/cli.rs ...)                     /acinit = agentcracker, static (src/guest.rs)
   config, session store, image cache                mounts images, builds overlays
   firecracker --no-api --config-file ...            chroots, runs the command in a pty
   control connection   <==== vsock 1024 ====>       config, seed, terminal, export
   egress proxy         <==== vsock 1025 ====>       127.0.0.1:3128 relay (HTTPS_PROXY)
   review / apply / branch

 block devices:  vda base.img (ro, root)   vdb usr.img (ro)   vdc tools.img (ro)
                 vdd lower.img (ro)        vde scratch.img (rw)
                 [vdf lower-delta.img (ro)]  [next: the project's cache.img (rw)]
```

- **One binary, two roles.**  `agentcracker` is a single Rust crate.
  `make` builds it twice: dynamically linked for the host, and statically
  linked (`+crt-static`) as `acinit`, which is copied into the base image.
  `main()` checks `getpid() == 1`: as PID 1 it runs `guest::main`,
  otherwise `cli::run`.  So host and guest always agree on the protocol
  and stream formats, which live in shared code (`src/proto.rs`).
- **Firecracker** runs as the invoking user, without the jailer, with a
  seccomp filter compiled at build time.  It is started with `--no-api`
  and a JSON config file.  agentcracker never talks to its API socket.
- **The guest kernel** is built from source by the Makefile (see "Kernel"
  in `README.md`).  It has no modules and no initramfs.
- **Images** are EROFS, written by agentcracker itself (`src/erofs.rs`),
  and cached under `~/.cache/agentcracker`.  The **scratch disk** is a
  sparse ext4 file per session.  The only other writable device is the
  project's **build cache** (`src/buildcache.rs`), the guest's
  `~/.cache`, kept across the project's sessions.  The host never mounts
  either.
- **The session store** (`~/.local/state/agentcracker/sessions/<id>/`)
  holds everything about a session between and after boots.

## 2. Building and installing

`make` builds four artefacts as your user:

| Artefact | Built from | Notes |
|---|---|---|
| `target/release/agentcracker` | this crate | the host CLI |
| `build/acinit-target/.../agentcracker` | this crate, `+crt-static` | the guest init; installed as `acinit` |
| `firecracker/build/.../firecracker` | the `firecracker` submodule | gnu target, linked against libseccomp |
| `build/vmlinux-<KVER>` | kernel.org tarball (SHA-256 pinned) | Firecracker's CI config + `kernel/agentcracker.config` |
| `build/seccomp.bpf` | Firecracker's musl policy, adapted | `agentcracker __seccomp-json` adds glibc's syscall spellings, then `seccompiler-bin` compiles it |

`make install` (optionally `PREFIX=~/.local`) only copies files.  It
never builds, so `sudo make install` cannot leave root-owned build output
behind.  At run time `images::find_asset` locates `firecracker`,
`vmlinux`, `acinit` and `seccomp.bpf` in `$AGENTCRACKER_LIB`, then next to
the binary (`../lib/agentcracker`), and finally in a source checkout's
build tree, so `target/release/agentcracker` works without installing.

## 3. The life of a session

What follows is `cd ~/src/proj && agentcracker claude`, step by step,
naming the function that does each part.

### 3.1 Command line (`cli.rs`)

`cli::run` dispatches on the first argument.  Anything that is not a
subcommand is a command to run, so it goes to `cmd_run`
(`agentcracker run <cmd>` covers names that clash with subcommands).
`parse_opts` takes `--allow`, `--no-net` and `--console`, and stops at
the first non-option so the command's own flags are left alone.

### 3.2 Preparing the session (`cli::cmd_run`)

1. The current directory is canonicalised.  agentcracker refuses `/` or
   any directory that contains `$HOME`.
2. `Config::load` merges defaults, `~/.config/agentcracker/config.toml`
   and `./.agentcracker.toml` (scalars override, lists append).
3. `Session::create` makes a new directory with a random 8-hex-digit id
   and writes `meta.json` (status `starting`).  `cmd_run` records vCPUs,
   memory, network settings, the allowlist and the git `HEAD`.
4. `images::lower_image` walks the project (`Tree::walk_into`, honouring
   `exclude`) and records a manifest entry (path, mode, size, mtime,
   inode) for every entry.  The cache key is a hash of that manifest, so
   an unchanged tree reuses the cached image.  The image is hardlinked
   into the session as `lower.img`, and the manifest is saved as
   `manifest.json`.
5. `images::create_scratch` formats a sparse 64 GiB ext4 file,
   `scratch.img`, with `mkfs.ext4`.

If any step fails, the half-made session directory is removed.

### 3.3 Booting (`cli::boot_once` → `vm::boot`)

`boot_once` takes the session lock (`flock` on `lock`), marks the session
`running` and calls `vm::boot`, which:

1. finds the installed assets and checks `/dev/kvm`;
2. gets the shared images, building them only if needed:
   - `base_image`: `/acinit`, mount points, usr-merge symlinks, an
     allowlisted copy of host `/etc`, and generated
     `passwd`/`group`/`hosts`/`hostname`/`resolv.conf`;
   - `usr_image`: host `/usr`.  If only an older snapshot exists it is
     used straight away, and a detached `agentcracker refresh --background`
     rebuilds the new one;
   - `detect_tools` + `tools_image`: toolchain roots outside `/usr`,
     found from `$PATH` (e.g. `~/.cargo` and `~/.rustup`, `~/.nvm`,
     `~/.local/share/claude`), never credential directories;
3. creates a runtime directory (`$XDG_RUNTIME_DIR/agentcracker/<id>/`),
   binds the unix sockets Firecracker forwards vsock ports to
   (`v.sock_1024` for control, `v.sock_1025` for the proxy) and starts the
   proxy (`proxy::serve`);
4. writes `firecracker.json`: kernel and boot arguments
   (`root=/dev/vda ro rootfstype=erofs init=/acinit`, plus `quiet` unless
   `--console`), the five drives in a fixed order, vCPUs and memory
   (SMT off), vsock (guest CID 3) and an entropy device;
5. builds the `GuestConfig` (identity, cwd, command, environment from
   `guest_env`, tools, ancestor directory owners, device names) and the
   home seed (`build_seed`: Claude Code settings and credentials, a
   `~/.claude.json` pruned to this project, git's global ignore file;
   git's identity goes as an agent file, `guidance::git_identity`);
6. starts Firecracker, with its output appended to `console.log`, and
   calls `attach`.

### 3.4 Inside the guest (`guest.rs`)

The kernel mounts `base.img` read-only as `/` and runs `/acinit`.
`guest::run`:

1. mounts `/proc`, `/sys`, `/dev`, `/dev/pts` and `/dev/shm`;
2. connects to the host on vsock port 1024 (retrying for up to 5 s) and
   reads the CONFIG frame;
3. sets the clock from the host's time and the hostname to
   `agentcracker`;
4. mounts the scratch disk at `/scratch` and the read-only images under
   `/lower/{usr,tools,proj}`, and bind-mounts `/` at `/lower/base`;
5. builds `/newroot` from overlays, each with its upper and work
   directories on scratch (`overlay()`), mounted with `redirect_dir`,
   `metacopy`, `index` and `xino` all off:

   | Mount point | Lower | Upper |
   |---|---|---|
   | `/newroot` | `/lower/base` | `/scratch/root/upper` |
   | `/newroot/usr` | `/lower/usr` | `/scratch/usr/upper` |
   | `/newroot/<tool root>` | `/lower/tools/<root>` | `/scratch/tools/<i>/upper` |
   | `/newroot/<cwd>` | `/lower/proj` | `/scratch/proj/upper` |

   Missing parent directories are created with the owners and modes the
   host reported (`mkdirs_mirror`), so paths like `/tmp/claude-1000`
   keep the right owner;
   With a build cache, its disk is mounted at `/scratch/cache` and its
   `home/` bind-mounted on `$HOME/.cache` (`mount_cache`; if it will not
   mount, the session goes on without it);
6. mounts proc, sysfs, cgroup2, `/dev` and a tmpfs `/run` inside the new
   root, and brings up loopback;
7. receives the SEED frames into `/scratch/seed.stream` and unpacks them
   into the user's home (`extract_seed`);
8. with networking, starts the proxy listener on `127.0.0.1:3128`
   (`start_proxy`): each local connection is spliced to a new vsock
   connection on port 1025;
9. starts the command (`spawn`): fork, `setsid`, chroot into `/newroot`,
   chdir to the project, drop to the user's uid/gid, `execve` along
   `$PATH`.  It gets a pty when the host side is a terminal, pipes
   otherwise; then acinit sends READY.

### 3.5 Running

On the host, `vm::attach` puts the terminal in raw mode.  A thread
(`stdin_pump`) sends stdin as STDIN frames and window changes, picked up
by a SIGWINCH self-pipe, as RESIZE frames.  The main loop writes STDOUT
and STDERR frames to the terminal.

In the guest, one thread per output stream sends STDOUT/STDERR frames
(`stream_output`).  Another (`pump_input`) applies STDIN, STDIN_EOF,
RESIZE and STOP frames, and sends SIGHUP to the command's process group
if the host goes away.  STOP is how `agentcracker stop` works: it sends
SIGTERM to the session's host process (pid in `meta.json`), whose
SIGTERM handler has `stdin_pump` send STOP; the guest gives the command
SIGTERM, then SIGKILL 5 s later, and shutdown proceeds as usual.  The
main thread reaps every process (as PID 1 must) until the command exits,
recording other exit statuses for extra shells (`record_exit`).

Extra commands in a running session (`agentcracker shell` while it
runs): acinit's `exec_server` listens on vsock port 1026 and accepts
connections from the host only (CID 2).  The host (`vm::exec_running`)
connects through Firecracker's `v.sock` with `CONNECT 1026`, sends an
EXEC frame (`proto::ExecRequest`: command, terminal or not, size,
`TERM`), and then speaks the same STDIN/RESIZE/STDIN_EOF and
READY/STDOUT/STDERR/ERROR/EXIT frames as the control connection.  The
guest starts the command with the session's own `spawn`, so it runs in
the same root, as the same user, with the same environment.

`--detach` (`cli::run_detached`) takes the session lock, forks, and lets
the child (new session, stdin `/dev/null`, stdout/stderr to the
session's `stdout`/`stderr` files) run `boot_and_review` with that lock;
there is no terminal, so there is no review.  `wait` takes each
session's lock (blocking) to learn that its VM has gone.

All network traffic goes through the proxy.  `proxy::handle` reads
`CONNECT host:port`, checks it with `config::host_allowed` (port 443
unless `host:port` is listed), resolves and connects on the host, then
copies bytes without reading them.  Every decision goes to `net.log`.

### 3.6 Shutdown and export (`guest::run`, after the command exits)

1. Remaining output gets up to 0.5 s to drain; every other process gets
   SIGTERM, then SIGKILL once none are left or 0.2 s have passed; output
   gets up to another 0.5 s; then filesystems are synced.
2. EXIT is sent with the exit status (128 + signal if the command was
   killed by a signal).
3. `export_upper` walks `/scratch/proj/upper` and streams it as EXPORT
   frames.  Whiteouts (char devices 0:0) become deletions, directories
   with `trusted.overlay.opaque=y` become opaque records, and files and
   symlinks are sent in full.  Then EXPORT_END.
4. The agent state paths (`~/.claude/projects`, the credentials file and
   configured `state` entries) are streamed as STATE frames, then
   STATE_END.
5. DONE is sent, and `poweroff()` resets the VM.  With `reboot=k`,
   Firecracker exits.

The host writes the two streams to `changes.stream.tmp` and
`state.stream.tmp` and renames each into place when its end marker
arrives.  `vm::boot` waits up to 5 s for Firecracker to exit (then kills
it), removes the runtime directory and returns an `Outcome`.

### 3.7 After the VM stops (`cli::boot_once`)

`boot_once` records the end time, exit code and status (`exited`, or
`crashed` if no exit status arrived), then:

- `ChangeSet::load` + `summary` record change counts in `meta.json`;
- `agentstate::extract_state` unpacks `state.stream` into `state/`;
- `agentstate::guest_refreshed_credentials` reports whether the guest
  refreshed its Claude login, and deletes the exported copy.  Guest
  credentials are never written to the host: the host cannot tell a
  refreshed token for the user's account from one for an account a
  compromised guest planted.

### 3.8 Review, apply and branch (`cli::review`, `changes.rs`, `apply.rs`, `gitimport.rs`)

`ChangeSet::from_stream` classifies each streamed entry against the
manifest and against the host as it is now:

- **Added, Modified, Deleted**: copy-ups that changed nothing (same
  content and mode as the host) are dropped.  A mode-only change is
  marked as such.  An opaque directory is expanded into deletions of
  whatever the snapshot had beneath it.
- **Conflict**: the host entry changed after the snapshot (by mode,
  inode, size or mtime) or, for an added path, appeared since.
- **Sensitive**: build files, CI and editor config, dotfiles, `.claude/`
  and the like, and newly executable files.  These are highlighted, not
  blocked.
- **`.git/`** entries are kept separately.  They are never applied.

The review menu offers diff (`render_diff` runs `diff -u` per file and
pages the output), apply, branch, shell (boot again with the user's
shell), keep and discard.

**Apply** (`apply::apply`) deletes first, then creates in stream
order.  Every write goes through `Confined`: the parent directory is
opened with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS)`, data goes to a temporary file
(`O_EXCL | O_NOFOLLOW`) that is renamed over the target, and only
`mode & 0777` is kept.  Conflicts are skipped unless the user chooses to
overwrite them.

**Branch** (`gitimport::import_branch`) copies only the agent's object
files (loose objects and packs, names validated) out of the stream into
a bare scratch repository, which borrows the host's objects via
`alternates`.  The host repository then fetches the agent's HEAD from it
with `fetch.fsckObjects` into `agentcracker/<id>` (forced), or into the
session's `--branch` name (`SessionMeta::work_branch`) without forcing:
that branch is checked first, so a branch checked out on the host, or
one the agent's HEAD does not descend from, is refused with a reason.

`--branch NAME` (`cli::check_new_branch`) needs a git repository with
commits and a valid name not yet used there.  On the session's first
boot it goes to the guest as `GuestConfig::git_branch` (name and the
base commit), and acinit's `start_branch` writes
`.git/refs/heads/<name>` and `.git/HEAD`, as the user, before the
command starts; the index and work tree already match the base.  The
agent's instructions name the branch.

### 3.9 Later: resume, shell, show, rm

`resume` and `shell` (`cli::cmd_resume`) boot the same session again.
The scratch disk still holds the overlay upper layers and the guest
home, so the agent sees its earlier work.  The project is **not**
snapshotted again.  Only the credentials are re-seeded.  `ls`, `show`,
`diff`, `apply`, `branch` and `rm` read the session store.  `rm`
refuses while a session's lock is held.

## 4. Files on disk

```text
$PREFIX/bin/agentcracker
$PREFIX/lib/agentcracker/{acinit,firecracker,vmlinux,seccomp.bpf}

~/.cache/agentcracker/               ($XDG_CACHE_HOME)
  base/base-<key>.img                base root; key: user, acinit mtime, /etc, symlinks
  usr/usr-<key>.img                  /usr; key: package DBs + directory mtimes
  tools/tools-<key>.img              toolchains; key: roots + directory mtimes
  lower/<dir>-<key>.img              full project snapshots; key: directory + manifest hash
  lower/<dir>-<key>.delta-<base>.img delta over the base snapshot <base>
  lower/<dir>-<key>.manifest         the manifest of <key> (binary)
  {base,usr,tools}/lock              serialises builders
  refresh.log                        output of background /usr rebuilds

~/.local/state/agentcracker/sessions/<id>/   ($XDG_STATE_HOME)
  meta.json  manifest.bin  lower.img  [lower-delta.img]  scratch.img
  changes.stream  state.stream  state/  console.log  net.log  lock  tmp/
  [stdout  stderr]                    output of --detach'ed runs

~/.local/state/agentcracker/caches/<key>/    build cache per project; key: FNV of the path
  cache.img  dir  lock                ext4 image (the guest's ~/.cache), its project, flock()ed while used

$XDG_RUNTIME_DIR/agentcracker/<id>/  (or /tmp/agentcracker-<uid>/<id>/)
  firecracker.json  v.sock  v.sock_1024  v.sock_1025     (only while booted)
```

Cached images are replaced atomically (temporary file + rename) and older
ones are deleted under the lock.  A running VM keeps its open file, so
that is safe.  Project snapshots that no session hardlinks are removed
after a week unused.

## 5. Protocol and stream formats

### Control frames (vsock port 1024)

A frame is `type: u8`, `len: u32` big-endian, then `len` bytes (at most
16 MiB).  Constants are `proto::M_*`.

| # | Name | Direction | Payload |
|---|---|---|---|
| 1 | CONFIG | host → guest | `GuestConfig` as JSON |
| 2, 3 | SEED, SEED_END | host → guest | home seed file stream |
| 4 | STDIN | host → guest | terminal input |
| 5 | RESIZE | host → guest | rows `u16`, cols `u16` |
| 6 | STDIN_EOF | host → guest | — |
| 7 | STOP | host → guest | — (SIGTERM the command, SIGKILL after 5 s) |
| 8 | EXEC | host → guest | `ExecRequest` as JSON; first frame on port 1026 only |
| 10 | READY | guest → host | — |
| 11 | ERROR | guest → host | UTF-8 message; the guest powers off |
| 12 | STDOUT | guest → host | command output |
| 13 | EXIT | guest → host | exit status `i32` |
| 14, 15 | EXPORT, EXPORT_END | guest → host | project upper layer file stream |
| 16, 17 | STATE, STATE_END | guest → host | agent state file stream |
| 18 | DONE | guest → host | — |
| 19 | STDERR | guest → host | command stderr (non-tty only) |

Order: CONFIG, SEED*, SEED_END → READY → (STDOUT/STDERR ↔ STDIN/RESIZE)*
→ EXIT → EXPORT*, EXPORT_END → STATE*, STATE_END → DONE.

### Exec connections (vsock port 1026)

Host-initiated, through Firecracker (`CONNECT 1026` on `v.sock`, answered
`OK <port>`).  EXEC, then the control connection's STDIN, RESIZE,
STDIN_EOF and STOP frames from the host and READY, STDOUT, STDERR, ERROR
and EXIT from the guest.  The guest drops connections from any CID but
the host's.

### Proxy connections (vsock port 1025)

Each is a raw TCP byte stream from a guest client: an HTTP `CONNECT`
request followed, if allowed, by the tunnelled TLS bytes.

### File stream

Used for the home seed, the change export and the agent state.  Each
record is a tag byte followed by fields.  Strings are a `u32` length plus
bytes, modes are `u32` (permission bits only), sizes are `u64`, all
big-endian:

```text
'D' path mode             directory
'F' path mode size data   regular file
'L' path target           symlink
'X' path                  deletion (overlay whiteout)
'O' path mode             opaque directory (replaces the lower one)
'E'                       end
```

There are no owners, devices, xattrs or hard links.  `StreamReader`
rejects any path that `util::safe_rel_path` does not accept (absolute,
empty or `.`/`..` components, NUL bytes, over 4096 bytes or a component
over 255).  The host never extracts the change stream as a whole.  It
reads file data by offset (`StreamReader::offset`) when it diffs or
applies.

## 6. Security boundaries

The guest is assumed hostile.  These are the places where its output
reaches the host, and how each one is handled:

| Channel | Guard |
|---|---|
| Block devices | Only `scratch.img` and the project's build cache `cache.img` are writable, and the host never mounts or parses either.  The cache's contents reach only later sessions of the same project, one at a time (flock), never the host. |
| Control frames | Length-capped (16 MiB); unknown frame types ignored; the guest's config cannot be changed by the guest. |
| `changes.stream` | Parsed with path validation; data read by offset; applied only on request, through `Confined` (`openat2` beneath the project, no symlinks, temporary file + rename, `mode & 0777`); `.git/` never written; conflicts skipped unless the user chooses to overwrite. |
| Git objects | Only object files with validated names; imported via `git fetch` with `fsckObjects`; no guest hooks, config or refs used. |
| `state.stream` | Unpacked with `Confined` into the session's `state/`; symlinks and deletions ignored. |
| Credentials | Never written back to the host or kept in the session; a refresh in the guest is only reported. |
| Terminal output | Every guest-derived string agentcracker prints (paths, symlink targets, diffs on a terminal, branch names, host names, transcript text, guest errors, console tails) goes through `util::safe_text`, which shows control, C1 and bidi-override characters as escapes; the terminal is soft-reset after an interactive session; the proxy refuses CONNECT targets that are not host names or IP literals. |
| Secrets in git's configuration | The guest's `~/.gitconfig` is written by agentcracker with `user.name` and `user.email` only (`guidance::git_identity`), on every boot; the user's own (`sendemail.smtpPass`, tokens in URLs or headers, credential helpers) never enters the VM. |
| Secrets in the snapshots | The project snapshot's `.git/config` has `user:token@` stripped from URLs and `extraheader` lines dropped; the toolchain snapshot excludes cargo, npm, PyPI, netrc and git credential files; new sessions warn about credential-like project files (`images::credential_like`). |
| Network | No NIC; HTTPS `CONNECT` only, to allowlisted hosts (port 443 unless `host:port` is listed); DNS resolved on the host; decisions logged. |
| Test kernels (`acrboot`) | Off unless the user's config says `boot = true` (a project's cannot); otherwise the host hides VMX and SVM from the guest (a Firecracker CPU template: its KVM then refuses VMXON and EFER.SVME), so a guest kernel the agent took over cannot reach the host's nested-virtualisation code either, and acinit removes `/dev/kvm`; with it acinit makes `/dev/kvm` the user's.  Nothing runs on the host: the test VM is a Firecracker nested in the session's VM (its CPUs, memory and disk), with no network and no vsock, killed on timeout, a few seconds after a panic, and with the session.  The agent controls that VM's kernel, and the host's KVM handles its exits first, so the boundary there is the host's nested-virtualisation code against ring 0.  Its records reach the host as state (`boot.log` lines parsed strictly and escaped when shown, consoles capped at 4M × 20). |
| Firecracker | Runs as the user, with the compiled seccomp filter.  **No jailer**: it needs root, which conflicts with the rootless goal, so there is no chroot or cgroup limit around the VMM. |

What goes into the guest is limited too.  `/etc` is copied from an
allowlist (`images::ETC_ALLOW`), toolchain roots never include
credential directories (`images::NEVER_TOOLS`), and the environment is
filtered (`vm::guest_env`).  The agent profile's variables
(`ANTHROPIC_*`/`CLAUDE_CODE_*`, or `OPENAI_*`/`CODEX_*`) are passed
through, API keys included, because the agent needs them.

## 7. Source guide

All source is in `src/`.

| File | Role |
|---|---|
| `main.rs` | Entry point; picks the host or guest role. |
| `cli.rs` | Subcommands, the run → boot → review loop, session queries. |
| `config.rs` | Config files, defaults, the allowlist matcher. |
| `session.rs` | The session store: `meta.json`, manifest, locking, lookup. |
| `images.rs` | Building and caching base/usr/tools/project images; scratch disk; asset lookup. |
| `erofs.rs` | The EROFS writer: in-memory tree, host walk, image layout, reflink copy. |
| `vm.rs` | Firecracker config and launch, home seed, guest environment, terminal attach. |
| `proxy.rs` | Host side of the egress proxy. |
| `proto.rs` | vsock frames and the file stream encoder/decoder. |
| `guest.rs` | acinit: mounts, overlays, seed, proxy relay, command, export, poweroff. |
| `agent.rs` | Agent profiles (Claude Code, Codex): hosts, seeded files, login, state, environment. |
| `activity.rs` | The `log` timeline: network log and transcript tool calls. |
| `guidance.rs` | What the agent is told: the sandbox section of its instructions file, the acrboot skill. |
| `acrboot.rs` | `acrboot`: the guest command that boots test kernels in nested microVMs. |
| `buildcache.rs` | Per-project build caches (the guest's `~/.cache`): attach with a lock, list, drop. |
| `changes.rs` | The change set: classification against the manifest and the host, the list and diff. |
| `apply.rs` | Applying changes to the host through confined writes (`openat2`). |
| `gitimport.rs` | Importing the agent's commits as a host branch. |
| `agentstate.rs` | The agent's exported state: unpacking it, refreshed logins, transcript summaries. |
| `util.rs` | Errors, hashing, paths, locks, glob/excludes, formatting, prompts. |

### `main.rs`
`main()`: runs `guest::main` as PID 1, otherwise `cli::run`.  Turns
errors into `agentcracker: <msg>` and exit status 1.

### `agent.rs`

`Profile` describes one agent; `CLAUDE` and `CODEX` are the built-in
ones.  `detect` picks one from the command (looking past `env`, `npx`,
`sh -c` and similar), `for_session` from a session's recorded `agent`,
and `Profile::path` resolves a path in the agent's directory, honouring
`CODEX_HOME`.  `vm::first_boot_seed`, `vm::state_paths`,
`vm::credential_path` and `vm::guest_env` take the profile;
`agentstate::transcripts` reads Claude's or Codex's transcripts, and
`activity::tool_events` both formats.

### `guidance.rs`

`agent_files` decides, on every boot, what acinit writes into the guest's
home (`GuestConfig::agent_files`): the sandbox section of the profile's
instructions file (`Profile::instructions`), between `BEGIN` and `END`
markers, and the `agentcracker-acrboot` skill when `boot = true` (or its
removal).  acinit's `write_agent_files` writes them with the user's
filesystem credentials (`setfsuid`), using `with_section` to replace the
old section and keep the rest of the file.  These paths are not in the
exported state, so they never reach the host.

### `acrboot.rs`

The guest command (`main` dispatches to it when the program is called
`acrboot`; acinit links `/usr/bin/acrboot` to itself).  `check_kvm`
tells "not enabled" from "no nested virtualisation"; `check_kernel`
refuses what Firecracker cannot boot; then it runs `/acboot/firecracker`
(in the base image, with `/acboot/seccomp.bpf`) on the kernel and disks,
copies the console to stdout and, capped, to `N.console`, watches for a
panic, applies the timeout, stops on SIGINT/SIGTERM/SIGHUP (acinit's
shutdown sends SIGTERM), and appends the outcome to `boot.log`, both in
`~/.local/state/acrboot` (`RECORDS`, always among the exported state
paths).  CPUs and memory are clamped to the guest's (memory less
`RESERVE_MIB`).

`--run` attaches the session's base and `/usr` images (`/dev/vda`,
`/dev/vdb` in the guest, which acinit makes readable with `boot`) as the
test VM's read-only `vda` and `vdb`, a spec disk (`Spec` as JSON, padded
to 4K) as `vdc`, and an ext4 copy of `--dir` (`copy_dir_image`, via
`images::mkfs_ext4 -d`) as `vdd`; the command line adds
`root=/dev/vda ro rootfstype=erofs init=/acinit acrboot_run=1`.  The
kernel hands `acrboot_run=1` to init as an environment variable, so
`main` runs `acrboot::init` instead of `guest::main`: it mounts the usual
filesystems, `/usr`, tmpfs over `/tmp`, `/run`, `/root`, `/var` (with `/var/run` -> `/run`) and
the top directory of `--dir` (the base image is read-only), the copy,
bpffs, debugfs, tracefs, cgroup2 and securityfs (each optional), lifts
`RLIMIT_MEMLOCK`, brings up `lo`, runs `sh -c CMD` as root and prints
`RUN_STATUS` with the status, which `acrboot` finds in the console.

### `buildcache.rs`

`attach` takes a project's cache for one boot (creating `cache.img` with
`images::create_disk` on first use) and returns it with its `flock`
held, or `None` when another running session has it; `vm::boot` adds it
as the last drive and passes its device as `GuestConfig::dev_cache`.
`list` and `drop_cache` back `agentcracker cache`.

### `activity.rs`

The timeline behind `agentcracker log`: `net_events` parses `net.log`
from a byte offset (so `-f` can follow it), `tool_events` collects tool
calls from every transcript in the exported state (Claude Code's and
Codex's, subagents' included) and `boot_events` the test boots,
`parse_iso8601` reads their timestamps, and `render`/`json` format
events, escaping the agent's text.  While the session runs, the
transcripts and `boot.log` are still in the guest: `Live::poll` lists
them with their sizes and reads what each gained since its last call,
with `vm::exec_capture` (a command over the exec port, as the user, its
output capped), and parses that the same way.

### `cli.rs`
- `run`: dispatch, including the hidden `__seccomp-json` and `__mkimage`.
- `cmd_run`: prepare a new session (§3.2) and boot it.
- `boot_once`: one boot, with status and result recording (§3.3, §3.7).
- `boot_and_review`, `review`, `apply_interactive`, `keep_msg`: the
  post-session menu (§3.8).
- `cmd_resume` (also `shell`, which runs `vm::exec_running` when the
  session is up), `cmd_ls`, `cmd_show`, `cmd_log`, `cmd_diff`,
  `cmd_apply`, `cmd_branch`, `cmd_wait`, `cmd_stop`, `cmd_rm`,
  `cmd_refresh`: one per subcommand.
- `run_detached`: `--detach`; `session_brief`/`session_json`: `--json`.
- Helpers: `parse_opts`, `cwd`, `git_head`, `status_of`, `fmt_time`,
  `load_cs`.

### `config.rs`
- `Config::load` / `merge`: defaults plus both files.
- `host_allowed`: allowlist matching (`*`, `*.domain`, exact,
  `host:port`).
- `expand`: `~` expansion.  `DEFAULT_ALLOW` and `DEFAULT_EXCLUDE_USR`.

### `session.rs`
- `Session::create`, `load_dir`, `save` (atomic), `save_manifest`,
  `manifest`, `lock`, `is_running`, `disk_usage`, `remove`.
- `list`, `find` (id prefix or latest for the directory),
  `looks_like_id`.
- `Meta` and `Summary`: the `meta.json` schema.

### `images.rs`
- `find_asset` (with `kernel_version_key`): locate installed files.
- `usr_image`, `usr_key`, `spawn_background_refresh`, `Refresh`: the
  `/usr` snapshot.
- `detect_tools`, `tool_root_for`, `tools_image`, `NEVER_TOOLS`:
  toolchains.
- `base_image`, `etc_tree`, `ETC_ALLOW`: the root image.
- `lower_image`, `gc_lower`, `Lower`: the project snapshot.
- `create_scratch`: the scratch disk.
- Cache helpers: `mtime_sig`, `dir_sig`, `newest`, `remove_others`.
  Also `status` for progress messages.

### `erofs.rs`
- `Tree`, `Node`, `Kind`, `Content`: the in-memory tree (`add`, `child`,
  `mkdir_p`, `mkdir_p_at`).
- `Tree::walk_into`: host directory to tree, with excludes, hard links,
  manifest and `WalkStats`.
- `write_image`: nid assignment, layout, inode table, superblock, atomic
  write.  `dir_blocks` serialises directories.
- `copy_into` / `copy_slow`: reflink-first data copy.
- `ManifestEntry`: also the session manifest's record type.

### `vm.rs`
- `boot`: everything needed to start Firecracker (§3.3).  Returns an
  `Outcome`.
- `attach`: the host side of the control protocol.  `accept_guest`,
  `stdin_pump`, `RawTerm`, `on_winch` and `winsize` handle the terminal.
- `build_seed`, `first_boot_seed`, `state_paths`, `CRED_PATH`,
  `hash_file`: what crosses into and out of `$HOME`.
- `guest_env`, `ancestor_dirs`: parts of the `GuestConfig`.
- `console_tail`: console context for error messages.
- `exec_running`, `exec_capture`, `exec_connect`: commands in a running
  session's VM over the exec port (§3.5), attached or with the output
  collected.

### `proxy.rs`
- `serve` and `handle`: accept vsock-forwarded connections, apply
  policy, tunnel.
- `log` and `summarize`: `net.log`.

### `proto.rs`
- Ports and frame type constants; `GuestConfig`.
- `write_frame`, `read_frame`, `FrameWriter` (a byte sink → frames).
- `StreamWriter`, `StreamReader`, `Entry`, `stream_tree`: the file
  stream.

### `guest.rs`
- `main` and `run`: the acinit sequence (§3.4–§3.6); `poweroff`.
- `mount`, `overlay`, `ovl_escape`, `mkdirs`, `mkdirs_owned`,
  `mkdirs_mirror`: building the root.
- `vsock_connect`, `start_proxy`, `splice`, `lo_up`: connectivity.
- `extract_seed`, `export_upper`: streams in and out.
- `spawn`, `Child`, `write_all_fd`, `set_clock`: running the command.

### `changes.rs`
- `ChangeSet::load` / `from_stream`, `Change`, `Op`, `St`,
  `is_sensitive`, `host_matches_manifest`, `same_content`:
  classification.
- `summary`, `shown`, `conflicts`, `summary_line`, `short_summary`,
  `print_list`, `render_diff`, `show_diff`, `colorize`: presentation.

### `apply.rs`
- `Confined` (`write_file`, `write_bytes`, `symlink`, `mkdir`,
  `delete`), `openat2_beneath`: confined writes.
- `apply`, `Applied`: applying a change set.

### `gitimport.rs`
- `agent_head`, `import_branch`, `git_file`, `read_stream_file`, `is_sha`.

### `agentstate.rs`
- `extract_state`, `guest_refreshed_credentials`: the exported state.
- `transcripts`, `Transcript`, `codex_transcripts`: summaries for `show`.

### `util.rs`
- `Error`, `Result`, `bail!`, `Context`, `last_os_error`: errors.
- `Fnv`: stable hashing for cache keys.
- `cache_dir`, `state_dir`, `config_dir`, `runtime_dir`, `home`,
  `mkdir_private`, `tilde`: paths.
- `try_lock`, `lock`: `flock`.
- `glob_match`, `Excludes`, `safe_rel_path`: matching and validation.
- `human_bytes`, `human_age`, `human_duration`, `parse_mem_mib`,
  `user_name`, `user_shell`, `group_name`, `prompt_key`, `isatty`,
  `cstr`, `now`, `random_hex`: small helpers.

## 8. Tests

- `cargo test`: unit tests (currently the kernel version ordering in
  `images.rs`).
- `make test` (or `tests/run.sh [words...]`): end-to-end scripts that
  boot real VMs, so they need `/dev/kvm`.  Each `tests/tNN-*.sh` is
  standalone and uses `tests/lib.sh` (logging, assertions, an isolated
  session store).  `tests/pty.py` drives the interactive review on a
  pseudo-terminal.  The scripts cover:

  | Script | Area |
  |---|---|
  | `t00-cli.sh` | usage and errors, no VM needed |
  | `t01-boot.sh` | guest environment, identity, paths, isolation |
  | `t02-timing.sh` | startup and teardown time |
  | `t03-changes.sh` | change capture, summary, listing, diff |
  | `t04-apply.sh` | apply, idempotence, conflicts, what is never applied |
  | `t05-review-menu.sh` | the interactive review |
  | `t06-resume.sh` | resume/shell persistence, agent state export |
  | `t07-network.sh` | proxy policy, `--no-net`, logging |
  | `t08-branch.sh` | branch import |
  | `t09-sessions.sh` | listing, lookup, show, removal |
  | `t10-hostile-guest.sh` | credentials, terminal escapes, secrets in snapshots |
  | `t11-orchestration.sh` | `--detach`, `wait`, `stop`, `--json`, shells in a running session |
  | `t12-log.sh` | `log`: network and tool-call timeline, read live from a running VM, `-f`, `--json`, escaping |
  | `t13-profiles.sh` | agent profiles: Codex seeding, login, environment, transcripts, selection |

  `AGENTCRACKER=/path/to/agentcracker make test` tests an installed copy.
  `.github/workflows/test.yml` runs `make test` on GitHub's Linux runners
  (which have KVM) for every push and pull request, caching the guest
  kernel, firecracker and cargo builds, and fails the job if any test
  fails; logs of failed tests are uploaded as an artifact.  The runner
  has no reflinks, so CI keeps the snapshots small: `AC_TEST_CONFIG`
  gives every test a config with `exclude_usr` entries for what the tests
  never use, and the tests run with a minimal `PATH` so no toolchains are
  snapshotted.
  A failing test's work directory and sessions are kept under
  `build/tests/`.

## 9. Debugging and development aids

- `--console`: show the guest kernel console and acinit messages live;
  the kernel is booted without `quiet`.
- `<session>/console.log`: the console and Firecracker's log from every
  boot.  Its last lines are appended to boot errors.
  `AGENTCRACKER_FC_LOG=Info` (or `Debug`) raises Firecracker's log level
  (default `Error`).
- `<session>/net.log`: every proxy decision.  `agentcracker show`
  summarises it.
- `<session>/state/.local/state/acrboot/`: `boot.log` and
  `<n>.console` (the first 4M) of each `acrboot` boot, as the guest
  recorded them; the test VM's Firecracker log is in the guest's
  `/tmp/acrboot-<pid>/` while it runs.
- `agentcracker shell [SESSION]`: a shell inside a session's VM, on the
  same disk.
- `AGENTCRACKER_LIB=<dir>`: use the assets in `<dir>` (e.g. a different
  `vmlinux`).
- `agentcracker refresh`: rebuild the `/usr` snapshot now.
  `~/.cache/agentcracker/refresh.log` has the output of background
  rebuilds.
- `agentcracker __mkimage <dir> <out.img>`: write `<dir>` as an EROFS
  image and print walk/write timings.  You can check the result with
  `fsck.erofs` or a loop mount.
- `agentcracker __seccomp-json <in.json> <out.json>`: the seccomp policy
  adaptation used by the Makefile.

## 10. Making changes

- **Image contents or layout**: bump `images::FORMAT` so that cached
  images built under the old rules are not reused.
- **A new control frame**: add an `M_*` constant in `proto.rs`, then
  handle it in both `vm::attach` and `guest::run`.  Host and guest are
  the same binary, so they are always upgraded together, but a running
  session's `acinit` is the copy in its base image.  A rebuilt base image
  (its key includes acinit's mtime) is used on the next boot.
- **A new `GuestConfig` field**: give it a default (the struct is
  `Default`) and fill it in `vm::boot`.
- **A new config key**: add it to `config::File` and `Config`, and merge
  it in `Config::merge` (scalars override, lists append).  Mention it in
  `cli::USAGE` and the README.
- **New data out of the guest**: go through a file stream and
  `Confined`.  Never mount, loop-mount or parse guest-written disk images
  on the host.
- **Docs**: keep the module comment and the function comments in step
  with behaviour, and keep this file's source guide in step with the
  files.

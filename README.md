# agentcracker: disposable microVMs for coding agents

## Quick start

```
$ git clone --recursive <this repo> && cd agentcracker
$ make                    # builds firecracker (submodule), a guest kernel and
                          # agentcracker; run as your user, not root
$ make test               # optional: run tests/ against the build
$ sudo make install       # copies into /usr/local (or: make install PREFIX=~/.local)
$ cd ~/src/myproject
$ agentcracker claude     # first run snapshots /usr (~30s on btrfs); after that
                          # a VM is up in ~0.3s and gone ~0.3s after the agent exits
```

**Large trees.**  The first session in a directory snapshots the whole
project, `.git` included.  For a kernel tree (about 90k files, 4.6G with
history) that takes about 10s on btrfs; later sessions reuse the snapshot
or add a small delta of what changed, and start in under a second.  On
filesystems without reflinks (ext4, for example) the first snapshot
really copies every byte, so it takes much longer and uses as much disk
again as the tree.  Leave out build output you don't need in the VM with
`exclude = [...]` in `.agentcracker.toml` (e.g. `exclude = ["*.o", "*.ko",
"/vmlinux*"]`).

Requirements: Linux x86_64, read/write access to `/dev/kvm` (the `kvm`
group), `vhost_vsock`, and the build tools `make check-deps` lists (Rust,
a C toolchain, kernel build deps, glibc-static, e2fsprogs).  The kernel
build (6.18 LTS, Firecracker's CI config plus `kernel/agentcracker.config`)
takes a few minutes once; see [Kernel](#kernel) for details.

When the agent exits the VM powers off, and agentcracker summarises what
changed in the project and offers:

```
  M src/main.rs
  A src/new_test.rs
  D old.txt
  M Makefile  (runs or configures tools on the host - review carefully)
4 files changed: 2 modified, 1 added, 1 deleted
The agent committed: main is now 3f2a9c1d07e4
[d]iff [a]pply [b]ranch [s]hell [K]eep for later (not applied) [x] discard
```

Nothing reaches your directory until you choose **apply** (now, or later
with `agentcracker apply`).

Everything else is a subcommand:

```
agentcracker [--allow HOST]... [--no-net] [--console] [--detach] <command> [args...]
agentcracker ls     [--json]         # sessions: age, status, changes, directory
agentcracker show   [--json] [SESSION]   # changes, network log, Claude transcripts, disk use
agentcracker diff   [SESSION]
agentcracker apply  [SESSION]
agentcracker branch [SESSION]        # agent's commits -> branch agentcracker/<id>
agentcracker resume [SESSION] [command...]
agentcracker shell  [SESSION]        # also opens a shell inside a *running* session
agentcracker wait   [--json] [SESSION...]   # for --detach'ed sessions
agentcracker stop   [SESSION...]     # end running sessions, keeping their changes
agentcracker rm     SESSION...
agentcracker refresh                 # rebuild /usr + toolchain snapshots now
```

`SESSION` is an id prefix and defaults to the latest session for the
current directory.  `--detach`, `wait`, `stop` and `--json` let scripts
and orchestrators run several agents at once, each in its own VM, and
compare their results; applying always stays a separate, deliberate
step.  `man agentcracker` (or `man -l man/agentcracker.1` in the source
tree) has the full reference and a worked example of a session's life.  See [Implementation notes](#implementation-notes) for
how the build differs from the design below.

## Introduction

Coding agents are most useful when they are allowed to act: run the
build, run the tests, install a dependency, rewrite a dozen files, try
something and throw it away.  They are most dangerous for exactly the
same reason.  Today the choice is mostly between two unsatisfying
options:

1. approve every command by hand, which turns the agent back into a
   very fast typist waiting on a slow human; or
2. run in "yolo" mode and trust that nothing goes wrong - no stray
   `rm -rf`, no `git push --force`, no helpful clean-up of `~/.ssh`.

Containers help, but they share the host kernel, and getting a
container to look like "my project, with my toolchain, but nothing
else" tends to involve a Dockerfile per project and a pile of bind
mounts that quietly re-expose the host.

agentcracker takes a different approach.  The whole user experience is
one command:

```
$ cd ~/src/myproject
$ agentcracker claude
```

That boots a Firecracker microVM in well under a second, presents the
current working directory inside it at the same path, and runs the
agent there.  The agent sees a normal writable checkout, but every
write lands in a copy-on-write overlay layer that lives inside the VM.
The real directory on the host is never written to.  When the agent
exits, the user gets a diff, and chooses whether to apply it, keep the
session around for later, or throw it away.

The guiding idea: _the agent gets full autonomy inside a box, and the
human gets a single, reviewable decision at the boundary._

## Goals and non-goals

Goals:

- **Zero configuration for the common case.**  `agentcracker <cmd>`
  should work in any directory without a per-project setup step.
- **The host filesystem is read-only from the agent's point of view.**
  Not "read-only unless it finds a writable bind mount" - structurally
  read-only, because the only path from guest to host is a narrow,
  explicit protocol.
- **Hardware isolation.**  The agent runs on its own kernel behind KVM.
  A guest kernel exploit is not a host compromise.
- **Fast enough to not think about.**  Sub-second start, native-ish
  file and CPU performance.
- **Your tools, not an image's.**  The agent should find the same
  compilers, interpreters, linters and agent CLIs it would find in
  your shell.  No Dockerfile to maintain and no "works on the host,
  breaks in the sandbox".
- **Rootless.**  Membership of the `kvm` group should be the only
  privilege required.
- **Agent-agnostic.**  `claude` is the motivating case, but
  `agentcracker bash`, `agentcracker make test` or any other agent CLI
  should work the same way.

Non-goals:

- Protecting the contents of the working directory from the agent.
  The agent can read the project - that is the point - and can send
  it to the model provider, as it would outside the sandbox.
- Being a general-purpose VM manager or a container replacement.
- Multi-tenant hosting.  This is a single-user developer tool, though
  most of the design carries over.
- Reproducible environments.  The guest deliberately mirrors _this_
  host's userspace; it is not a portable build environment.

## Architecture overview

```
 host                                              guest (microVM)
 ------------------------------------------------  ---------------------------------
 agentcracker CLI                                   acinit (PID 1)
  |  - resolves config, session                       - mounts /proc /sys /dev
  |  - builds/caches /usr + toolchain snapshots       - assembles / from base + /usr
  |  - builds/caches lower layer for $PWD             - assembles overlay at $PWD
  |  - creates sparse scratch disk                    - starts vsock services
  |  - launches firecracker (via jailer)              - runs `claude` in a pty
  |  - attaches terminal over vsock                   - on exit: sync, report, poweroff
  |  - runs egress proxy on vsock
  |  - on exit: diff / apply / keep / discard
  |
  +-- firecracker ---- virtio-blk ro  base.img    --> /           (acinit, skeleton /etc)
                  ---- virtio-blk ro  usr.img     --> /usr        (host /usr snapshot)
                  ---- virtio-blk ro  tools.img   --> $HOME/...   (host toolchain dirs)
                  ---- virtio-blk ro  lower.img   --> overlay lowerdir  ($PWD snapshot)
                  ---- virtio-blk rw  scratch.img --> overlay upperdir + workdir, /tmp, $HOME
                  ---- vsock          (terminal, control, egress proxy, live-share)
                  (no NIC by default)
```

Five pieces:

1. **The `agentcracker` CLI** on the host - orchestration, terminal
   attach, review and apply.
2. **Firecracker + jailer** - the VMM, running unprivileged in a
   chroot with seccomp and a cgroup.
3. **A guest kernel, a tiny base rootfs, and a read-only snapshot of
   the host's `/usr`** - shared between sessions, cached, rebuilt
   only when the host's packages change.
4. **`acinit`** - a small static PID 1 in the guest that wires
   everything up and runs the requested command.
5. **The session store** - per-session state on the host
   (`~/.local/state/agentcracker/<session>/`): scratch disk, base
   manifest, logs.

## The key problem: getting $PWD into the VM

Firecracker deliberately has a tiny device model: virtio-blk,
virtio-net, vsock, balloon and entropy.  There is _no_ virtio-fs and
no virtio-9p.  That is part of why it is fast and small, but it means
"just share the directory" is not available off the shelf.  This is
the most important design decision in the whole tool.

The overlay itself is the easy part.  We assemble it _inside the guest_:

```
mount -t overlay overlay \
      -o lowerdir=/mnt/lower,upperdir=/scratch/upper,workdir=/scratch/work \
      $PWD
```

- **lowerdir** is a read-only view of the host's working directory.
- **upperdir/workdir** live on the guest-private scratch disk.

Because the overlay is assembled in the guest, the host never sees a
writable mount of the project at all.  The only question is how the
lowerdir gets there.  There are three reasonable options:

| Option | How | Pros | Cons |
|---|---|---|---|
| **A. Snapshot image** (default) | Host builds an EROFS image of `$PWD` (`mkfs.erofs`), attaches as read-only virtio-blk | Point-in-time consistent; fastest in-guest I/O; dead simple guest side; no host-side server | Image build cost on big trees; host edits after start are not visible |
| **B. Live read-only share** | Host runs a small read-only 9P (or NFS) server; guest mounts it over vsock (`trans=fd` via a tiny helper) | No build step; sees host changes | Slower metadata ops; overlayfs explicitly calls lower changes underneath a mounted overlay undefined; more attack surface on the host side |
| **C. Block-level CoW** | If `$PWD` is on btrfs/XFS, reflink-copy into an image, or use a dm-snapshot of a loop device | Very cheap on CoW filesystems | Filesystem-specific; needs privileges for dm |

**Recommendation: A by default, B as `--live`.**  The snapshot model
matches how people actually think about handing work to an agent ("here
is the state of my tree, go do something with it") and gives a clean
base for the diff at the end.  It also means the host-side code that
the guest can talk to is minimal.

Making A fast:

- **EROFS** is designed for exactly this - read-only, compact, fast to
  build and to mount.  `mkfs.erofs` on a typical source tree is
  hundreds of milliseconds.
- **Cache by content.**  Key the image on a manifest of
  `(path, size, mtime, inode)`; if nothing changed since the last
  session in this directory, reuse the image.  For git repos, the
  manifest can be built cheaply from the index plus `git status`.
- **Layer it.**  Large rarely-changing trees (`node_modules`,
  `target/`, `.git/objects`) can go into a separate cached EROFS image
  stacked as a second lowerdir, so the per-session image only contains
  the hot part of the tree.
- **Exclusions** via `.agentcracker.toml` (or reuse `.gitignore`
  semantics on request) for trees the agent does not need.

The directory is mounted at the **same absolute path** in the guest as
on the host.  Build systems, compile_commands.json, editor configs and
agent transcripts are full of absolute paths; preserving them avoids a
whole category of subtle breakage.

## The scratch disk

A sparse file (say 20G apparent, a few MB actual) attached read-write.
`acinit` formats it on first boot (ext4, or XFS for reflink support
inside the guest) and carves it into:

- `/scratch/upper`, `/scratch/work` - the project overlay;
- the guest `$HOME` and `/tmp`;
- writable overlays over `/`, `/usr` and the toolchain directories,
  so the agent can `dnf install` / `pip install` / `cargo install`
  extra tools for this session without touching the host or the
  shared snapshots.

Because it is a plain file on the host, keeping a session is free and
discarding one is `rm`.  Resuming a session means booting again with
the same scratch disk and lower image.

## Kernel and root filesystem: the host's own userspace

The usual way to give a sandbox tools is an image: a Dockerfile, an
OCI image, a curated rootfs.  That works, but it is a second
environment to maintain, and it is always subtly different from the
one the developer actually uses.  The agent then burns time (and the
human's patience) rediscovering that the image has the wrong compiler
version, lacks a linter, or has no idea where the project's
pre-commit hooks expect `clang-format` to live.

agentcracker does not ship a toolchain image.  Instead, **the guest's
`/usr` is a read-only snapshot of the host's `/usr`**, built with the
same EROFS machinery used for the project directory.  Whatever is
installed on the host is what the agent gets: same compilers, same
interpreters, same versions, same agent CLI.

### Layout

The guest root is assembled by acinit from four read-only layers plus
the scratch disk:

| Mount | Source | Contents |
|---|---|---|
| `/` | `base.img` (shipped with agentcracker, a few MB) | acinit, mount points, skeleton `/etc`, usr-merge symlinks (`/bin -> usr/bin`, `/lib -> usr/lib`, ...) |
| `/usr` | `usr.img` - snapshot of host `/usr` | the entire host userspace |
| `/etc` (selected) | copied into `base.img` overlay at boot | the parts of host `/etc` programs need to run - see below |
| `$HOME/...` | `tools.img` - snapshot of named host dirs | user-level toolchains: `~/.rustup`, `~/.cargo/bin`, `~/.local/bin`, `~/.nvm`, `~/go`, pyenv, ... |
| `$PWD` | `lower.img` + scratch upper | the project, as described above |

Each read-only layer gets its own writable overlay on the scratch
disk, so the agent can install additional tools for a session; they
vanish with the session and never reach the host.

### What gets copied from `/etc`

`/etc` is where host secrets and host identity live, so it is _not_
snapshotted wholesale.  agentcracker copies an allowlist of files that
are needed for userspace to function and are not sensitive:

- dynamic linker config: `ld.so.conf`, `ld.so.conf.d/`, `ld.so.cache`;
- `alternatives/` (so `cc`, `python3`, `java` resolve as on the host);
- CA bundle and `ssl/`, `pki/tls/certs` (needed for HTTPS via the
  proxy);
- `os-release`, `localtime`, `nsswitch.conf`, `profile.d/`,
  locale config;
- a synthesised `passwd`/`group` containing only root and the
  invoking user, and a `resolv.conf` / `hosts` pointing at the guest's
  own loopback proxy.

Never copied: `shadow`, `sudoers`, `ssh/`, `krb5.keytab`, machine-id,
NetworkManager connections, anything under `/etc` the allowlist does
not name.

### Toolchains outside `/usr`

Many developer toolchains live in `$HOME` rather than `/usr`, and
`/opt` is common for vendor tools.  agentcracker auto-detects the
usual suspects (rustup, cargo, nvm/fnm, pyenv, go, sdkman, `/opt/*`
entries on `$PATH`) by walking the user's `$PATH`, and snapshots
those directories - and only those - into `tools.img`, mounted at the
same paths in the guest.  `$PATH` itself is passed through, so command
resolution in the guest matches the shell that launched agentcracker.
The agent CLI is found the same way: if `claude` resolves on the host,
it resolves in the guest.

The config file can add or remove directories explicitly:

```toml
# .agentcracker.toml  (or ~/.config/agentcracker/config.toml)
vcpus   = 8
memory  = "8G"
exclude = ["build/", "*.o"]
allow   = ["api.anthropic.com", "github.com", "pypi.org"]
tools   = ["~/.rustup", "~/.cargo", "/opt/llvm-19"]
no_tools = ["~/.local/share/Steam"]
```

### Keeping the snapshot fresh and cheap

`/usr` is several GB on a typical developer workstation, so the
snapshot must be built rarely and reused heavily:

- **Build once, share everywhere.**  One `usr.img` serves every
  session on the host, so its cost is amortised across all of them.
- **Invalidate on package changes.**  The cache key is the package
  database state (rpm/dpkg/pacman db mtime and checksum) plus a cheap
  mtime scan of `/usr/local`.  A `dnf upgrade` triggers a rebuild;
  nothing else does.
- **Rebuild in the background.**  When the key changes, agentcracker
  keeps booting the previous snapshot while it builds the new one,
  then swaps atomically.  A session never waits on a `/usr` rebuild
  except the very first time.  (`agentcracker refresh` forces it.)
- **Compressed, lazily read.**  EROFS with lz4 compression keeps the
  image a fraction of `/usr`'s size, and the guest only pages in the
  blocks it touches.  The page cache on the host keeps hot blocks
  shared across concurrent VMs.
- **Skip what the guest can't use:** `/usr/lib/modules`, firmware,
  kernel source trees under `/usr/src`, `/usr/lib/debug` (opt-in
  via config for people who want debuginfo in the sandbox).

Why a _snapshot_ rather than a live read-only share of `/usr`?  The
same reasons as for the project: point-in-time consistency (a host
package upgrade mid-session cannot pull libraries out from under a
running build), native block-device performance, and no host-side
file server for the guest to attack.

### Kernel

The guest runs its own minimal kernel, not the host's.  The host
kernel is configured for hardware the guest doesn't have, so only the
host's userspace is reused.  This is visible to software that inspects
`uname -r` or `/lib/modules`, which is acceptable: tools that need the
host's running kernel (BPF tracing of the host, loading modules) are
exactly what a sandbox should not offer.

**Where it comes from.**  agentcracker does not ship or download a
prebuilt kernel; `make` (target `kernel`) builds one from source, as
your user:

1. Download `linux-$(KVER).tar.xz` (currently 6.18.60, an LTS release)
   from cdn.kernel.org into `build/` and check it against the SHA-256
   pinned in the `Makefile` (`KVER`, `KSHA256`).  To move to a newer
   point release, update both variables.
2. Start from Firecracker's own guest config,
   `firecracker/resources/guest_configs/microvm-kernel-ci-x86_64-6.18.config`
   (from the `firecracker` submodule) - the minimal virtio-mmio,
   serial-console, no-PCI config Firecracker tests against.
3. Merge in `kernel/agentcracker.config` with
   `scripts/kconfig/merge_config.sh`, then `make olddefconfig`.  The
   additions are:
   - EROFS (with xattrs, POSIX ACLs and security labels) for the
     read-only base, `/usr`, tools and project images;
   - overlayfs, with `redirect_dir`, `metacopy` and `index` off so the
     upper layer stays simple to turn into a diff;
   - vsock, ext4 (scratch disk) and auto-mounted devtmpfs;
   - cgroups, user namespaces, veth and tun, so podman works in the guest;
   - `CONFIG_MODULES` off: everything is built in, and there is no
     initramfs.
4. `make vmlinux` (not `bzImage`: Firecracker boots the uncompressed
   ELF on x86) and copy the result to `build/vmlinux-$(KVER)`.

The kernel is rebuilt when `kernel/agentcracker.config` or Firecracker's
base config changes (for example after a submodule update), or when
`KVER` changes.  The first build takes a few minutes; after that it is
cached in `build/`.

**How agentcracker finds it.**  `make install` copies it to
`$PREFIX/lib/agentcracker/vmlinux`.  At run time agentcracker uses the
first of:

1. `$AGENTCRACKER_LIB/vmlinux`;
2. `<dir of the agentcracker binary>/../lib/agentcracker/vmlinux`;
3. when running from a source checkout (`target/release/agentcracker`),
   the highest-versioned `build/vmlinux-*`.

To try a different kernel, build it with the same config and point
`AGENTCRACKER_LIB` at a directory containing it (alongside `acinit`,
`firecracker` and `seccomp.bpf`).

**Booting.**  Firecracker gets the kernel as `kernel_image_path`, with
`root=/dev/vda ro rootfstype=erofs init=/acinit` plus `pci=off
nomodule` and `quiet` unless `--console` is given.  It reaches PID 1
in ~100ms.

**Licensing.**  The kernel is GPL-2.0.  Building it locally raises no
obligations; anyone redistributing a built `vmlinux` must also provide
the corresponding source and the merged config.

### Trade-offs of committing to the host userspace

- **Not reproducible, by design.**  The environment is "this
  machine", not a pinned image.  That is the right default for an
  interactive developer tool and the wrong one for CI.
- **Reads widen slightly.**  The agent can read all of `/usr` and the
  named toolchain directories.  These should not contain secrets, but
  `/usr/local` and `/opt` occasionally do (licence files, vendored
  config); the `no_tools` list and an `exclude_usr` list cover that.
- **No host daemons.**  The binaries are there but the services are
  not: no host Docker daemon, no system D-Bus, no host database.
  Tools that expect a running service must start their own inside the
  guest.
- **Filesystem layout assumptions.**  This assumes a Linux host with a usr-merged
  (or nearly so) layout; non-merged hosts need `/bin`, `/sbin`,
  `/lib*` snapshotted too, which acinit handles as extra layers.

## acinit: the guest side

A small static binary (Rust or Go) acting as PID 1.  It is the only
custom code in the guest, and it is deliberately boring:

1. Mount `/proc`, `/sys`, `/dev`, `/dev/pts`, cgroup2.
2. Read its session config from the kernel command line / a config
   blob on the scratch disk (target path, uid/gid, env, command, tty
   size).
3. Format or mount the scratch disk; mount `base.img` as `/`, the
   host `/usr` snapshot at `/usr` and the toolchain snapshot at its
   host paths, each with a writable overlay; copy in the allowlisted
   `/etc` files; build the project overlay at `$PWD`.
4. Create a user matching the host uid/gid, so file ownership in the
   final diff is sensible.
5. Start the vsock services (below).
6. Spawn the command in a pty as that user, in `$PWD`.
7. On exit: `sync`, write an exit record, `reboot(RB_POWER_OFF)` -
   Firecracker exits when the guest powers off.

## vsock: the only door

There is no network interface by default.  Every guest/host
interaction goes over vsock, which Firecracker exposes on the host as
a unix socket owned by the user.  Distinct ports carry distinct
services:

| Port | Service | Direction |
|---|---|---|
| 1 | **Terminal** - pty stream, window resize, signals, exit status | host <-> guest |
| 2 | **Control** - status, "export upper layer", graceful shutdown | host -> guest |
| 3 | **Egress proxy** - HTTP CONNECT to an allowlist | guest -> host |
| 4 | **Live share** - read-only 9P (only with `--live`) | guest -> host |

**Terminal.**  The serial console is slow and mixes in kernel output,
so it is reserved for debugging (`--console`).  Instead the CLI puts
the host terminal in raw mode and streams it over vsock to the pty
acinit created - `docker exec -it`, essentially.  `SIGWINCH` becomes a
resize message; Ctrl-C reaches the agent, not the VMM.  A full TUI like
Claude Code just works.

**Egress.**  Agents need to reach the model API, and often package
registries and git hosts.  Rather than a TAP device plus nftables
(which needs root and leaks the whole host network namespace), the
guest gets `HTTPS_PROXY=http://127.0.0.1:3128`, where a tiny forwarder
bridges to vsock port 3.  On the host, agentcracker runs a CONNECT
proxy that:

- permits only hostnames on the allowlist (default: the agent's API
  endpoint; extended via config or `--allow`);
- never sees plaintext (it just splices TLS after CONNECT);
- logs every connection to the session log, so you can see what the
  agent talked to.

`--net=none` disables egress entirely (for fully local agents);
`--net=full` attaches a real NIC for when you genuinely need it.

## Credentials

The agent needs to authenticate to its API; nothing else from the
host's credential store should be reachable.

- agentcracker copies a _minimal_ set of agent config into the guest
  `$HOME` at boot: e.g. for Claude Code, the API key or OAuth token and
  settings - but not `~/.ssh`, `~/.aws`, `~/.gitconfig` credential
  helpers, browser profiles, etc.
- Optionally, transcripts and agent state written in the guest are
  synced back to the host on exit (`--sync-agent-state`), so session
  history survives.
- Credentials never flow back: a token the guest refreshed is not copied
  to the host, because the host cannot tell it from a token for some
  other account that a compromised guest planted (which would quietly
  send the user's later host sessions to that account).
- Accept the limit honestly: the token is inside the VM, so a
  misbehaving agent could exfiltrate it to an allowlisted endpoint.
  Use scoped / short-lived tokens where the provider supports them.
  (A future refinement: the host proxy terminates TLS for the API
  endpoint only and injects the credential, so the guest never holds
  it.)
- `git push` from inside the VM is off by default because no git
  credentials are present - which is usually what you want.  Getting
  work out of the box goes through the apply step below.

## Session lifecycle

```
agentcracker claude
   |
   +- resolve config, session id
   +- reuse usr.img / tools.img           (rebuild in background if stale)
   +- build or reuse lower.img for $PWD      (record base manifest)
   +- create scratch.img
   +- jailer -> firecracker (base, usr, tools, lower, scratch, vsock)
   +- attach terminal ... agent runs ...
   +- guest powers off
   |
   +- summarise:  "14 files changed, 2 added, 1 deleted"
       [d]iff  [a]pply  [k]eep  [x] discard
```

And as explicit subcommands:

```
agentcracker claude [args...]   # run a new session in $PWD
agentcracker ls                 # list sessions (dir, age, size, status)
agentcracker diff [session]     # show changes vs. base
agentcracker apply [session]    # write changes to the real tree
agentcracker resume [session]   # boot again on the same overlay
agentcracker shell [session]    # poke around inside a session
agentcracker rm [session]       # discard
```

Several sessions against the same directory can run concurrently -
each has its own upper layer - which makes "try three approaches in
parallel and keep the best one" a natural workflow.

## Extracting the diff

On exit, the upper layer _is_ the change set: every file the agent
created or modified, plus overlayfs whiteouts (character devices 0/0)
for deletions and `trusted.overlay.opaque` xattrs for replaced
directories.

To read it without mounting an untrusted filesystem image on the host
(see below), the host asks acinit, before poweroff, to serialise the
upper layer as a simple tar-like stream over vsock port 2:
regular files, directories, symlinks, whiteouts-as-deletes, and mode
bits - nothing else.  The host stores that stream in the session
directory and diffs it against the base manifest.

If `$PWD` is a git repo, a second presentation is available: apply the
change set to a temporary worktree based on `HEAD` and show it as a
normal `git diff`, or commit it to a branch
(`agentcracker apply --branch agent/fix-foo`) so it can be reviewed
and merged like any other contribution.

## Applying changes safely

Apply is the only time data crosses from guest to host, so it is where
the paranoia goes:

- **Never mount the scratch image on the host.**  A guest that controls
  the bytes of an ext4 image can target host filesystem parsers.  The
  host only consumes the constrained stream produced above, parsed by
  a small, careful decoder.
- **Path confinement.**  Every path is resolved relative to `$PWD`
  with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`.  No `..`,
  no absolute paths, no writing through a symlink planted by the agent.
- **Strip dangerous metadata.**  No setuid/setgid bits, no device
  nodes, no xattrs, ownership forced to the invoking user.
- **Conflict detection.**  The base manifest records what each file
  looked like when the session started.  If the host copy has changed
  since (you kept working while the agent ran), apply refuses that
  file and reports a conflict rather than silently clobbering it;
  `--merge` attempts a three-way merge for text files.
- **Flag sensitive files.**  Changes to files that the _host_ will
  later execute deserve a louder warning in the review: `.git/hooks/*`,
  `.git/config`, `.envrc`, `.vscode/`, `Makefile`, CI config, shell rc
  files.  An agent quietly adding a git hook is a sandbox escape by
  another name.  By default `.git/` internals are excluded from apply
  entirely; only working-tree changes (and, with `--branch`, the
  agent's commits) come across.

## Host-side hardening

- Firecracker runs under **jailer**: its own chroot containing only the
  images and sockets for this session, a dedicated cgroup (CPU, memory,
  pids limits), a seccomp filter, and new namespaces.
- No TAP device, no bridge, no iptables - so no root.  `/dev/kvm`
  access is the only requirement.
- The host-side services the guest can reach are: the terminal stream,
  the control channel, a CONNECT proxy with an allowlist, and
  (optionally) a read-only 9P server.  That is the entire attack
  surface beyond KVM and Firecracker's virtio devices, and each piece
  is small enough to audit.

## Performance

- **Cold start:** Firecracker to PID 1 is ~125ms; acinit setup is tens
  of ms.  The dominant variable cost is building `lower.img` the first
  time in a directory.
- **Warm start:** with a cached lower image, total time to agent
  prompt should be dominated by the agent CLI's own startup.
- **Snapshot/restore:** Firecracker can snapshot a booted VM.  Keep a
  pre-booted, pre-warmed snapshot of the VM (kernel up, `/usr` mounted, acinit
  waiting, node runtime loaded) and restore it, hot-plugging the
  session disks.  This takes the VM portion of startup to tens of ms.
- **Memory:** guest memory is allocated lazily; a balloon device lets
  idle sessions give memory back.  Several concurrent sessions on a
  laptop is realistic.
- **I/O:** virtio-blk on EROFS and ext4 is close to native for the
  build/test workloads agents run.  The `--live` 9P path is the slow
  one, which is part of why it is not the default.

## Threat model summary

Protects against:

- the agent deleting, corrupting or rewriting files outside the
  sandbox, including the project itself until you choose to apply;
- the agent reading host secrets outside the project (`~/.ssh`,
  cloud credentials, browser data);
- the agent reaching arbitrary network destinations;
- a compromised guest kernel affecting the host, to the extent KVM
  and Firecracker hold up.

Does not protect against:

- the agent reading anything inside `$PWD`, or sending it to an
  allowlisted endpoint;
- misuse of the API credential it was given;
- the human applying a bad change without reading the diff - the
  review step is a real decision, not a formality.

## Related work: other ways to sandbox an agent

agentcracker is not the first answer to this problem, and for many
people it will not be the right one.  The existing options fall
roughly into five families.  The useful questions to ask of each are:

- **Where is the isolation boundary?**  Kernel policy, user-space
  kernel, or hardware virtualisation?
- **What happens to writes?**  Do they go straight to the real tree
  (restricted in scope), or into a copy that needs a deliberate step
  to promote?
- **How is the network controlled?**
- **Whose toolchain does the agent use?**  The host's, or an image's?
- **What does it cost to adopt?**

### 1. Process-level sandboxes on the host kernel

_Examples: Claude Code's built-in sandbox and Anthropic's open-source
`sandbox-runtime` (bubblewrap on Linux, Seatbelt on macOS), OpenAI
Codex CLI's sandbox (Landlock + seccomp on Linux, Seatbelt on macOS),
and general-purpose tools like bubblewrap, firejail, nsjail and
Landlock used directly._

The agent runs as a normal host process, but the kernel is told to
deny it things: writes outside the working directory, reads of
sensitive paths, and network access except via a filtering proxy.

- **Boundary:** the host kernel's own access-control machinery
  (namespaces, Landlock, seccomp, Seatbelt).  A kernel bug is a
  sandbox escape.
- **Writes:** go _directly_ into the real working directory.  The
  sandbox limits _where_ the agent can write, not _whether_ those
  writes are reversible.  `git` is the undo mechanism, and anything
  untracked or ignored is unprotected.
- **Network:** typically a proxy with a domain allowlist - the same
  idea as agentcracker's vsock proxy.
- **Toolchain:** the host's.  This is the big advantage: whatever
  works in your shell works for the agent, with no image to maintain.
  agentcracker's `/usr` snapshot is designed to keep exactly this
  property across a VM boundary.
- **Cost:** near zero.  No startup latency, no extra disk, works on
  macOS.

This is the right default for most people most of the time, and it
is the bar agentcracker has to clear.  The gap it leaves is exactly
the one agentcracker targets: _changes inside the project are
immediate and unreviewed_, and the whole security argument rests on
the host kernel.

### 2. Containers

_Examples: Docker/Podman, VS Code devcontainers (including the Claude
Code reference devcontainer with a default-deny firewall script),
and the various "run the agent in a container" wrappers._

- **Boundary:** namespaces + cgroups + seccomp on the shared host
  kernel - stronger than case 1 in practice because the default
  configuration is more locked down, but the same kind of boundary.
- **Writes:** the project is almost always a read-write _bind mount_,
  so writes land in the real tree, just as in case 1.  The container
  protects the rest of the host, not the project.  (One can bind
  mount read-only and use an overlay inside the container - which is
  essentially agentcracker's filesystem model without the VM.)
- **Network:** iptables/nftables inside the container, or a custom
  network with an egress proxy.  Setting it up well takes effort.
- **Toolchain:** the image's.  Great for reproducibility; friction
  when the host has the tools set up and the image does not.
- **Cost:** a Dockerfile or devcontainer.json per project, a daemon
  (or rootless Podman), and some care that convenience mounts
  (`~/.gitconfig`, the Docker socket, `$HOME`) don't quietly undo the
  isolation.

### 3. User-space kernels

_Example: gVisor (`runsc`), used by several hosted sandbox
providers._

- **Boundary:** the application's syscalls are serviced by a
  user-space kernel written in a memory-safe language, which in turn
  makes a much smaller set of host syscalls.  Much smaller host
  kernel attack surface than containers, without needing KVM.
- **Writes / network / toolchain:** same as containers - gVisor is an
  OCI runtime, so it slots in under Docker with the same mounts and
  images.  It also has its own overlay support for the root
  filesystem.
- **Cost:** some syscalls and filesystem-heavy workloads are notably
  slower, and compatibility is high but not perfect - which matters
  for agents that run arbitrary build systems and test suites.

### 4. Local microVMs and container-in-VM runtimes

_Examples: Kata Containers (OCI containers inside a lightweight VM on
QEMU, Cloud Hypervisor or Firecracker), libkrun-based tools (krunvm,
Podman's `krun` runtime, microsandbox), Apple's per-container
lightweight VMs on macOS, and plain VMs via Lima/Colima/Multipass._

This is agentcracker's family.

- **Boundary:** hardware virtualisation, same as agentcracker.
- **Writes:** most of these share the host directory with virtio-fs
  (or 9P), read-write - so once again writes go to the real tree,
  now across a VM boundary.  The VM protects the host _system_; it
  does not on its own make changes to the _project_ reviewable.
- **Network:** usually a virtual NIC with NAT; filtering is left to
  the user.
- **Toolchain:** the image's (Kata, libkrun) or a full distro (Lima).
- **Cost:** varies from "drop-in Docker runtime" (Kata, krun) to "run
  a whole VM" (Lima).  Startup ranges from sub-second to many
  seconds.

agentcracker is closest to a Kata-or-libkrun microVM with three
opinions added: the project is _read-only_ to the guest and changes
are captured in a guest-private overlay; the network is a vsock-only
allowlist rather than a NIC; and the UX is a single command scoped to
"the directory I'm in" rather than to an image.

### 5. Hosted sandboxes

_Examples: E2B, Vercel Sandbox and Fly Machines (Firecracker-based),
Modal (gVisor-based), Daytona, and the managed environments behind
cloud coding agents such as Claude Code on the web or Codex cloud._

- **Boundary:** strong - usually microVMs or gVisor - and, crucially,
  on _someone else's machine_.  Nothing on your laptop is reachable
  at all.
- **Writes:** into a remote clone of the repo; work comes back as a
  branch or pull request.  This is the cleanest review boundary of
  all, and the one agentcracker's `apply --branch` mode imitates.
- **Network:** controlled by the provider, often configurable.
- **Toolchain:** a provider image, customisable to varying degrees.
- **Cost:** money, latency, a git remote (uncommitted local state is
  not available), and sending the code to a third party.

### Adjacent: isolation of _work_, not of _the agent_

Two techniques are often mentioned alongside sandboxing but solve a
different problem:

- **git worktrees** give parallel agents separate checkouts so they
  don't trample each other.  They give no protection against an agent
  that steps outside its worktree.
- **Filesystem snapshots** (btrfs, ZFS, LVM) give a cheap "undo" for
  the project but don't confine anything; snapshot-before-run plus
  roll-back-on-regret is a reasonable complement to case 1.

### Comparison

| | Boundary | Project writes | Rest of host | Network | Toolchain | Setup | Startup |
|---|---|---|---|---|---|---|---|
| Process sandbox (bwrap, Seatbelt, Landlock) | Host kernel policy | Direct to real tree | Protected (policy) | Proxy allowlist | Host | None | ~0 |
| Container (Docker, devcontainer) | Shared kernel, namespaces | Direct (bind mount) | Protected | DIY firewall | Image | Per-project config | ~1s |
| gVisor | User-space kernel | Direct (bind mount) | Protected | DIY | Image | Runtime install | ~1s |
| Local microVM (Kata, libkrun, Lima) | KVM | Direct (virtio-fs) | Protected | NIC + NAT | Image | Runtime/VM install | 0.2s-10s |
| Hosted sandbox (E2B, cloud agents) | Remote VM / gVisor | Remote clone -> PR | Not reachable | Provider | Provider image | Account | Seconds |
| **agentcracker** | **KVM** | **CoW overlay -> review -> apply** | **Not reachable** | **vsock proxy allowlist** | **Host (`/usr` snapshot)** | **None** | **<1s warm** |

### Where agentcracker wins and where it loses

What it offers that the others mostly don't, _in combination_:

- **Reviewable local changes.**  Every other local option writes into
  the real tree.  agentcracker is the only one where the default
  outcome of a session is "nothing changed until you said so" -
  which hosted sandboxes provide, but only for committed code on a
  remote machine.  That includes uncommitted work, ignored files,
  build artefacts and anything else `git` would not save you from.
- **Hardware isolation with the host's toolchain.**  `cd` and run;
  no Dockerfile, no devcontainer.json, no image to keep in sync.
  Because the guest `/usr` is a snapshot of the host's, the agent
  gets the same tools a process sandbox would give it - the one thing
  every other VM- or container-based option gives up.
- **A tiny, auditable host interface.**  No NIC and no shared
  writable filesystem means the guest can only reach a handful of
  small, purpose-built host services.
- **Cheap parallel experiments** against the same tree, each with its
  own upper layer, without making worktrees.

What it gives up:

- **Some read isolation, and reproducibility.**  Using the host's
  `/usr` and toolchain directories means the agent can read them, and
  the environment is "this machine" rather than a pinned image.  For
  a local developer tool that is the right trade; for CI it is not.
- **Live host state.**  The agent gets a point-in-time copy of the
  host's userspace, not the host itself: no running daemons, and
  packages installed on the host mid-session don't appear until the
  next session.
- **Linux + KVM only.**  Firecracker does not run on macOS, where a
  large share of agent users live; Seatbelt-based sandboxes and
  Apple's container VMs cover that platform.
- **The snapshot cost** on large trees, and the staleness that comes
  with snapshot semantics - the agent doesn't see edits you make
  while it runs, unless you use `--live`.
- **The extra step.**  Review-then-apply is the point, but it is also
  friction; a process sandbox's "changes are already there" is
  genuinely nicer for small, low-risk tasks.

Net: process sandboxes are the right default for everyday use;
hosted sandboxes are the right answer for fire-and-forget work on
committed code; agentcracker targets the space in between - long,
autonomous, local sessions where you want the agent to have a free
hand _and_ want the result to arrive as one reviewable change.

## Implementation notes

What exists today, and where it departs from the design above.  For how
the code works - the session flow step by step, on-disk layout, protocol
and stream formats, security boundaries, and a guide to every source
file - see [IMPLEMENTATION.md](IMPLEMENTATION.md).

**One program.**  `agentcracker` is a single Rust binary.  `make` builds it
twice: dynamically linked for the host, and statically linked as
`acinit`, the guest's PID 1.  The program checks `getpid() == 1` to
decide which role it is playing.  Layout after `make install`:

```
$PREFIX/bin/agentcracker                         (PREFIX defaults to /usr/local)
$PREFIX/lib/agentcracker/{acinit,firecracker,vmlinux,seccomp.bpf}
~/.cache/agentcracker/{usr,tools,base,lower}/   cached images
~/.local/state/agentcracker/sessions/<id>/      per-session state
```

**Images.**  agentcracker writes the read-only EROFS images itself
(`src/erofs.rs`): uncompressed, block-aligned, extended inodes, no
xattrs.  There's no dependency on erofs-utils.  Unreadable files are skipped
instead of failing the build, and file data is copied with
`copy_file_range`, so on btrfs/XFS large files are reflinked (a 21G
`/usr` snapshot takes about 27s and very little disk space).  Small files are copied
normally, after the reflinks, because interleaving them with clones made btrfs
flush constantly.  Because there are no xattrs, file capabilities and SELinux
labels don't reach the guest.  The scratch disk is a sparse 64G
ext4 image formatted on the host with `mkfs.ext4` before first boot.  It's
never mounted or read on the host afterwards.

**Caching.**  `usr.img` is keyed on the package database plus directory
mtimes in `/usr`.  When the key changes, the old image keeps booting while a
detached `agentcracker refresh --background` rebuilds it.  `tools.img`
(toolchain roots found by walking `$PATH`, e.g. `~/.nvm`,
`~/.local/share/claude`, `~/.cargo` + `~/.rustup`) is rebuilt in the
foreground when it goes stale, because agent CLIs auto-update.  The project
snapshot is keyed on its manifest; unused snapshots are dropped after a week.
When the project changed only a little since its last full snapshot, the new
session gets a small delta image instead (changed entries plus overlayfs
whiteouts for deletions), stacked above the old snapshot in the guest; a
full snapshot is written again once over a quarter of the tree has changed.
The tree walk runs on several threads.  On a 91k-file kernel tree a session
starts its command in about 0.8s after an edit (versus about 10s for a full
re-snapshot); `AGENTCRACKER_TIMING=1` prints where startup time goes.

**Guest.**  acinit stacks overlays on the scratch disk over `/`, `/usr`,
each toolchain directory and the project.  It mirrors the host's owner and
mode for any parent directories it has to create, chroots into the result
and runs the command as the invoking user: in a pty of its own when
agentcracker is on a terminal, otherwise with plain pipes (so stdout and
stderr stay separate and tools behave as they would in a host pipeline).  Configuration, the
terminal stream, the home seed and the exported changes all travel over a
single guest-initiated vsock connection; the egress proxy uses a second
port.  On exit, acinit stops stray processes, serialises the project's
upper layer (files, dirs, symlinks, whiteouts, opaque dirs, permission
bits only) and the agent state, then resets the VM, and Firecracker exits.

**Firecracker.**  It's built from the submodule (pinned to the v1.17.0 release) for the gnu target.
Firecracker only ships a seccomp policy for musl, so `make` compiles that
policy with the glibc spellings of the same operations added (`epoll_wait`,
`tgkill`, `FUTEX_WAIT_BITSET` variants, and the `TCGETS2`/`TCSETS2`
ioctls) and drops `blk_worker` (which this version rejects in custom filters).
Without `tgkill` every VM exit was a seccomp kill plus a multi-gigabyte
core dump; `make test` checks the console log for this.  The result
is passed with `--seccomp-filter`.  **The jailer is not used**: it needs
root, which conflicts with the rootless goal.  Firecracker runs as the
user, without a chroot or cgroup limits.

**Agent state.**  The guest `$HOME` lives on the scratch disk, so it
survives `resume` and `shell`, along with anything the agent installed.  On first boot
the guest gets Claude Code's settings, commands, agents, skills, plugins,
this project's transcripts (so `claude --continue` works) and a
`~/.claude.json` filtered to this project.  `.credentials.json` is
refreshed on every boot.  On every exit, `~/.claude/projects` is exported
to `<session>/state/`, where `agentcracker show` summarises it.  If the
guest refreshes the OAuth token, agentcracker says so but never copies it
to the host (see [Credentials](#credentials)); if refresh-token rotation
then logs out Claude on the host, `/login` there fixes it.  Extra paths
come from `home = [...]` and `state = [...]` in the config.

**Apply.**  Implemented as described: confined `openat2` writes, temp file
plus rename, setuid/setgid dropped, `.git/` internals never written,
sensitive files flagged.  Nothing the guest controls reaches the terminal
raw: file names, symlink targets, diff content (on a terminal), branch and
host names and transcript text are printed with control and
bidi-override characters escaped, so a diff under review cannot hide
lines or write the clipboard.  Conflicts are detected by comparing the host's
current size, mtime, inode and mode with the manifest; a change the host
already has (applied before, or the same edit made by hand) is not a
conflict and is skipped, so applying twice is harmless.  `branch` writes only
the agent's new loose objects and packs into a scratch repo, then does
`git fetch` from it with `fetch.fsckObjects`.

**Network.**  The default allowlist is `anthropic.com`, `claude.ai`,
`claude.com` and their subdomains, port 443 only (`host:port` entries allow
other ports); `--allow '*'` admits any host.  Denied hosts show up in
`agentcracker show`, without a ready-made `--allow` command, since the
agent chose them.

The allowlist limits where the VM connects, not what leaves it.  Data can
still go out through the allowed services themselves: the Anthropic API
accepts any API key (so an injected prompt can send data to someone
else's account), and server-side tools such as Claude Code's WebSearch run
on Anthropic's servers, so their queries (and any URLs they fetch) never
pass through agentcracker's proxy at all.  Only `--no-net` closes these
channels, and it also cuts off the agent's API.

So agentcracker keeps what it can out of the guest's reach: the snapshot's
`.git/config` has `user:token@` stripped from remote URLs and
`extraheader` settings removed (the host file is untouched); the
toolchain snapshot leaves out registry credentials (cargo's
`credentials.toml`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`);
and a new session warns about project files that look like credentials
(`.env`, private keys, key stores, ...), which can then be left out with
`exclude`.

**Tests.**  `tests/` holds standalone bash scripts sharing `tests/lib.sh`
(logging, assertions, an isolated session store per test) and
`tests/pty.py` (drives the interactive review on a pseudo-terminal).
`make test` runs them all against the in-tree build (and GitHub Actions
runs it on every push and pull request); `tests/run.sh apply
resume` runs a subset, and any `tests/tNN-*.sh` can be run on its own.
`AGENTCRACKER=/usr/local/bin/agentcracker` tests an installed copy instead.
Tests need `/dev/kvm`; they share `~/.cache/agentcracker` (so the `/usr`
snapshot is built once) and keep a failing test's work directory and
sessions for inspection under `build/tests/`.

**Not implemented yet:** `--live` (9P), `--net=full`, `apply --merge`,
pre-warmed snapshot/restore, the balloon device, `sudo` inside the guest,
and hosts that are not usr-merged.

## Open questions

- **Large monorepos.**  Even with caching and layering, snapshotting a
  multi-GB tree is not free.  Is per-subtree snapshotting (only the
  directory you ran in, plus lazily-fetched extras) worth the
  complexity?  Or should `--live` get faster (a purpose-built
  read-only protocol rather than 9P)?
- **Cloud Hypervisor instead of Firecracker?**  It supports virtio-fs,
  which removes the lower-layer problem entirely, at the cost of a
  larger device model.  Worth keeping the VMM behind an interface.
- **Nested agents and tools.**  Agents increasingly want to run
  containers themselves (test databases, etc.).  The host's
  podman/docker binaries are in the `/usr` snapshot, but the guest
  kernel and acinit need cgroup and overlay support for nested
  containers, and image storage needs to live on the scratch disk.
- **Credential injection at the proxy** so the guest never holds the
  API token - is the TLS-termination complexity worth it?
- **Observability.**  The VM boundary is a natural place to record
  everything the agent did: every exec, every file touched, every
  connection.  A BPF-based recorder inside the guest kernel could
  produce an audit trail alongside the diff (see deeptrace.md).

## License

agentcracker is licensed under the Apache License, Version 2.0; see
[LICENSE](LICENSE).  Firecracker (the `firecracker` submodule) is also
Apache-2.0.  The guest kernel built by the Makefile is GPL-2.0, and
anyone redistributing a built `vmlinux` must also provide its
corresponding source.

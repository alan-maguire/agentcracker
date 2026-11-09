# agentcracker: design

Why agentcracker is built the way it is: the problem, the choices, and
the alternatives.  For what it does and how to use it, see the
[README](README.md); for how the code works, see
[IMPLEMENTATION.md](IMPLEMENTATION.md).  Ideas that were considered but
not built are marked as such.

## Motivation

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

## Getting the project into the VM

Firecracker deliberately has a tiny device model: virtio-blk,
virtio-net, vsock, balloon and entropy.  There is _no_ virtio-fs and
no virtio-9p.  That is part of why it is fast and small, but it means
"just share the directory" is not available off the shelf.  This is
the most important design decision in the whole tool.

The overlay itself is the easy part.  It is assembled _inside the
guest_: a read-only view of the project as the lower layer, and a
guest-private scratch disk for the upper layer.  Because of that, the
host never sees a writable mount of the project at all.  The only
question is how the lower layer gets there.  There were three options:

| Option | How | Pros | Cons |
|---|---|---|---|
| **A. Snapshot image** (built) | The host writes an EROFS image of the project and attaches it as a read-only virtio-blk device | Point-in-time consistent; fastest in-guest I/O; simple guest side; no host-side server | Image build cost on big trees; host edits after start are not visible |
| **B. Live read-only share** (not built) | The host runs a read-only 9P (or NFS) server; the guest mounts it over vsock | No build step; sees host changes | Slower metadata operations; overlayfs calls changes underneath a mounted overlay undefined; more attack surface on the host |
| **C. Block-level CoW** (not built) | dm-snapshot of a loop device, or similar | Very cheap on CoW filesystems | Filesystem-specific; needs privileges for dm |

A matches how people think about handing work to an agent ("here is
the state of my tree, go do something with it"), gives a clean base for
the diff at the end, and keeps the host-side code the guest can talk to
minimal.  What makes it fast enough:

- **EROFS**, written by agentcracker itself (no erofs-utils): read-only,
  compact, cheap to build, and its file data is reflinked from the
  project on btrfs or XFS.
- **Cache by manifest.**  The image is keyed on the tree's
  `(path, mode, size, mtime, inode)`; if nothing changed since the last
  session in this directory, the image is reused.
- **Deltas.**  When only a little changed, a session gets a small delta
  image (the changed entries, plus whiteouts for deletions) stacked
  above the last full snapshot, until over a quarter of the tree has
  changed.
- **Exclusions** (`exclude` in `.agentcracker.toml`) for what the agent
  does not need.

The project appears at the **same absolute path** in the guest as on
the host.  Build systems, `compile_commands.json`, editor configs and
agent transcripts are full of absolute paths; preserving them avoids a
whole category of subtle breakage.

The scratch disk is a sparse file (64G apparent, little actual)
formatted on the host before first boot and never mounted there.  It
holds the project's upper layer, the guest `$HOME` and `/tmp`, and
writable overlays over `/`, `/usr` and the toolchain directories, so
the agent can install extra tools for a session without touching the
host or the shared snapshots.  Keeping a session is free, discarding
one is `rm`, and resuming one is booting again on the same disk.

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
same EROFS writer used for the project directory.  Whatever is
installed on the host is what the agent gets: same compilers, same
interpreters, same versions, same agent CLI.

### Layout

The guest root is assembled by acinit from four read-only layers plus
the scratch disk:

| Mount | Source | Contents |
|---|---|---|
| `/` | `base.img` (shipped with agentcracker, a few MB) | acinit, mount points, skeleton `/etc`, usr-merge symlinks (`/bin -> usr/bin`, `/lib -> usr/lib`, ...) |
| `/usr` | `usr.img` - snapshot of host `/usr` | the entire host userspace |
| `/etc` (selected) | part of `base.img`, built for this host | the parts of host `/etc` programs need to run - see below |
| `$HOME/...` | `tools.img` - snapshot of named host dirs | user-level toolchains: `~/.rustup`, `~/.cargo/bin`, `~/.local/bin`, `~/.nvm`, `~/go`, pyenv, ... |
| `$PWD` | `lower.img` (+ a delta) + scratch upper | the project, as described above |

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

`tools` and `no_tools` in the config add or remove directories
explicitly.

### Keeping the snapshot fresh and cheap

`/usr` is several GB on a typical developer workstation, so the
snapshot must be built rarely and reused heavily:

- **Build once, share everywhere.**  One `usr.img` serves every
  session on the host, so its cost is amortised across all of them.
- **Invalidate on package changes.**  The cache key is the package
  database's mtime (rpm, dpkg, pacman, apk) plus directory mtimes two
  levels into `/usr`, which catches `/usr/local` too.  A `dnf upgrade`
  triggers a rebuild; little else does.
- **Rebuild in the background.**  When the key changes, agentcracker
  keeps booting the previous snapshot while it builds the new one,
  then swaps atomically.  A session never waits on a `/usr` rebuild
  except the very first time.  (`agentcracker refresh` forces it.)
- **Reflinked, lazily read.**  The image is uncompressed, but its file
  data is reflinked from `/usr` on btrfs or XFS, so it costs little disk;
  the guest only pages in the blocks it touches, and the host's page
  cache shares hot blocks across concurrent VMs.
- **Skip what the guest can't use:** `/usr/lib/modules`, firmware,
  kernel source trees under `/usr/src`, `/usr/lib/debug` (the
  `exclude_usr` list, which the config can change).

Why a _snapshot_ rather than a live read-only share of `/usr`?  The
same reasons as for the project: point-in-time consistency (a host
package upgrade mid-session cannot pull libraries out from under a
running build), native block-device performance, and no host-side
file server for the guest to attack.

### The guest kernel

The guest runs its own minimal kernel, not the host's.  The host
kernel is configured for hardware the guest doesn't have, so only the
host's userspace is reused.  This is visible to software that inspects
`uname -r` or `/lib/modules`, which is acceptable: tools that need the
host's running kernel (BPF tracing of the host, loading modules) are
exactly what a sandbox should not offer.  agentcracker builds it from
source rather than shipping one (see the README's "Building").

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

## The guest side: acinit

The only custom code in the guest is acinit, a static PID 1 (the same
Rust program as the host CLI, in another role), and it is deliberately
boring: it receives its configuration from the host over vsock, mounts
the read-only images and stacks writable overlays on the scratch disk,
puts the project at its path, seeds `$HOME`, runs the command as the
invoking user (in a pty of its own when the host side is a terminal,
with plain pipes otherwise), and on exit serialises the project's upper
layer and the agent's state back to the host before resetting the VM.

## vsock: the only door

There is no network interface.  Every guest/host interaction goes over
vsock, which Firecracker exposes on the host as a unix socket owned by
the user:

| Port | Service | Opened by |
|---|---|---|
| 1024 | **Control**: configuration, the home seed, the terminal or pipe streams, the exported changes and state | guest |
| 1025 | **Egress proxy**: one connection per HTTPS `CONNECT` | guest |
| 1026 | **Exec**: extra commands in a running session (`shell`, `log`) | host |

**Terminal.**  The serial console is slow and mixes in kernel output,
so it is reserved for debugging (`--console`).  Instead the CLI puts
the host terminal in raw mode and streams it to the pty acinit created
- `docker exec -it`, essentially.  `SIGWINCH` becomes a resize message;
Ctrl-C reaches the agent, not the VMM.  A full TUI like Claude Code just
works.

**Egress.**  Agents need to reach the model API, and often package
registries and git hosts.  Rather than a TAP device plus nftables
(which needs root and exposes the host's network), the guest gets
`HTTPS_PROXY=http://127.0.0.1:3128`, a forwarder to the proxy port.  On
the host, agentcracker runs a CONNECT proxy that admits only allowlisted
hostnames, never sees plaintext (it splices TLS after `CONNECT`), and
logs every connection.  A real NIC (`--net=full`) was considered and not
built.

## Credentials

The agent needs to authenticate to its API; nothing else from the
host's credential store should be reachable.

- Only a minimal set of the agent's configuration and its login go
  in.  Of git's configuration only the user's name and email go in:
  the rest can hold passwords, tokens and credential helpers.
- Credentials never flow back: a token the guest refreshed is not
  copied to the host, because the host cannot tell it from a token for
  some other account that a compromised guest planted (which would
  quietly send the user's later host sessions to that account).
- The limit, honestly: the token is inside the VM, so a misbehaving
  agent could exfiltrate it to an allowlisted endpoint.  Scoped,
  short-lived tokens help.  (Not built: having the host proxy terminate
  TLS for the API endpoint and inject the credential, so the guest
  never holds it.)
- `git push` from inside the VM fails, because no git credentials are
  present - which is usually what you want.  Work leaves the box through
  review and apply, or as an imported branch.

## Getting changes out

On exit, the overlay's upper layer _is_ the change set: every file the
agent created or modified, plus whiteouts for deletions and opaque
directories for replaced ones.  To read it without mounting an
untrusted filesystem image on the host, acinit serialises it as a
simple stream (regular files, directories, symlinks, whiteouts as
deletes, permission bits - nothing else), which the host diffs against
the manifest recorded when the session started.  The agent's commits
come out the same way, as git objects, and are imported with `git
fetch` and fsck rather than by applying `.git/`.

Apply is the only time data crosses from guest to host, so it is where
the paranoia goes: never mount the scratch image on the host (a guest
that controls an ext4 image's bytes can target the host's filesystem
code); resolve every path beneath the project with
`openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`; drop setuid and
setgid bits, device nodes and xattrs; refuse to overwrite what the
host changed since the snapshot; flag changes to files the host will
later run (`.git/hooks`, `Makefile`, CI config, editor settings), since
an agent quietly adding a git hook is a sandbox escape by another
name; and never write inside `.git/`.  (Not built: a three-way merge
for conflicting text files.)

## Host-side hardening

- A runaway or hostile guest cannot fill the host's disk: what it sends
  the host - its changes, state, console and output - is written only
  while the filesystem keeps 2G free, and its own disks (sparse files it
  grows by writing to them) stop growing because the session is stopped
  at the same point, and does not start below it.
- Firecracker runs **without the jailer**, which needs root: it is an
  ordinary process of the invoking user, confined by its seccomp filter
  (a per-thread syscall allowlist) and nothing else.  There is no chroot,
  cgroup or namespace around it, so a guest that escaped into the VMM
  would have that user's access to the host.  Wrapping it in a user
  namespace or Landlock is a possible future step.
- No TAP device, no bridge, no iptables - so no root.  `/dev/kvm`
  access is the only requirement.
- With `boot = true`, the guest also gets nested virtualisation, so
  the host's KVM nested code (nVMX/nSVM) faces a kernel the agent
  controls.  Without it the host hides VMX and SVM from the guest (a
  Firecracker CPU template), so that code is out of reach.
- The host-side services the guest can reach are: the control
  connection (which carries the terminal stream), and a CONNECT proxy
  with an allowlist.  (`agentcracker shell` also connects to a server in
  the guest, but that connection is opened by the host.)  That is the
  entire attack surface beyond KVM and Firecracker's virtio devices,
  and each piece is small enough to audit.

## Performance

- **Cold start:** Firecracker to PID 1 is ~125ms; acinit setup is tens
  of ms.  The dominant variable cost is the first project snapshot in
  a directory.
- **Warm start:** with a cached project image, time to the agent's
  prompt is dominated by the agent CLI's own startup.
- **I/O:** virtio-blk on EROFS and ext4 is close to native for the
  build and test workloads agents run.
- **Not built:** restoring a pre-booted Firecracker snapshot (kernel up,
  `/usr` mounted, acinit waiting) to take VM startup to tens of ms, and
  a balloon device so idle sessions give memory back.

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
  review step is a real decision, not a formality;
- trusting the agent's account of its work: its transcripts and test
  results are written inside the VM, by an environment it controls, so
  only the proxy's network log is the host's own observation.

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
  all, and the one agentcracker's `branch` imitates.
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
  while it runs.
- **The extra step.**  Review-then-apply is the point, but it is also
  friction; a process sandbox's "changes are already there" is
  genuinely nicer for small, low-risk tasks.

Net: process sandboxes are the right default for everyday use;
hosted sandboxes are the right answer for fire-and-forget work on
committed code; agentcracker targets the space in between - long,
autonomous, local sessions where you want the agent to have a free
hand _and_ want the result to arrive as one reviewable change.

## Open questions

- **Large monorepos.**  Even with caching and layering, snapshotting a
  multi-GB tree is not free.  Is per-subtree snapshotting (only the
  directory you ran in, plus lazily-fetched extras) worth the
  complexity?  Or a live read-only share (option B above), with a
  purpose-built protocol rather than 9P?
- **Cloud Hypervisor instead of Firecracker?**  It supports virtio-fs,
  which removes the lower-layer problem entirely, at the cost of a
  larger device model.  Worth keeping the VMM behind an interface.
- **Nested agents and tools.**  Agents increasingly want to run
  containers themselves (test databases, etc.).  The host's
  podman/docker binaries are in the `/usr` snapshot and the guest
  kernel has cgroups, user namespaces, veth and tun for them, but
  rootless containers in the guest are untested, and image storage
  would need to live on the scratch disk.
- **Credential injection at the proxy** so the guest never holds the
  API token - is the TLS-termination complexity worth it?
- **Observability.**  The VM boundary is a natural place to record
  everything the agent did: every exec, every file touched, every
  connection.  A BPF-based recorder inside the guest kernel could
  produce an audit trail alongside the diff; `agentcracker log`
  already merges the proxy's log with the agent's own transcripts.

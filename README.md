# agentcracker: disposable microVMs for coding agents

Coding agents are most useful when they are allowed to act - run the
build, run the tests, rewrite a dozen files - and most dangerous for the
same reason.  agentcracker runs the agent in a Firecracker microVM of
its own, with your project at the same path, your own toolchain (a
snapshot of the host's `/usr`), and HTTPS only to an allowlist.  Every
write lands in a copy-on-write layer inside the VM; your directory is
never written to.  When the agent exits you get one decision: review
the changes, then apply them, keep the session for later, or throw it
away.

_The agent gets full autonomy inside a box, and you get a single,
reviewable decision at the boundary._  [DESIGN.md](DESIGN.md) explains
why it is built this way and how it compares with other sandboxes;
[IMPLEMENTATION.md](IMPLEMENTATION.md) is a guide to the code; `man
agentcracker` is the full reference.

## Quick start

```
$ git clone --recursive <this repo> && cd agentcracker
$ make                    # builds firecracker (submodule), a guest kernel and
                          # agentcracker; run as your user, not root
$ make test               # optional: run tests/ against the build
$ sudo make install       # copies into /usr/local (or: make install PREFIX=~/.local)
$ cd ~/src/myproject
$ agentcracker claude     # or: agentcracker codex  (acr is short for agentcracker)
                          # the first run snapshots /usr (~30s on btrfs); after that
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
takes a few minutes once; see [The guest kernel](#the-guest-kernel) for details.

## A session

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
with `agentcracker apply`).  In a git repository, what git ignores - build
output - is counted but left out of the list, the diff and apply (`[i]` in
the menu, or `--ignored`, brings it in), so the agent can build and test
without burying its edits under thousands of object files.

## Commands

```
agentcracker [--allow HOST]... [--no-net] [--console] [--detach] [--branch NAME] <command> [args...]
agentcracker ls     [--json]         # sessions: age, status, changes, directory
agentcracker show   [--json] [SESSION]   # changes, network log, Claude transcripts, disk use
agentcracker log    [--json] [-f] [SESSION]   # network requests + the agent's tool calls
agentcracker diff   [--ignored] [SESSION]   # --ignored: include what git ignores
agentcracker apply  [--ignored] [SESSION]
agentcracker branch [SESSION]        # agent's commits -> branch agentcracker/<id>, or --branch's NAME
agentcracker resume [SESSION] [command...]
agentcracker shell  [SESSION]        # also opens a shell inside a *running* session
agentcracker wait   [--json] [SESSION...]   # for --detach'ed sessions
agentcracker stop   [SESSION...]     # end running sessions, keeping their changes
agentcracker rm     SESSION...
agentcracker refresh                 # rebuild /usr + toolchain snapshots now
agentcracker cache  [--drop [DIR]]   # per-project build caches (the guest's ~/.cache)
```

`SESSION` is an id prefix and defaults to the latest session for the
current directory.  `acr` is short for `agentcracker`.

- **Review later.**  A kept session can be diffed, applied, resumed
  (`resume`: boot it again on the same disk) or opened in a shell
  (`shell`, also while it runs) at any time.
- **Watch it.**  `log` is one timeline of the session's network
  requests, the agent's tool calls and its test kernel boots - while it
  runs too (`log -f` follows it).  `show` summarises a session: changes,
  network activity per host, transcripts, disk use.
- **Several at once.**  `--detach`, `wait`, `stop` and `--json` let
  scripts run several agents at once, each in its own VM, against the
  same tree, and compare their results; applying always stays a
  separate, deliberate step.

## Configuration

`~/.config/agentcracker/config.toml`, and `.agentcracker.toml` in the
project (which cannot set `boot`, and whose lists add to yours):

```toml
vcpus    = 8
memory   = "8G"                  # default: half of RAM, at most 8G
net      = true                  # false: no network at all (as --no-net)
allow    = ["github.com", "*.github.com"]   # added to the agent's defaults
exclude  = ["build/", "*.o"]     # left out of the project snapshot
cache    = true                  # the project's persistent ~/.cache (default)
# boot   = true                  # acrboot (user config only; off by default)
agent    = "claude"              # when the command doesn't say (claude, codex)
tools    = ["/opt/llvm-19"]      # extra toolchain directories to snapshot
no_tools = ["~/.local/share/Steam"]
exclude_usr = ["lib/debug"]      # left out of the /usr snapshot
home     = ["~/.config/foo"]     # extra files copied into the guest's $HOME
state    = ["~/.local/share/foo"]  # extra guest files kept with the session
env      = ["MY_VAR"]            # host environment variables passed in
```

## What's inside the VM

- **Your userspace.**  The guest's `/usr` is a read-only snapshot of the
  host's, and toolchains in your home or `/opt` that are on `$PATH`
  (rustup, cargo, nvm, pyenv, go, the agent CLI itself, ...) are
  snapshotted at the same paths, so the agent finds the tools your shell
  would.  Snapshots are shared by every session and rebuilt in the
  background when your packages change: the session that notices boots
  on the old one.  After installing something, `agentcracker refresh`
  rebuilds them at once.  `/etc` is an allowlisted subset (linker
  config, certificates, locale, ...), never secrets.
- **The project**, at the same path, from a snapshot taken when the
  session starts (reused, or with a small delta, when little changed).
  The agent sees a normal writable checkout; edits you make on the host
  meanwhile are not visible to it.
- **Its own kernel**, built by `make` (see "Building"), not the host's.
- **Its own disk** for everything it writes: the project's changes,
  `$HOME`, `/tmp`, and anything it installs - all gone with the session.
- **The agent's login and configuration** (for Claude Code: settings,
  skills, plugins, this project's transcripts so `claude --continue`
  works), and git's `user.name` and `user.email` - nothing else of your
  home, no `~/.ssh`, no cloud credentials, and none of the rest of your
  git configuration.  A login the agent refreshes is never copied back.

## Network

There is no network device.  The agent gets HTTPS through a proxy on
the host that allows only listed hosts: by default the agent's own
(`anthropic.com`, `claude.ai`, `claude.com` and their subdomains for
Claude Code; `openai.com` and `chatgpt.com` for Codex), plus `allow` in
the config and `--allow HOST` (`*.example.com` for subdomains,
`host:port` for another port, `'*'` for any host).  Refused hosts show up
in `log` and `show`.  `--no-net` turns the network off entirely.

The allowlist limits where the VM connects, not what leaves it.  Data
can still go out through the allowed services: the Anthropic API accepts
any API key (so an injected prompt could send data to someone else's
account), and server-side tools such as WebSearch run on Anthropic's
servers, so the proxy never sees them.  agentcracker keeps what it can
out of the guest's reach - tokens are stripped from the snapshot's
`.git/config`, registry credentials (`.npmrc`, `.pypirc`, `.netrc`, ...)
are left out of the toolchain snapshot - and warns about project files
that look like credentials, which `exclude` can leave out.

## Reviewing and applying

Apply is the only time anything crosses from the VM to your directory,
so it is careful:

- the host never mounts the VM's disk: it reads a narrow stream of
  files, directories, symlinks, deletions and permission bits;
- every path is resolved beneath the project (`openat2` with
  `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), each file is written to a
  temporary name and renamed into place, and setuid and setgid bits are
  dropped;
- a file you changed on the host since the session started is a
  conflict: skipped unless you choose to overwrite it;
- changes to files the host will run - `Makefile`, CI config, editor
  settings, dotfiles, new executables - are flagged for review, and
  nothing inside `.git/` is ever written;
- what git ignores (build output) is counted but left out, by the host's
  rules, not the agent's copy of `.gitignore`; `--ignored` or `[i]`
  brings it in;
- nothing the agent wrote reaches your terminal raw: file names, diff
  content and transcript text are shown with control characters escaped.

## Git: the agent's commits

If the agent commits, `agentcracker branch` (or `[b]` on exit) imports
its commits into your repository as a branch, without touching your
current branch, index or work tree: only git objects are taken from the
VM, and `git fetch` checks them.  The branch is `agentcracker/<id>`
(replaced by a later import), or the one you name when you start:

```
agentcracker --branch fix/foo claude
```

starts the agent on a new branch `fix/foo` at your `HEAD`, tells it to
commit there, and imports into `fix/foo` - by fast-forward only, so a
resumed session's later commits extend it, and rewritten history is
refused.  The commits carry your git name and email.

## The build cache

The scratch disk starts empty, so every session would build the project
from cold.  Each project directory therefore also gets one persistent
disk, its **build cache**, mounted as the guest's `~/.cache` in every
session of that project.  That is where ccache, sccache, Go's build cache
and pip already keep theirs, so they become incremental across sessions
with no setup.  An out-of-tree build can go there too:

```
make O=~/.cache/kbuild -j$(nproc)    # a kernel: tinyconfig vmlinux, 50s -> 4s next session
```

(an `O=` kernel build needs a clean source tree; see "Kernel
development in a session" for that and for ccache).

- **Per project, one at a time.**  The cache is keyed on the project
  directory and locked by the session using it; a concurrent session of
  the same project gets an empty `~/.cache` of its own (and says so).
- **Never on the host.**  The host creates, attaches and deletes the
  image (a sparse ext4 file under
  `~/.local/state/agentcracker/caches/`) but never mounts it.  What an
  agent leaves there can only mislead later sessions of the same
  project, not the host; `agentcracker cache --drop` starts it afresh.
- **Visible.**  `agentcracker cache` lists every project's cache with its
  size and last use; `show` reports the session's.  `cache = false` in
  the config turns it off.

## What the agent is told

The agent would not otherwise know any of this.  On every boot acinit
writes, in the guest only, a short section into the agent's user-level
instructions file (`~/.claude/CLAUDE.md`; Codex's `AGENTS.md`, or
`AGENTS.override.md` if you use one): that its changes are reviewed
before they reach your directory, which hosts the network allows (and
that a `403` means asking you, not retrying), that `~/.cache` persists,
which branch to commit on (with `--branch`), and, with `boot = true`,
that `acrboot` exists.  The section sits between
markers, so the next boot replaces it, and the rest of the file is yours.
With `boot = true` it also installs an `agentcracker-acrboot` skill (in
the agent's `skills/`, a format Claude Code and Codex share) with the
details: configuring the kernel, KUnit, root disks, decoding a panic.  The
files are written as you (`setfsuid`), and none of them leaves the VM: your
host copies are never changed.

## Booting the agent's kernel: `acrboot`

An agent working on a kernel can build it, and with `boot = true` in
`~/.config/agentcracker/config.toml` it can run it too: the session's VM
gets nested virtualisation (`/dev/kvm`, with the host's VMX or SVM passed
through) and an `acrboot` command:

```
acrboot [--cpus N] [--mem SIZE] [--timeout SECS] [--append ARGS] [--disk FILE]...
        [--run CMD [--dir DIR]] VMLINUX
```

It boots the kernel in a Firecracker microVM of its own, inside the
session's, and shows the serial console; `acrboot` exits 0 when the
kernel shut the VM down, 1 on a panic, 124 on a timeout, 2 on an error.
Three uses:

```
acrboot --append "kunit.filter_glob=list* kunit_shutdown=reboot" vmlinux   # built-in KUnit suites
acrboot --disk rootfs.img vmlinux                                          # a root disk (/dev/vda)
acrboot --timeout 3600 --dir tools/testing/selftests/bpf --run ./test_progs vmlinux   # selftests
```

`--run CMD` needs no root filesystem: the test VM boots on the session's
own userspace (its root and `/usr` images, read-only), with a copy of
`DIR` (default `.`) at the same path, read-write and discarded after.
acinit is its init: it mounts `/proc`, `/sys`, `/dev`, tmpfs on `/tmp`
and friends, bpffs, debugfs, tracefs and cgroup2, brings up `lo`, runs
`CMD` as root with `sh -c` in `DIR`, and `acrboot` exits with its
status (124 on a timeout, 125 if the VM ended without it finishing).
So the BPF selftests run as built, against the libraries they were
built with - `vmtest.sh` itself cannot run in a session (it wants QEMU,
a downloaded root filesystem and `sudo`).  The kernel needs EROFS,
ext4 and tmpfs, which `acrboot --kconfig` includes.

- **The kernel** must be the uncompressed ELF `vmlinux` (Firecracker does
  not boot a `bzImage`) with the options Firecracker needs (virtio-mmio,
  virtio-blk, ACPI, `KVM_GUEST`, an 8250 console; see
  `firecracker/docs/kernel-policy.md`).  `acrboot --kconfig` prints them
  (`kernel/acrboot.config`) for `scripts/kconfig/merge_config.sh`.  End a
  boot with a reboot (`kunit_shutdown=reboot`, `reboot -f`): the VM stops
  when the kernel resets it.
- **The test VM** gets no network and no vsock, its disks read-write in
  place, CPUs and memory out of the session's (default 2 CPUs and 1G),
  and a timeout (default 10 minutes).  It is stopped a few seconds after a
  panic, and when the session ends.  A boot to init takes about half a
  second.
- **On record.**  Each boot is a line in the guest's
  `~/.local/state/acrboot/boot.log`, with its console (the first 4M, last
  20 boots) beside it, so each boot is a `boot` line in `agentcracker
  log`, read out of the VM while it runs
  (`boot  PANIC  29M kernel, 1.3s: panic=0`).
- **The host** must allow nested virtualisation: `kvm_intel` or `kvm_amd`
  with `nested=1` (the default on current kernels; check
  `/sys/module/kvm_intel/parameters/nested`).  Without it `acrboot` says
  so.
- **Opt-in, and only by you.**  Nothing runs on the host: a test kernel
  that escapes its VM lands in the session's VM, and its disk, memory and
  CPUs are the session's.  But it hands the agent ring 0 in a VM whose
  exits the host's KVM handles first, so the host's nested-virtualisation
  code faces a kernel the agent controls - more than a session otherwise
  exposes.  So it is off by default, and without it the guest has no
  `/dev/kvm` and the host hides VMX and SVM from it (a Firecracker CPU
  template), so not even a guest kernel the agent took over can reach
  that code.  A project's `.agentcracker.toml` cannot turn it on (a
  cloned repository must not grant that to its agents).

## Kernel development in a session

Putting the pieces together for a kernel tree - say, having the agent
fix a BPF bug and prove the fix with the BPF selftests.  The agent's
skill covers the build and test steps, so usually you just ask for the
result; the setup is yours.

**Setup, once.**  `boot = true` in `~/.config/agentcracker/config.toml`,
and enough memory for a kernel build plus a test VM (`memory = "12G"`;
the default is at most 8G).  If you install packages on the host for the
build (`ccache`, `clang`, `pahole`), run `agentcracker refresh` before
the next session: otherwise that session still boots the previous `/usr`
snapshot while a new one is built in the background.

**Building.**  A plain in-tree build works: the objects are kept for the
session, and dropped when it ends, so the next session builds from cold
again (for scale, bpf-next with the BPF selftests' configuration takes
about 11 minutes from scratch with 8 vCPUs, and its selftests 3 more).
Two options make later sessions faster, alone or together, because
`~/.cache` persists:

- **ccache**, if it is installed: `make CC="ccache gcc" -j$(nproc)`.
  Recompiling comes from the cache, in-tree or not.  Pass the same `CC`
  every time (the kernel records it in `.config`), and consider raising
  ccache's 5G limit (`ccache -M 20G` in a session; the setting is kept in
  `~/.cache/ccache`).
- **An out-of-tree build**: `make O=~/.cache/kbuild -j$(nproc)`, so make
  skips whatever has not changed since the last session.  `make O=`
  refuses a source tree that has an in-tree build in it ("The source tree
  is not clean, please run 'make mrproper'"): run `make mrproper` in the
  tree on the host (in a session it only cleans that session's copy), or
  give sessions a worktree of their own (`git worktree add ../linux-acr`).

The cache belongs to the directory `agentcracker` was started in, one
session at a time (a second gets an empty `~/.cache`, and says so); it
is 64G, sparse, and `agentcracker cache` shows how much is used.

**Configuring for the BPF selftests.**  Their configuration fragments,
plus what Firecracker needs (shown out of tree; in-tree, drop `O=`,
`-O $O` and `KBUILD_OUTPUT=`, and use `.config` and `vmlinux` in the
tree):

```
O=~/.cache/kbuild B=tools/testing/selftests/bpf
cat $B/config $B/config.vm $B/config.x86_64 > $O/.config
acrboot --kconfig > /tmp/acrboot.config
scripts/kconfig/merge_config.sh -m -O $O $O/.config /tmp/acrboot.config
make O=$O olddefconfig && make O=$O -j$(nproc)
make -C $B KBUILD_OUTPUT=$O -j$(nproc)
```

The selftests build in the source tree, so they are rebuilt each
session; git ignores their output, so it stays out of the review.

**Running them.**  `--run` boots the new kernel on the session's own
userspace with a copy of the selftests directory, so `test_progs` runs
as built:

```
acrboot --cpus 8 --mem 8G --timeout 3600 --dir $B --run './test_progs -j' $O/vmlinux
acrboot --cpus 8 --mem 8G --dir $B --run './test_progs -t NAME' $O/vmlinux
```

`acrboot` exits with `test_progs`' status.  The whole suite takes two
to three minutes on 8 vCPUs, and copying the 1.5G directory into the
test VM a few seconds per boot.

**Verifying a fix.**  Reproduce first: run the failing test with `-t`
on a kernel built without the fix and keep its output, then apply the
fix, rebuild (incremental), and run it again, then the whole suite for
regressions.  Each boot is a `boot` line in `agentcracker log`, with its
console kept in the session, so you can check what the agent ran and
what it saw before you `apply` its change.

**What differs from `vmtest.sh` and CI.**

- **The userspace is your host's.**  Tests that need a tool your host
  lacks fail (`xdp_synproxy` wants `iptables-legacy`), and the BPF
  programs are compiled by your host's clang: a development snapshot can
  make the verifier reject programs that CI's release clang does not.
  Compare against a run on an unmodified kernel before blaming the fix.
- **No PMU.**  Tests that need hardware performance counters fail.
- **No QEMU.**  `vmtest.sh` cannot run in a session; `acrboot --run`
  replaces it.

## A working cycle: write, test, commit

The pieces above make one loop: the agent writes the code, tests it in
its own VM (for a kernel, with `acrboot`), and commits it; you review
the commits and take them as a branch.

1. **Start the session on a branch.**  `agentcracker --branch fix/foo
   claude` in your repository (with `boot = true` for a kernel).  The
   agent starts on a new branch `fix/foo` at your `HEAD`, and is told to
   commit its work there.  Your own checkout stays where it is.
2. **Ask for the change, the test and the commits.**  For example: "fix
   the verifier bug in ..., reproduce it with `test_progs -t NAME` under
   acrboot before and after, run the whole suite, and commit the fix and
   the new test separately with a Signed-off-by".  The session's git
   has your name and email (and nothing else of your git configuration),
   so the commits carry your identity.
3. **Watch, or not.**  `agentcracker log -f` in another terminal shows
   its commands, test boots and network requests as they happen.
4. **On exit, take the branch.**  The review menu says the agent
   committed and offers **`[b]ranch`**: it imports the commits into your
   repository as `fix/foo`, without touching your current branch, index
   or work tree.  Review them like anyone's (`git log -p main..fix/foo`),
   and use **`[d]iff`** for anything it changed but did not commit.  Then
   merge, rebase or send them as you would any branch.
5. **Iterate.**  `agentcracker resume SESSION` boots the same session
   again, still on `fix/foo`; ask for changes, then `agentcracker branch`
   (or `[b]` on exit) again.  A named branch is only ever fast-forwarded:
   if the agent rewrote commits you already imported, or you moved
   `fix/foo` yourself, the import is refused and says so (nor does it
   import into a branch you have checked out).

Without `--branch`, the commits are imported as `agentcracker/<id>`
(overwritten by a later import), wherever the agent made them.

## Limitations

- **Linux on x86_64 with KVM only.**  Firecracker doesn't run on macOS.
- **No root in the guest**: the agent runs as you, so it can't `sudo`
  or install system packages (but can install into its own `$HOME`).
- **A snapshot, not a live view**: the agent doesn't see edits you make
  on the host while it runs.
- **Your host's userspace**: the environment is this machine, not a
  pinned image - right for interactive work, wrong for CI.  Hosts that
  are not usr-merged are not supported.
- **The first snapshot of a large tree** takes a while, especially
  without reflinks (see Quick start).
- **Not implemented**: a live read-only share of the project, a real
  network device, three-way merges on apply, pre-booted VM snapshots
  for faster start.

What it protects against, and what it doesn't: the agent can't change
anything outside the VM until you apply, can't read your other files
(`~/.ssh`, cloud credentials, browser data) and can only connect to
allowed hosts; a guest kernel exploit has KVM and Firecracker to get
through.  It can read the whole project and send it to an allowed
host, it can misuse the API login it was given, and it can't stop you
applying a bad change without reading it.  [DESIGN.md](DESIGN.md) has
the full threat model.

## Building

`make` builds Firecracker (from the `firecracker` submodule, pinned to
v1.17.0), the guest kernel, and agentcracker, as your user.

**agentcracker** is one Rust program: `make` builds it for the host and,
statically linked, as `acinit`, the guest's init (which is also the
`acrboot` command).  After `make install`:

```
$PREFIX/bin/agentcracker                         (PREFIX defaults to /usr/local)
$PREFIX/bin/acr -> agentcracker                  short alias
$PREFIX/lib/agentcracker/{acinit,firecracker,vmlinux,seccomp.bpf}
~/.cache/agentcracker/{usr,tools,base,lower}/   cached images
~/.local/state/agentcracker/sessions/<id>/      per-session state
~/.local/state/agentcracker/caches/             per-project build caches
```

**Firecracker** runs as you, without the jailer (which needs root),
under a seccomp filter `make` compiles from Firecracker's own policy
with the glibc spellings of its syscalls added.

### The guest kernel

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

## Tests

`tests/` holds standalone bash scripts sharing `tests/lib.sh`.  `make
test` runs them all against the in-tree build; `tests/run.sh apply
resume` runs a subset, and any `tests/tNN-*.sh` runs on its own.
`AGENTCRACKER=/usr/local/bin/agentcracker` tests an installed copy.
They need `/dev/kvm`, and keep a failing test's work directory under
`build/tests/`.

## License

agentcracker is licensed under the Apache License, Version 2.0; see
[LICENSE](LICENSE).  Firecracker (the `firecracker` submodule) is also
Apache-2.0.  The guest kernel built by the Makefile is GPL-2.0, and
anyone redistributing a built `vmlinux` must also provide its
corresponding source.

//! What the agent is told about its environment.
//!
//! Inside a session the agent does not know it is in a VM whose changes
//! are reviewed, that the network is an allowlist, that `~/.cache` persists
//! or that it can boot kernels.  On every boot agentcracker writes, in the
//! guest only:
//!
//! - a short section in the agent's user-level instructions file
//!   (`~/.claude/CLAUDE.md`, Codex's `AGENTS.md`), between markers, so it
//!   is replaced rather than repeated on the next boot and the user's own
//!   text is kept;
//! - with `boot = true`, an `agentcracker-acrboot` skill (`SKILL.md` in the
//!   agent's `skills/`, a format Claude Code and Codex share), and without
//!   it, nothing there.
//!
//! None of it reaches the host: these files are not part of the session's
//! exported state.

use std::path::Path;

use crate::agent::Profile;
use crate::proto::AgentFile;

/// Start and end markers of agentcracker's section in an instructions file.
pub const BEGIN: &str = "<!-- agentcracker: begin (written in this session's VM only; the host's copy of this file is unchanged) -->";
pub const END: &str = "<!-- agentcracker: end -->";

/// Name of the acrboot skill.
const SKILL: &str = "agentcracker-acrboot";

/// What a session tells its agent.
pub struct Context<'a> {
    /// The project directory.
    pub cwd: &'a Path,
    /// Whether the guest has network access, and the allowlist.
    pub net: bool,
    pub allow: &'a [String],
    /// Whether `~/.cache` is the project's build cache this boot.
    pub cache: bool,
    /// Whether `acrboot` is enabled, and the session's CPUs and memory
    /// (the test VMs' limits).
    pub boot: bool,
    pub vcpus: u32,
    pub mem_mib: u64,
}

/// The files to write into the guest's home for profile `p` (`home`: the
/// user's home, for the profile's directory).
pub fn agent_files(p: &Profile, home: &Path, c: &Context) -> Vec<AgentFile> {
    // the first instructions file the user has, else the last name
    let names = p.instructions;
    let file = names.iter().find(|n| home.join(p.path(home, n)).exists()).unwrap_or(&names[names.len() - 1]);
    let mut out = vec![AgentFile { path: p.path(home, file), content: Some(instructions(c)), block: true }];
    out.push(AgentFile {
        path: p.path(home, &format!("skills/{SKILL}/SKILL.md")),
        content: c.boot.then(|| skill(c)),
        block: false,
    });
    out
}

/// The section for the instructions file.
fn instructions(c: &Context) -> String {
    let cwd = c.cwd.display();
    let mut s = format!(
        "{BEGIN}\n## agentcracker sandbox\n\n\
         You are running inside an agentcracker microVM, not directly on the user's machine.\n\n\
         - Your changes to `{cwd}` stay in this VM until the user reviews them and chooses to apply them. \
         Work normally - edit, build, test, commit.  Changes outside `{cwd}` never leave this VM.\n"
    );
    if c.cache {
        s.push_str(
            "- `~/.cache` persists across this project's sessions: keep build caches there (ccache, Go and pip \
             use it already; an out-of-tree build can use `make O=~/.cache/<name>`).\n",
        );
    }
    if !c.net {
        s.push_str("- There is no network access in this session.\n");
    } else {
        let hosts = if c.allow.iter().any(|a| a.trim() == "*") { "any host".to_string() } else { c.allow.join(", ") };
        s.push_str(&format!(
            "- Network access is HTTPS only, through a proxy that allows: {hosts}.  A connection refused with \
             `403 Forbidden` means that host is not allowed: don't retry it or look for a way around it - tell \
             the user which host you need and why (they can allow it with `--allow HOST`).\n"
        ));
    }
    if c.boot {
        s.push_str(&format!(
            "- `acrboot` boots a Linux kernel you built in a separate microVM and shows its console - for KUnit, \
             boot tests and reproducing crashes.  See the `{SKILL}` skill, or `acrboot --help`.\n"
        ));
    }
    s.push_str(END);
    s.push('\n');
    s
}

/// The acrboot skill.
fn skill(c: &Context) -> String {
    format!(
        r#"---
name: {SKILL}
description: Boot a Linux kernel you built in a separate microVM and read its console - run KUnit tests, check that a change boots, reproduce a crash. Use in a Linux kernel tree when compiling is not enough and the kernel has to run.
---

# Booting a kernel you built: acrboot

You are in an agentcracker VM with nested virtualisation: `acrboot` boots
a kernel in a microVM of its own, inside this one (no network), and shows
its serial console.

```
acrboot [--cpus N] [--mem SIZE] [--timeout SECS] [--append ARGS] [--disk FILE]... VMLINUX
```

Exit status: 0 the kernel shut the VM down, 1 kernel panic, 124 timeout,
2 error.  Defaults 2 CPUs, 1G, 600s; at most {vcpus} CPUs and {mem}M here
(the test VM's memory comes out of this VM's).

## 1. Configure the kernel to boot under Firecracker

Use the uncompressed ELF `vmlinux` at the top of the build tree, never
`arch/x86/boot/bzImage`.  Merge the options Firecracker needs into your
configuration:

```
acrboot --kconfig > acrboot.config
scripts/kconfig/merge_config.sh -m .config acrboot.config   # with O=, add -O <dir> and use <dir>/.config
make olddefconfig
```

Build out of tree in `~/.cache` when you can (`make O=~/.cache/kbuild`):
it persists across sessions, so the next build is incremental, and build
output stays out of the user's review.

## 2. Run built-in tests (KUnit)

Enable the suites (`CONFIG_KUNIT=y` plus e.g. `CONFIG_LIST_KUNIT_TEST=y`),
build, then:

```
acrboot --append "kunit.filter_glob=list* kunit_shutdown=reboot" vmlinux | tee kunit.log
```

The results are KTAP lines (`ok N ...` / `not ok N ...`) in the console.
`kunit_shutdown=reboot` ends the boot when the tests finish; without it
the kernel goes on to look for a root disk and panics.

## 3. Boot to userspace

`--disk FILE` attaches a disk image, read-write and in place (copy it
first to keep the original); the first is `/dev/vda` and becomes the root device unless `--append` sets `root=`.
Make one from a directory with `mkfs.ext4 -d DIR rootfs.img 512M`, and
give it an init (`--append init=/path`).  Have the init end with a reboot
(`reboot -f`, or `echo b > /proc/sysrq-trigger`): the VM stops when the
kernel resets it.

## 4. Run tests on this session's userspace (`--run`)

`--run CMD` boots the kernel on this VM's own root and `/usr`, read-only,
with a copy of `--dir DIR` (default `.`) at the same path, and runs CMD
there as root (`sh -c`), with bpffs, debugfs, tracefs and cgroup2
mounted.  `acrboot` exits with CMD's status.  No root disk to build: the
binaries run against the libraries they were built with.  Keep DIR small
(it is copied); writes in it are discarded.  For the BPF selftests
(`tools/testing/selftests/bpf/vmtest.sh` cannot run here - it needs QEMU
and sudo):

```
B=tools/testing/selftests/bpf; cat $B/config $B/config.vm $B/config.x86_64 > $O/.config
acrboot --kconfig > acrboot.config
scripts/kconfig/merge_config.sh -m -O $O $O/.config acrboot.config
make O=$O olddefconfig && make O=$O -j$(nproc)
make -C tools/testing/selftests/bpf KBUILD_OUTPUT=$O -j$(nproc)
acrboot --cpus {vcpus} --timeout 3600 --dir tools/testing/selftests/bpf \
  --run './test_progs -j > /tmp/out 2>&1; rc=$?; grep -E "^(Summary|#.*FAIL)" /tmp/out; exit $rc' $O/vmlinux
```

(`O` out of tree in `~/.cache`; `make O=` refuses a source tree that has
an in-tree build, so build from a clean checkout or `git clone --shared`.)
Run a subset with `./test_progs -t NAME`.  Tests that need hardware
performance counters fail here: the test VM has no PMU.

## 5. When it panics

`acrboot` exits 1 and stops the VM a few seconds after the report.  Decode
the trace against your build:

```
scripts/decode_stacktrace.sh vmlinux < console.log
```

## Notes

- A boot that never ends (waiting for a root device, a hang) is stopped at
  `--timeout` with status 124.
- No modules are loaded: build what the test needs in (`=y`).
- The test VM has virtio block devices and a serial console only: no
  network, no PCI devices, no other hardware.
- Each boot's console is also kept in `~/.local/state/acrboot/N.console`
  (the first 4M, the last 20 boots), which the user sees with the session
  (`agentcracker log` lists the boots).
"#,
        vcpus = c.vcpus,
        mem = c.mem_mib.saturating_sub(crate::acrboot::RESERVE_MIB).max(128)
    )
}

/// `text` with agentcracker's marked section replaced by `section` (or
/// added at the end): everything else in it is kept as it was.
pub fn with_section(text: &str, section: &str) -> String {
    let mut kept = String::new();
    let mut inside = false;
    let mut after = false;
    for line in text.split_inclusive('\n') {
        let l = line.trim_end();
        if l.starts_with("<!-- agentcracker: begin") {
            inside = true;
        } else if inside && l == END {
            inside = false;
            after = true;
        } else if !inside {
            // the blank line that separated the old section goes with it
            if !(after && l.is_empty()) {
                kept.push_str(line);
            }
            after = false;
        }
    }
    let kept = kept.trim_end();
    if kept.is_empty() { section.to_string() } else { format!("{kept}\n\n{section}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_is_replaced_not_repeated() {
        let sec = format!("{BEGIN}\nnew\n{END}\n");
        assert_eq!(with_section("", &sec), sec);
        let once = with_section("# mine\nkeep me\n", &sec);
        assert_eq!(once, format!("# mine\nkeep me\n\n{sec}"));
        let old = format!("# mine\n\n{BEGIN}\nold\n{END}\n\nafter\n");
        assert_eq!(with_section(&old, &sec), format!("# mine\n\nafter\n\n{sec}"));
        assert_eq!(with_section(&once, &sec), once);
    }
}

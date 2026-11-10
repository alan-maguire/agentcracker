# agentcracker: build firecracker (submodule), a guest kernel and the tool.
#
#   make                    # build everything (as your user)
#   make test               # run tests/ against the in-tree build
#   sudo make install       # install into /usr/local; copies only, never builds
#   make install PREFIX=~/.local   # rootless alternative

PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
LIBDIR      := $(PREFIX)/lib/agentcracker
MANDIR      := $(PREFIX)/share/man/man1

KVER        := 6.18.60
KSHA256     := 3c2f44ef6acc021a7ad444d9a2e6ec1ef488ff09368793d0004a6080f69d621e
KURL        := https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$(KVER).tar.xz

# The host's architecture: the guest runs the host's own /usr, so the guest
# kernel, Firecracker and the seccomp policy are all built for it.  aarch64
# is supported without acrboot (Firecracker gives guests no EL2), and is
# untested.
ARCH        := $(shell uname -m)
ifeq ($(ARCH),x86_64)
KARCH       := x86
KIMAGE      := vmlinux
else ifeq ($(ARCH),aarch64)
KARCH       := arm64
# Firecracker boots arm64 kernels from the Image, not the ELF vmlinux
KIMAGE      := arch/arm64/boot/Image
else
$(error unsupported architecture $(ARCH): agentcracker builds for x86_64 and aarch64)
endif
FC_CONFIG   := firecracker/resources/guest_configs/microvm-kernel-ci-$(ARCH)-6.18.config
# kernel/agentcracker.config, plus what only this architecture needs
KFRAGMENTS  := kernel/agentcracker.config $(wildcard kernel/agentcracker-$(ARCH).config)

B           := $(CURDIR)/build
KSRC        := $(B)/linux-$(KVER)
JOBS        ?= $(shell nproc)
HOST_TRIPLE := $(ARCH)-unknown-linux-gnu

FC_BIN      := firecracker/build/cargo_target/$(HOST_TRIPLE)/release/firecracker
SECCOMPILER := firecracker/build/cargo_target/$(HOST_TRIPLE)/release/seccompiler-bin
SECCOMP     := $(B)/seccomp.bpf
AC_BIN      := target/release/agentcracker
AC_INIT     := $(B)/acinit-target/$(HOST_TRIPLE)/release/agentcracker
VMLINUX     := $(B)/vmlinux-$(KVER)

.PHONY: all install uninstall check-deps firecracker kernel agentcracker seccomp test FORCE

all: check-deps firecracker kernel agentcracker seccomp

check-deps:
	@missing=""; \
	for t in cargo cc make flex bison bc perl curl tar xz mkfs.ext4 git; do \
	  command -v $$t >/dev/null 2>&1 || missing="$$missing $$t"; done; \
	test -e /usr/include/libelf.h || missing="$$missing libelf-devel"; \
	test -e /usr/include/openssl/ssl.h || missing="$$missing openssl-devel"; \
	{ test -e /usr/lib64/libc.a || test -e /usr/lib/$(ARCH)-linux-gnu/libc.a; } || missing="$$missing glibc-static"; \
	if [ -n "$$missing" ]; then echo "missing build dependencies:$$missing"; \
	  echo "  Fedora: sudo dnf install cargo gcc make flex bison bc perl curl xz e2fsprogs git elfutils-libelf-devel openssl-devel glibc-static"; \
	  echo "  Debian: sudo apt install cargo gcc make flex bison bc perl curl xz-utils e2fsprogs git libelf-dev libssl-dev libc6-dev"; \
	  exit 1; fi; \
	test -r /dev/kvm -a -w /dev/kvm || echo "warning: /dev/kvm is not accessible; add yourself to the kvm group"

# --- firecracker ------------------------------------------------------------
firecracker: $(FC_BIN)

# The submodule commit this checkout pins, kept in a file that is only
# rewritten when it changes, so pulling a new pin rebuilds firecracker (and,
# through it, the seccomp filter) while an unchanged pin rebuilds nothing.
FC_REV := $(B)/firecracker.rev
$(FC_REV): FORCE
	@mkdir -p $(B); rev=$$(git ls-tree HEAD firecracker | awk '{print $$3}'); \
	  [ "$$(cat $@ 2>/dev/null)" = "$$rev" ] || echo "$$rev" > $@
FORCE:

$(FC_BIN): $(FC_REV)
	git submodule update --init firecracker
	@# firecracker's build script links against libseccomp; distros often ship
	@# only the runtime .so.2, so provide an unversioned link for the linker.
	mkdir -p $(B)/libshim
	lib=$$(ls /usr/lib64/libseccomp.so.2 /usr/lib/$(ARCH)-linux-gnu/libseccomp.so.2 /usr/lib/libseccomp.so.2 2>/dev/null | head -1); \
	  if [ -n "$$lib" ]; then ln -sf $$lib $(B)/libshim/libseccomp.so; fi
	cd firecracker && LIBRARY_PATH=$(B)/libshim \
	  cargo build --release --target $(HOST_TRIPLE) -p firecracker
	@# cargo leaves an up-to-date binary untouched; mark it as current
	touch $@

# firecracker only ships a default seccomp policy for musl builds; compile
# that policy (adapted for glibc) and pass it at runtime.
seccomp: $(SECCOMP)

$(SECCOMP): $(FC_BIN) agentcracker
	cd firecracker && LIBRARY_PATH=$(B)/libshim \
	  cargo build --release --target $(HOST_TRIPLE) -p seccompiler --bin seccompiler-bin
	$(AC_BIN) __seccomp-json firecracker/resources/seccomp/$(ARCH)-unknown-linux-musl.json $(B)/seccomp.json
	$(SECCOMPILER) -t $(ARCH) -i $(B)/seccomp.json -o $@

# --- guest kernel -------------------------------------------------------------
kernel: $(VMLINUX)

$(B)/linux-$(KVER).tar.xz:
	mkdir -p $(B)
	curl -fL --retry 3 -o $@.tmp $(KURL)
	echo "$(KSHA256)  $@.tmp" | sha256sum -c -
	mv $@.tmp $@

$(KSRC)/Makefile: $(B)/linux-$(KVER).tar.xz
	tar -C $(B) -xf $<
	touch $@

# The base config lives in the firecracker submodule; depending on it means a
# submodule bump that changes the config rebuilds the kernel.
$(FC_CONFIG):
	git submodule update --init firecracker

# (installed as `vmlinux` whatever its format: the kernel Firecracker boots
# - the ELF vmlinux on x86_64, the Image on arm64)
$(VMLINUX): $(KSRC)/Makefile $(KFRAGMENTS) $(FC_CONFIG)
	cp $(FC_CONFIG) $(KSRC)/.config
	cd $(KSRC) && \
	  scripts/kconfig/merge_config.sh -m .config $(addprefix $(CURDIR)/,$(KFRAGMENTS)) >/dev/null && \
	  $(MAKE) ARCH=$(KARCH) olddefconfig >/dev/null && \
	  $(MAKE) ARCH=$(KARCH) -j$(JOBS) $(notdir $(KIMAGE))
	cp $(KSRC)/$(KIMAGE) $@

# --- agentcracker -------------------------------------------------------------
# One program, built twice: dynamically for the host, statically for use as
# PID 1 inside the guest (where there is no /usr until it mounts one).
agentcracker:
	cargo build --release
	RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--no-warnings -A linker_messages" \
	  cargo build --release --target $(HOST_TRIPLE) --target-dir $(B)/acinit-target

# --- tests --------------------------------------------------------------------
# Runs against the in-tree build by default; TESTS selects by name, e.g.
#   make test TESTS="apply resume"
#   make test AGENTCRACKER=/usr/local/bin/agentcracker    # test an install
test: all
	tests/run.sh $(TESTS)

# --- install ------------------------------------------------------------------
# install deliberately does not depend on the build targets: under sudo it
# would rebuild as root (with root's $$HOME and toolchain) and leave root-owned
# files in target/ and build/.
INSTALL_FILES := $(AC_BIN) $(AC_INIT) $(FC_BIN) $(VMLINUX) $(SECCOMP)

install:
	@for f in $(INSTALL_FILES); do test -e $$f || { \
	  echo "$$f is missing; run 'make' (without sudo) first"; exit 1; }; done
	install -d $(BINDIR) $(LIBDIR) $(MANDIR)
	install -m 0755 $(AC_BIN) $(BINDIR)/agentcracker
	ln -sf agentcracker $(BINDIR)/acr
	install -m 0755 $(AC_INIT) $(LIBDIR)/acinit
	install -m 0755 $(FC_BIN) $(LIBDIR)/firecracker
	install -m 0644 $(VMLINUX) $(LIBDIR)/vmlinux
	install -m 0644 $(SECCOMP) $(LIBDIR)/seccomp.bpf
	install -m 0644 man/agentcracker.1 $(MANDIR)/agentcracker.1
	ln -sf agentcracker.1 $(MANDIR)/acr.1
	@echo "installed agentcracker into $(PREFIX)"

uninstall:
	rm -f $(BINDIR)/agentcracker $(BINDIR)/acr $(MANDIR)/agentcracker.1 $(MANDIR)/acr.1
	rm -f $(LIBDIR)/acinit $(LIBDIR)/firecracker $(LIBDIR)/vmlinux $(LIBDIR)/seccomp.bpf
	-rmdir $(LIBDIR)

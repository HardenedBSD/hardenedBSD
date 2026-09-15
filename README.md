# About HardenedBSD

HardenedBSD is a fork of FreeBSD, founded in 2014, that implements
exploit mitigations and security hardening technologies. The primary
goal of HardenedBSD is to perform a clean-room re-implementation of
the grsecurity patchset for Linux to HardenedBSD.

Some of HardenedBSD's features can be toggled on a per-application and
per-jail basis using secadm or hbsdcontrol. Documentation for both
tools will be covered later.

For copyright information, please refer to [this](FreeBSD-COPYRIGHT) file.

# History

Work on HardenedBSD began in 2013 when Oliver Pinter and Shawn Webb
started working on an implementation of Address Space Layout
Randomization (ASLR), based on PaX's publicly-available documentation,
for FreeBSD. At that time, HardenedBSD was meant to be a staging area
for experimental development on the ASLR patch. Over time, as the
process of upstreaming ASLR to FreeBSD became more difficult,
HardenedBSD naturally became a fork.

HardenedBSD completed its ASLR implementation in 2015 with the
strongest form of ASLR in any of the BSDs. Since then, HardenedBSD has
moved on to implementing other exploit mitigations and hardening
technologies. OPNsense, an open source firewall based on FreeBSD,
incorporated HardenedBSD's ASLR implementation in 2016. OPNsense
completed their migration to HardenedBSD on 31 January 2019. In April 2021,
OPNsense switched back to FreeBSD.

HardenedBSD exists today as a fork of FreeBSD that closely follow's
FreeBSD's source code. HardenedBSD syncs with FreeBSD every six hours.
Some of the branches, but not all, are listed below:

1. main -> hardened/current/master
1. stable/15 -> hardened/15-stable/main

# Features

HardenedBSD has successfully implemented the following features:

1. PaX-inspired ASLR
1. PaX-inspired NOEXEC
1. PaX-inspired SEGVGUARD
1. Base compiled as Position Independent Executables (PIEs)
1. Base compiled with full RELRO (RELRO + BIND_NOW)
1. Hardening of certain sensitive sysctl nodes
1. Network stack hardening
1. Executable file integrity enforcement
1. Boot process hardening
1. procs/linprocfs hardening
1. Trusted Path Execution (TPE)
1. Randomized PIDs
1. SafeStack in base
1. SafeStack available in ports
1. Non-Cross-DSO CFI in base
1. Non-Cross-DSO CFI available in ports
1. Retpoline applied to base and ports
1. Variable auto-init applied to base and ports
1. Zeroing of CPU registers at function return
1. Link-Time Optimizations (LTO) applied to both apps and libs
1. Hardening of the runtime linker (RTLD)
1. Kernel malloc hardening
1. Shared memory hardening

# Verifying Build Artifacts

The HardenedBSD build artifacts are signed with an SSH key. SSH keys are used so
that artifacts can be validated using only tools included in the base operating
system.

First, download the SSH public key:

```
$ fetch https://installers.hardenedbsd.org/pub/keys/ssh.pub.txt
```

Then download the build artifact. For purposes of this documentation, the
compressed memstick installation image for HardenedBSD 15-STABLE will be used.

```
$ fetch https://installers.hardenedbsd.org/pub/15-stable/amd64/amd64/installer/LATEST/memstick.img.xz
$ fetch https://installers.hardenedbsd.org/pub/15-stable/amd64/amd64/installer/LATEST/memstick.img.xz.sig
```

Next, generate an `allowed_signers` file which contains the SSH public key:

```
$ echo "hbsd-os-build-01 $(cat ssh.pub.txt)" > allowed_signers
```

Now the signature file can be verified:

```
$ ssk-keygen -Y verify -f allowed_signers -I hbsd-os-build-01 -n file -s memstick.img.xz.sig < memstick.img.xz
```

# Generic Kernel Options

All of HardenedBSD's features that rely on kernel code require the
following kernel option:

```
options	PAX
```

Additionally, the following kernel option is not required, but exposes
extra sysctl nodes:

```
options PAX_SYSCTLS
```

Generic system hardening can be enabled with the following kernel
option:

```
options	PAX_HARDENING
```

# Generic System Hardening

HardenedBSD implements generic system hardening with the
`PAX_HARDENING` kernel option. Many of these hardening features deal
with restricting what non-root users are permitted to do. When the
kernel is compiled with the `PAX_HARDENING` kernel option, certain
`sysctl(8)` nodes are modified from their defaults.

`procfs(5)` and `linprocfs(5)` are modified to prevent arbitrary
writes to a process's registers. This behavior is controlled by the
`hardening.procfs_harden` `sysctl(8)` node.

`kld(4)` related system calls are restricted to non-jailed, root-only
users. Attempting to list kernel modules using `modfind(2)`,
`kldfind(2)`, and other KLD-related system calls will result in
permission denied if used by a non-root or jailed user.

The `hardening.pax.kmod_load_disable` sysctl tunable changes whether loading new
kernel modules is permitted. It supports the following values:

1. `0`: Permit loading of kernel modules
1. `1`: Prohibit loading of kernel modules
1. `2`: Prohibit loading of kernel modules, reboot required to re-enable kernel
   module loading.

When the `hardening.pax.kmod_load_disable` sysctl tunable is set to a value
greater than 0, loading kernel modules is prohibited. A reboot is required to
set `hardening.pax.kmod_load_disable` back to 0.

`kenv(1)` has been hardened to only allow access from privileged,
non-jailed processes.

The `hardening.kmalloc_zero` sysctl tunable, when set to a non-zero value,
causes all kernel heap allocations created and freed by `malloc(9)` to be
zeroed.  Additionally, the `PAX_HARDEN_KMALLOC` kernel option enables this by
default.

FreeBSD introduced the ability to dump non-dumpable mappings.
HardenedBSD does not permit such behavior.

FreeBSD provides a sysctl node, `security.bsd.map_at_zero`, that governs whether
userland processes can create memory allocations at the `NULL` (0) virtual
address. HardenedBSD has both removed the sysctl node and the ability for
userland processes to map at `NULL`. Further, it is not possible to create any
memory allocations lower than the first 64KB. This helps when a process may
contain a NULL pointer to a structure, and a member of that structure is
attempted to be accessed, causing a memory location dereference at (`NULL +
offsetof(struct->member)`).

jemalloc in HardenedBSD has been set to zero new allocations by
default. jemalloc also discards freed allocations by default (the `opt.retain`
option defaults to `false`.)

Process tracing (`ptrace`) is hardened:

* Process tracing facility itself is disabled by default
  (`security.bsd.allow_ptrace=0`).
* Unprivileged process debugging is prohibited by default
  (`security.bsd.unprivileged_proc_debug=0`).
* Remote syscall functionality (`ptrace(PT_SC_REMOTE)`) is prohibited by
  default.
* `ptrace(PT_SET_SC_RET)` is prohibited by default.
* Capability mode-enabled processes are prohibited targets by default
  (`hardening.prohibit_ptrace_capsicum=2`).

`uuidgen(1)` defaults to generating UUIDv4 identifiers.

TTY pushback vulnerabilities are mitigated by virtue of a new
`harden.harden_tty` sysctl node, defaulted to `1` (enabled).

Default packet TTL values are randomly generated at boot time to prevent
information disclosure and fingerprinting attacks. The random value will be
between 33 and 255, inclusive.

OpenSSH RSA host key generation is disabled by default.

Prohibiting new USB device connections can be toggled by setting the
`hardening.pax.prohibit_new_usb` sysctl tunable to one of two values:

1. `1`: Prohibited
1. `2`: Prohibited without possibility to disable without a reboot

Setting `hardening.pax.prohibit_new_usb` to its default (`0`) removes the
prohibition, allowing new USB devices to connect. If this sysctl node is set to
`2`, a reboot is required in order to re-allow new USB device connections.

HardenedBSD ensures that CVE-2021-4034 (argc == 0) is completely mitigated in
the case of buggy system image activators. Additionally, the environment pointer
(aka, `environ` or `envp`) must be non-NULL when calling `execve(2)`.

C++ code in the base operating system is built with clang's C++ hardening
(`-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_EXTENSIVE`). For userland C
and C++ code, HardenedBSD sets `_FORTIFY_SOURCE` to `2` by default.

[Alternative signal stacks](https://man.freebsd.org/cgi/man.cgi?query=sigaltstack&sektion=2&manpath=FreeBSD+14.2-RELEASE)
must be backed by `MAP_STACK` memory mappings. This helps protect against stack
pivoting with SROP-based payloads.

When the `kern.trap_enotcap` sysctl node is set to a non-zero value, Capsicum
violations that would cause the process to abort is integrated with our PaX
SEGVGUARD implementation. Repeated Capsicum violations within SEGVGUARD's
configured time window will prevent further execution of the application. By
default, the `kern.trap_enotcap` sysctl node is set to `0`.

It is not possible to call `fdlopen(3)` on a file descriptor that points to a
filesystem extended attribute (aka, named attribute). FreeBSD allows file
descriptors to be created that point to a filesystem extended attribute (the
`O_NAMEDATTR` `open(2)` flag). A shared object can be stored in an extended
attribute, which could be loaded via `fdlopen(3)`. On HardenedBSD, this is no
longer possible.

FreeBSD's `mac_do(4)` kernel module has been hardened to respect the per-process
flag that prevents gaining new privileges.

HardenedBSD and the ports tree both set the following `CFLAGS`/`CXXFLAGS`:

1. `-fno-delete-null-pointer-checks`
1. `-Werror=format-security`

Various `geom(4)` devfs nodes have been hardened to be owned by `root:wheel`
(rather than `root:operator`) and chmod `0600` (rather than `0640`). This closes
various avenues for leaking data, including decrypted `geli(8)` storage devices.

## Shared Memory (SHM) Hardening

Shared memory (SHM) hardening places restrictions on what can be done with the
shared memory subsystem (see `shm_open(2)`.) Use of
`shm_open(2)/__sys_shm_open2` system calls is prohibited when:

1. The `hardening.harden_shm` sysctl tunable is enabled;
1. The process has not opted out of the feature;
1. The process has entered into capability mode

A post-exploitation technique becoming more commonplace is to abuse
`memfd_create(2)` to create memory-backed file descriptors. These file
descriptors can be used with `fdlopen(3)` to load and execute a shared object
file using anonymous memory mappings, making forensics more difficult.

## Modified sysctl Nodes

These are the nodes that are modified from their original defaults
when `PAX_HARDENING` is enabled in the kernel:

|                  Node                 |                                   Description                                  |   Type  | Original Value |              Hardened Value             |
|:-------------------------------------:|:------------------------------------------------------------------------------:|:-------:|:--------------:|:---------------------------------------:|
| kern.coredump                         | Enable/Disable coredumps                                                       | Integer | 1              | 0                                       |
| kern.msgbuf_show_timestamp            | Show timestamp in msgbuf                                                       | Integer | 0              | 1                                       |
| kern.randompid                        | Random PID Modulus                                                             | Integer | 0, read+write  | Randomly set at boot and made read-only |
| machdep.efi_map                       | Dump EFI physical-to-virtual mappings, infoleak as feature                     | String  | Available to all | Available only to unjailed privileged process |
| net.inet.ip.connect_inaddr_wild       | Allow connecting to INADDR_ANY or INADDR_BROADCAST for connect(2)              | Integer | 1              | 0                                       |
| net.inet.ip.random_id                 | Assign random IP ID values                                                     | Integer | 0              | 1                                       |
| net.inet6.ip6.connect_in6addr_wild    | Allow connecting to the unspecified address for connect(2)                     | Integer | 1              | 0                                       |
| net.inet.tcp.blackhole                | Do not send RST on segments to closed ports                                    | Integer | 0              | 2                                       |
| net.inet.tcp.drop_synfin              | Drop TCP packets with SYN+FIN set                                              | Integer | 0              | 1                                       |
| net.inet.udp.blackhole                | Do not send port unreachables for refused connects                             | Integer | 0              | 2                                       |
| net.inet6.icmp6.nodeinfo              | Mask of enabled RFC4620 node information query types                           | Integer | 3              | 0                                       |
| net.inet6.ip6.use_deprecated          | Allow the use of addresses whose preferred lifetimes have expired              | Integer | 1              | 0                                       |
| net.inet6.ip6.use_tempaddr            | Use IPv6 temporary addresses with SLAAC                                        | Integer | 0              | 1                                       |
| net.inet6.ip6.prefer_tempaddr         | Prefer IPv6 temporary address generated last                                   | Integer | 0              | 1                                       |
| security.bsd.allow_tiocsti            | Allow TIOCSTI ioctl                                                            | Boolean | True           | False                                   |
| security.bsd.see_other_gids           | Unprivileged processes may see subjects/objects with different real gid        | Integer | 1              | 0                                       |
| security.bsd.see_other_uids           | Unprivileged processes may see subjects/objects with different real uid        | Integer | 1              | 0                                       |
| security.bsd.hardlink_check_gid       | Unprivileged processes cannot create hard links to files owned by other groups | Integer | 0              | 1                                       |
| security.bsd.hardlink_check_uid       | Unprivileged processes cannot create hard links to files owned by other users  | Integer | 0              | 1                                       |
| security.bsd.map_at_zero              | Permit processes to map an object at virtual address 0                         | Integer | 0              | Removed. Userland cannot map at NULL.   |
| security.bsd.see_jail_proc            | Unprivileged processes may see subjects/objects with different jail ids        | Integer | 1              | 0                                       |
| security.bsd.stack_guard_page         | Insert stack guard page ahead of the growable segments                         | Integer | 0              | 1                                       |
| security.bsd.unprivileged_proc_debug  | Unprivileged processes may use process debugging and tracing facilities        | Integer | 1              | 0                                       |
| security.bsd.unprivileged_read_msgbuf | Unprivileged processes may read the kernel message buffer                      | Integer | 1              | 0                                       |
| security.bsd.unprivileged_kenv_read   | Unprivileged processes can read the kernel environment                         | Integer | 1              | 0                                       |
| net.inet.ip.ttl                       | Maximum TTL on IP packets                                                      | Integer | 64             | Randomly set at boot                    |
| vfs.lookup_cap_dotdot                 | enables ".." components in path lookup in capability mode                      | Integer | 1              | 0                                       |
| vfs.lookup_cap_dotdot_nonlocal        | enables ".." components in path lookup in capability mode on non-local mount   | Integer | 1              | 0                                       |

## Untrusted/Insecure Kernel Modules

HardenedBSD marks certain kernel modules as untrustworthy. In order to load a
kernel module deemed untrustworthy, the `hardening.insecure_kmod` sysctl node
needs to be set to `1`. When the `PAX_HARDENING` kernel option is set, the
sysctl node is set to `0` by default (meaning: prohibit loading of untrusted
kernel modules). Otherwise, it's set to `1`.

If an untrusted kernel module is loaded via `loader.conf(5)`, the kernel module
is still loaded. Users are encouraged to use the `kld_list` option in
`rc.conf(5)` to load optional kernel modules rather than `loader.conf(5)`.
Kernel modules marked as untrusted can still be compiled directly into the
kernel.

The `hbsdcontrol` program can be used to disable insecure kernel module
enforcement on a per-module basis:

```
# hbsdcontrol pax disable insecure_kmod /path/to/kernel/module.ko
```

The following kernel modules are currently marked as untrusted by default.

1. /boot/kernel/accf_dns.ko
1. /boot/kernel/accf_http.ko
1. /boot/kernel/fusefs.ko
1. /boot/kernel/lindebugfs.ko
1. /boot/kernel/linux.ko
1. /boot/kernel/linux64.ko
1. /boot/kernel/linux_common.ko
1. /boot/kernel/smbfs.ko
1. /boot/kernel/tarfs.ko
1. /boot/kernel/virtio_p9fs.ko

## RTLD Hardening

When the `hardening.harden_rtld` sysctl tunable is set, the behavior
of the runtime linker is modified:

1. `LD_PRELOAD` is disabled.
1. Sensitive environment variables that control the behavior of the
   RTLD are scrubbed.
   * `LD_PRELOAD`
   * `LD_LIBMAP`
   * `LD_LIBRARY_PATH`
   * `LD_LIBRARY_PATH_FDS`
   * `LD_LIBMAP_DISABLE`
   * `LD_BIND_NOT`
   * `LD_DEBUG`
   * `LD_ELF_HINTS_PATH`
   * `LD_LOADFLTR`
   * `LD_LIBRARY_PATH_RPATH`
   * `LD_PRELOAD_FDS`
   * `LD_DYNAMIC_WEAK`
1. The RTLD cannot directly execute dynamically-linked executables.
1. Tracing loaded objects is prohibited. This directly impacts
   `ldd(1)`, which will provide no output.

RTLD hardening can cause issues when building applications/libraries. During the
build process, it is recommended to disable RTLD hardening in case of failure.
When using Poudriere, adding `hardening.harden_rtld=0` to the `JAIL_PARAMS`
configuration variable is sufficient.

Some applications, like LibreOffice, (ab)use `LD_LIBRARY_PATH`. Applications
needing to make use scrubbed environment variables require that the
`hardening.harden_rtld` sysctl node be set to `0`.

# Address Space Layout Randomization (ASLR)

ASLR randomizes the layout of the virtual address space of a process
through using randomized deltas. ASLR prevents attackers from knowing
where vulnerabilities lie in memory. Without ASLR, attackers can
easily craft and reuse exploits across all deployed systems. As is the
case with all exploit mitigation technologies, ASLR is meant to help
frustrate attackers, though ASLR alone is not sufficient to completely
stop attacks. ASLR simply provides a solid foundation in which to
implement further exploit mitigation technologies. A holistic approach
to security (aka, defense-in-depth) is the best way to secure a
system. Additionally, ASLR is intended and designed to help prevent
successful remote attacks, not local.

HardenedBSD's ASLR implementation is based off of PaX's design and
documentation. PaX's documentation can be found
[here](https://git.hardenedbsd.org/HardenedBSD/pax-docs-mirror/blob/master/aslr.txt).

When the `hardening.elf_pie_only` sysctl node is set to `1`, only applications
that are compiled as position-independent (PIE) are allowed to be executed.

On 13 July 2015, HardenedBSD's ASLR implementation was completed with
full stack and VDSO randomization. Since then, various improvements
have been made, like implementation shared library load order
randomization. HardenedBSD is the only BSD to support true stack
randomization. Meaning, the top of the stack is randomized in addition
to a random-sized gap between the top of the stack and the start of
the user stack.

ASLR is enabled by default in the `HARDENEDBSD` kernel configuration.
ASLR has been tested and is known to work on amd64, i386, arm, arm64,
and risc-v. The options for ASLR are:

```
options PAX
options PAX_ASLR
```

If the kernel has been compiled with `options PAX_SYSCTLS`, then the
sysctl node `hardening.pax.aslr.status` will be available. The
following values will determine the enforcement of ASLR:

1. 0 - Force disabled
1. 1 - Disabled by default. User must opt applications in.
1. 2 - Enabled by default. User must opt applications out (default.)
1. 3 - Force enabled

## Implementation

HardenedBSD's ASLR uses a set of four deltas on 32-bit systems and
five deltas on 64-bit systems. Additionally, on 64-bit systems, 32-bit
compatibility is supported by a set of different deltas. The deltas
are calculated at image activation (execve) time. The deltas are
provided as a hint to the virtual memory-y subsystem, which may further
modify the hint. Such may be the case if the application explicitly
requests superpage support or other alignment constraints.

The deltas are:

1. PIE execution base
1. mmap hint for non-fixed mappings
1. Stack top and gap
1. Virtual Dynamic Shared Object (VDSO)
1. On 64-bit systems, mmap hint for `MAP_32BIT` mappings

The calculation of each delta is controlled by how many bits of
entropy the user wants to introduce into the delta. The amount of
entropy can be overridden in the kernel config and via boot-time
(`loader.conf(5)`) tunables. By default, HardenedBSD uses the
following amount of entropy:

| Delta         | 32-bit  | 64-bit  | Compat  | Tunable                         | Compat Tunable                      | Kernel Option                   | Compat Kernel Option                |
|---------------|---------|---------|---------|---------------------------------|-------------------------------------|---------------------------------|-------------------------------------|
| mmap          | 14 bits | 30 bits | 14 bits | hardening.pax.aslr.mmap_len     | hardening.pax.aslr.compat.mmap_len  | PAX_ASLR_DELTA_MMAP_DEF_LEN     | PAX_ASLR_COMPAT_DELTA_MMAP_DEF_LEN  |
| Stack         | 14 bits | 42 bits | 14 bits | hardening.pax.aslr.stack_len    | hardening.pax.aslr.compat.stack_len | PAX_ASLR_DELTA_STACK_DEF_LEN    | PAX_ASLR_COMPAT_DELTA_STACK_DEF_LEN |
| PIE exec base | 14 bits | 30 bits | 14 bits | hardening.pax.aslr.exec_len     | hardening.pax.aslr.compat.exec_len  | PAX_ASLR_DELTA_EXEC_DEF_LEN     | PAX_ASLR_COMPAT_DELTA_EXEC_DEF_LEN  |
| VDSO          | 8 bits  | 28 bits | 8 bits  | hardening.pax.aslr.vdso_len     | hardening.pax.aslr.compat.vdso_len  | PAX_ASLR_DELTA_VDSO_DEF_LEN     | PAX_ASLR_COMPAT_DELTA_VDSO_DEF_LEN  |
| MAP_32BIT     | N/A     | 18 bits | N/A     | hardening.pax.aslr.map32bit_len | N/A                                 | PAX_ASLR_DELTA_MAP32BIT_DEF_LEN | N/A                                 |

When a process forks, the child process inherits its parent's ASLR
settings, including deltas. Only at image activation (execve) time
does a process receive new deltas.

To thwart heap spray attacks, HardenedBSD randomizes per-thread
stacks. Effectively, every call to `mmap(MAP_STACK)` gets randomized.
Per-thread stack randomization can be disabled on a per-process basis
by toggling ASLR for that process.

## Position-Independent Executables (PIEs)

In order to make full use of ASLR, applications must be compiled as
Position-Independent Executables (PIEs). If an application is not
compiled as a PIE, then ASLR will be applied to all but the execution
base. All of base is compiled as PIEs, with the exception of a few
applications that explicitly request to be statically compiled. Those
applications are:

1. All applications in /rescue
1. /sbin/devd
1. /sbin/init
1. /usr/sbin/nologin

Compiling all of base as PIEs can be turned off by setting
`WITHOUT_PIE` in `src.conf(5)`.

## Shared Library Load Order Randomization

Breaking ASLR remotely requires chaining multiple vulnerabilities,
including one or more information leakage vulnerabilities. Information
leakage vulnerabilities expose data an attacker can use to determine
the memory layout of the process. Code reuse attacks, like ROP and its
variants, exist to bypass exploit mitigations like PAGEEXEC/NOEXEC.
Over the years, a lot of tooling for automated ROP gadget generation
has been developed. The tools generally rely on gadgets found via
shared libraries and require that those shared libraries be loaded in
the same deterministic order. By randomizing the order in which shared
libraries get load, ROP gadgets have a higher chance of failing.
Shared library load order randomization is disabled by default, but
can be opted in on a per-application basis using secadm or
hbsdcontrol.

# PaX SEGVGUARD

ASLR has known weaknesses. If an information leak is present,
attackers can use the leak to determine the memory layout and, given
time, successfully exploit the application.

Some applications, like daemons, can optionally be set to
automatically restart after a crash. Automatically restarting
applications can pose a security risk by allowing attackers to repeat
failed attacks, modifying the attack until successful.

PaX SEGVGUARD provides a mitigation for such cases. SEGVGUARD keeps
track of how many times a given application has crashed within a
configurable window and will suspend further execution of the
application for a configurable time once the crash limit has been
reached.

The kernel option for PaX SEGVGUARD is:

```
options PAX_SEGVGUARD
```

SEGVGUARD can be configured by modifying the `hardening.pax.segvguard`
sysctl nodes.

# PAGEEXEC and MPROTECT (aka, NOEXEC)

[PAGEEXEC](https://git.hardenedbsd.org/HardenedBSD/pax-docs-mirror/blob/master/pageexec.txt)
and
[MPROTECT](https://git.hardenedbsd.org/HardenedBSD/pax-docs-mirror/blob/master/mprotect.txt)
comprise what is more commonly called W^X (W xor X). The design and
implementation in HardenedBSD is inspired by PaX's. PAGEEXEC prevents
applications from creating memory mappings that are both Writable (W)
and Executable (X) at `mmap(2)` time. MPROTECT prevents applications
from toggling memory mappings between writable and executable with
`mprotect(2)`. Combining both PAGEEXEC and MPROTECT prevents attackers
from executing injected code, thus forcing attackers to utilize code
reuse techniques like ROP and its variants. Code reuse techniques are
very difficult to make reliable, especially when multiple exploit
mitigation technologies are present and active.

The PAGEEXEC and MPROTECT features can be enabled with the
`PAX_NOEXEC` kernel option and is enabled by default in the
`HARDENEDBSD` kernel. If the `PAX_SYSCTLS` option is also enabled, two
new sysctl nodes will be created, which follow the same semantics as
the `hardening.pax.aslr.status` sysctl:

1. `hardening.pax.pageexec.status` - Default 2
1. `hardening.pax.mprotect.status` - Default 2

## PAGEEXEC

If an application requests a memory mapping via `mmap(2)`, and the
application requests `PROT_WRITE` and `PROT_EXEC`, then `PROT_EXEC` is
dropped. The application will be able to write to the mapping, but
will not be able to execute what was written. When an application
requests W|X mappings, the application is more likely to write to the
mapping, but not execute it. Such is the case with some Python
scripts: the developer is simply asking for more permissions than is
truly needed.

The kernel keeps a concept of pax protection. HardenedBSD drops
`PROT_EXEC` from the max protection when `PROT_WRITE` is requested.
When `PROT_EXEC` is requested, `PROT_WRITE` is dropped from the max
protection. When both are requested, `PROT_WRITE` is given priority
and `PROT_EXEC` is dropped from both the request and the max
protection.

## MPROTECT

If an application requests that a writable mapping be changed to
executable via `mprotect(2)`, the request will fail and set `errno` to
`EPERM`. The same applies to an executable mapping being changed to
writable via `mprotect(2)`. Applications and shared objects that
utilize text relocations (TEXTRELs) have issues with the MPROTECT
feature. TEXTRELs require that executable code be relocated to
different locations in memory. During the relocation process, the
newly allocated memory needs to be both writable and executable. Once
the relocation process is finished, the mapping can be marked as
`PROT_READ|PROT_EXEC`.

Some applications with a JIT, most notably Firefox, opt to create
writable memory mappings that are non-executable, but upgrade the
mapping to executable when appropriate. This gets rid of the problem
of having active memory mappings that are both writable and
executable. This makes applications like Firefox work with PAGEEXEC,
but still have an issue with MPROTECT.

By combining both PAGEEXEC and MPROTECT, HardenedBSD enables a strict
form of W^X. Some applications may have issues with PAGEEXEC,
MPROTECT, or both. When issues arise, secadm or hbsdcontrol can be
used to disable PAGEEXEC, MPROTECT, or both for just that one
application.

# Trusted Path Execution (TPE)

Trusted Path Execution enforces that to-be-executed programs, and other
executable code living on the filesystem, live in a properly secured/hardened
directory. TPE is disabled by default and can be enabled by setting the
`hardening.pax.tpe.status` sysctl node to `2`. Both the file and the directory
in which it is contained must NOT be writable if owned by root.

TPE is enforced at `execve(2)` and `mmap(2)` time. The `mmap(2)` integration
only applies when the execute bit is requested.

When the `hardening.pax.tpe.user_owned` sysctl node is set to `1`, the owner of
the directory MUST be the same as the account attempting execution. When the
`hardening.pax.tpe.root_owned` sysctl node is set to `1`, the owner of the
directory MUST be `root` (specifically, UID `0`).

TPE is usually configured to apply only to a specific GID, which is set via the
`hardening.pax.tpe.gid` sysctl node. If the `hardening.pax.tpe.all` sysctl node
is set to `1`, the TPE logic applies to all non-privileged processes.

The TPE GID logic can be negated by setting the `hardening.pax.tpe.negate`
sysctl node to `1`. This sysctl node does NOT apply when the
`hardening.pax.tpe.all` sysctl node is set to `1`.

# SafeStack

SafeStack is an exploit mitigation that creates two stacks: one for
data that needs to be kept safe, such as return addresses and function
pointers; and an unsafe stack for everything else. SafeStack promises
a low performance penalty (typically around 0.1%).

SafeStack requires both ASLR and W^X in order to be effective. With
HardenedBSD satisfying both of those prerequisites, SafeStack was
deemed to be an excellent candidate for default inclusion in
HardenedBSD. Starting with HardenedBSD 11-STABLE, it is enabled by
default for amd64. SafeStack can be disabled by setting
`WITHOUT_SAFESTACK` in `src.conf(5)`.

As of 08 Oct 2018, SafeStack only supports being applied to
applications and not shared libraries. Multiple patches have been
submitted to clang by third parties to add the missing shared library
support. As such, SafeStack is still undergoing active development.

SafeStack has been made available in the HardenedBSD ports tree as
well. Unlike PIE and RELRO and BIND_NOW, it is not enabled globally
for the ports tree. Some ports known to work well with SafeStack have
it enabled by default. Users are able to toggle SafeStack by using the
`config` make target. Additionally, the SafeStack option is only
applicable to the amd64 architecture. Attempting to enable SafeStack
for a non-amd64 port build will result in a NO-OP. SafeStack simply
will not be applied.

# Variable Auto-Initialization

In HardenedBSD 13, we enabled a feature from llvm called [automatic
variable initialization](https://reviews.llvm.org/D54604). Variables
that would normally be uninitialized are zero-initialized. This helps
prevent information leaks and abuse of code with undefined behavior.

From llvm's documentation:

This feature aims to make undefined behavior hurt less, which
security-minded people will be very happy about. Notably, this means
that there's no inadvertent information leak when:

* The compiler re-uses stack slots, and a value is used uninitialized.
* The compiler re-uses a register, and a value is used uninitialized.
* Stack structs / arrays / unions with padding are copied.

For more complete documentation, take a look at the link in the first
paragraph in this section.

# Register Zeroing

In HardenedBSD 15, we enabled a feature from llvm that [zeros used
registers](https://reviews.llvm.org/D110869). The entirety of the base userland
is built with `-fzero-call-used-regs=used`. Register zeroing is a feature
exposed to the ports tree via the ZEROREG hardening option. Individual ports
entries can opt into register zeroing by adding the following to the port's
`Makefile`:

```
USE_HARDENING+= zeroreg
```

The idea here is to help mitigate information leaks and lessen some ROP gadgets.

# Control-Flow Integrity (CFI)

Control-Flow Integrity (CFI) is an exploit mitigation technique that
prevents unwanted transfer of control from branch instructions to
arbitrary valid memory locations. The CFI implementation from
clang/llvm comes in two forms: Cross-DSO CFI and non-Cross-DSO CFI.
HardenedBSD 12 enables non-Cross-DSO CFI by default on amd64 and arm64
for base.

CFI requires a linker that supports Link Time Optimization (LTO).
Starting with 12, HardenedBSD ships with ld.lld as the default
linker. ld.lld supports LTO.

Non-Cross-DSO CFI adds checks both before and after every branch
instruction in the application itself. If an application loads
libraries via `dlopen(3)` and resolves functions via `dlsym(3)` and
calls those functions, the application will abort. Some applications,
like `bhyveload(8)` do this and thus have the cfi-icall scheme
disabled, allowing it to call functions resolved via `dlsym(3)`. Thus,
if a user finds that an application crashes in HardenedBSD 12, the
user should file a bug report. The cfi-icall scheme can be disabled
when building world by adding a CFI override in that application's
Makefile.

Note that Non-Cross-DSO CFI does not require ASLR and strict W^X.
Given that Cross-DSO CFI keeps metadata and state information,
Cross-DSO CFI does require ASLR and W^X in order to be effective.

Non-Cross-DSO CFI support has been added to HardenedBSD's ports
framework. However, it is not enabled by default. Support for CFI in
ports is still very premature and is only available for those brave
users who want to experiment.

As of 20 May 2017, Cross-DSO CFI is being actively researched.
However, support for Cross-DSO CFI is not available in HardenedBSD,
yet. Cross-DSO CFI would allow functions resolved through
`dlopen(3)`/`dlsym(3)` to work since CFI would be able to be applied
between Dynamic Shared Object (DSO) boundaries. Significant progress
has been made in the first half of 2018 with regards to Cross-DSO CFI.

The Cross-DSO CFI work was paused in 2019 and 2020. Work has resumed
in 2021, starting with applying LTO to libraries (in addition to the
LTO already applied to apps). When built with Cross-DSO CFI, some
applications, like the ZFS tools, crash. Work is ongoing to determine
the cause of the crashes and fix them.

# hbsdcontrol

`hbsdcontrol(8)` is a tool, included in base, that allows users to
toggle exploit mitigations on a per-application basis. Users will
typically use hbsdcontrol to disable PAGEEXEC and/or MPROTECT
restrictions. hbsdcontrol is similar in scope as secadm and is
preferred over secadm for filesystems that support extended
attributes.

Unlike secadm, hbsdcontrol does not use a configuration file. Instead,
it stores metadata in the filesystem extended attributes. Both UFS
and ZFS support extended attributes. Network-based filesystems, like
NFS or SMB/CIFS do not. secadm is the preferred method for exploit
mitigation toggling only in cases where extended attributes are not
supported.

Example usage of hbsdcontrol to disable MPROTECT for Firefox:

```
# hbsdcontrol pax disable mprotect /usr/local/lib/firefox/firefox
# hbsdcontrol pax disable mprotect /usr/local/lib/firefox/plugin-container
```

As of 09 Jul 2020, various ports have exploit mitigations pre-toggled
such that users do not have to worry about setting the toggles
themselves.

| Port           	| Path					| Exploit Mitigation	|
|-----------------------|---------------------------------------|-----------------------|
| editors/libreoffice	| lib/libreoffice/program/soffice.bin	| PaX MPROTECT		|
| editors/libreoffice	| lib/libreoffice/program/soffice.bin	| PaX PAGEEXEC		|
| lang/python37		| bin/python3.7				| PaX MPROTECT		|
| lang/python37		| bin/python3.7				| PaX PAGEEXEC		|
| lang/python38		| bin/python3.8				| PaX MPROTECT		|
| lang/python38		| bin/python3.8				| PaX PAGEEXEC		|
| security/keepassxc	| bin/keepassxc				| PaX MPROTECT		|
| security/keepassxc	| bin/keepassxc				| PaX MPROTECT		|
| security/keepassxc	| bin/keepassxc				| PaX PAGEEXEC		|
| sysutils/polkit	| lib/polkit-1/polkitd			| PaX MPROTECT		|
| sysutils/polkit	| lib/polkit-1/polkitd			| PaX PAGEEXEC		|
| www/chromium		| share/chromium/chrome			| PaX MPROTECT		|
| www/chromium		| share/chromium/chrome			| PaX PAGEEXEC		|
| www/firefox		| lib/firefox/firefox			| Pax MPROTECT		|
| www/firefox		| lib/firefox/plugin-container		| PaX MPROTECT		|

# Security Administration (secadm)

secadm is a tool, distributed via ports, that allows users to toggle
exploit mitigations on a per-application and per-jail basis. Users will
typically use secadm to disable PAGEEXEC and/or MPROTECT restrictions.

secadm also includes a feature known as Integriforce. Integriforce is
an implementation of verified execution. It enforces hash-based
signatures for binaries and their dependent shared objects.
Integriforce can be set in whitelisting mode. When there is at least
one Integriforce rule enabled, all desired applications and their
dependent shared objects must also have rules. If an application and
its shared objects are not included in the ruleset, execution of that
application will be disallowed. This also affects shared objects loaded
via [dlopen(3)](https://www.freebsd.org/cgi/man.cgi?query=dlopen&sektion=3&manpath=freebsd-release-ports).

When a file is added to secadm's ruleset, secadm will disallow
modifications to that file. This includes deleting, appending,
truncating, or otherwise modifying the file. This is because secadm
tracks files under its control by using the inode. Modifying the file
might change the inode, or freeing it in case of deletion, thereby
implicitly modifying the secadm ruleset. To protect the integrity of
the loaded ruleset, secadm also protects the files it controls.

Thus, when updating installed ports or packages, care must be taken.
Flush the ruleset prior to installing updates. The ruleset can be
reloaded after updating.

## Downloading and Installing secadm

secadm is not currently part of base, though that is planned in the
near future. secadm can be installed either through the package repo:

```
# pkg install secadm-kmod secadm
```

or by using HardenedBSD's ports tree:

```
# cd /usr/ports/hardenedbsd/secadm
# make install clean
# cd /usr/ports/hardenedbsd/secadm-kmod
# make install clean
```

## Configuring secadm

By default, secadm looks for a config file at
`/usr/local/etc/secadm.rules`. For purposes of this documentation,
that file will be simply referenced as `secadm.rules`. secadm does not
install or manage the `secadm.rules` file. It simply reads the file,
if it exists, passing the parsed data to the kernel module. secadm can
be configured either via the command-line or `secadm.rules`. Both
secadm and `secadm.rules` contain manual pages. Once installed, users
can look at the secadm man page in section 8 and secadm.rules in
section 5.

`secadm.rules` should be in a format that libucl can parse as secadm
uses libucl to parse `secadm.rules`.

An example `secadm.rules` would look like this:

```
secadm {
	pax {
		path: "/usr/local/lib/firefox/firefox",
		mprotect: false,
	},
	pax {
		path: "/usr/local/lib/firefox/plugin-container",
		mprotect: false,
	},
}
```

Once secadm is configured, it can be started via the
[rc(8)](https://www.freebsd.org/cgi/man.cgi?query=rc&sektion=8&manpath=freebsd-release-ports)
system:

```
# sysrc secadm_enable=YES
# service secadm start
```

## All secadm configuration options

These are the available pax options:

| Option           	| Requirement	| Type		| Description									|
|-----------------------|---------------|---------------|-------------------------------------------------------------------------------|
| path			| Required	| String	| Fully-qualified path of the executable					|
| aslr			| Optional	| Boolean	| Toggle ASLR									|
| disallow_map32bit	| Optional	| Boolean	| Toggle the ability to use the MAP_32BIT [mmap(2)](https://www.freebsd.org/cgi/man.cgi?query=mmap&sektion=2&manpath=freebsd-release-ports) flag on 64-bit systems	|
| mprotect		| Optional	| Boolean	| Toggle mprotect restrictions							|
| pageexec		| Optional	| Boolean	| Toggle pageexec restrictions							|
| segvguard		| Optional	| Boolean	| Toggle SEGVGUARD								|
| shlibrandom		| Optional	| Boolean	| Toggle shared library load order randomization				|

Example pax configuration:

```
secadm {
	pax {
		path: "/usr/local/lib/firefox/firefox",
		mprotect: false,
	},
	pax {
		path: "/usr/local/lib/firefox/plugin-container",
		mprotect: false,
	},
}
```

These are the available integriforce options:

| Option           	| Requirement	| Type		| Description									|
|-----------------------|---------------|---------------|-------------------------------------------------------------------------------|
| path			| Required	| String	| Fully-qualified path of the executable or shared library			|
| hash			| Required	| String	| [sha1(1)](https://www.freebsd.org/cgi/man.cgi?query=sha1&sektion=1&manpath=freebsd-release-ports) or [sha256(1)](https://www.freebsd.org/cgi/man.cgi?query=sha256&sektion=1&manpath=freebsd-release-ports) hash of the file						|
| type			| Required	| String	| Type of hash. Either "sha1" or "sha256".					|
| mode			| Required	| String	| Either "soft" or "hard". In soft mode, if the hash doesn't match, a warning is printed in syslog and execution is allowed. In hard mode, if the hash doesn't match, an error is printed in syslog and execution is denied. |

Example integriforce configuration:

```
secadm {
	integriforce {
		path: "/bin/ls",
		hash: "7dee472b6138d05b3abcd5ea708ce33c8e85b3aac13df350e5d2b52382c20e77",
		type: "sha256",
		mode: "hard",
	}
}
```

# Contributing to HardenedBSD

In 2026, HardenedBSD completed its migration away from a self-hosted GitLab
Enterprise instance to Radicle. HardenedBSD maintains a Radicle seed node that
can serve as the source-of-truth for all HardenedBSD-maintained repositories.

The Radicle Node ID (NID) for the seed node:
`did:key:z6MknwwMpmZET1PcvQjPYhA6hGY7wkYzxb9YtSRh5j2qSQdG`. This node can be
browsed at the [Radicle Explorer](https://radicle.network/nodes/rad.hardenedbsd.org).

For users who are unfamiliar with Radicle, they have provided a
[User Guide](https://radicle.dev/guides/user).

As of 20 May 2026, Radicle can have difficulties in fetching the initial set of
git pack files for our two largest repos (ports and src). To ease adoption of
Radicle for src and ports, the HardenedBSD project periodically publishes
archives of the repos meant to be unarchived into Radicle's storage location
(default: `${HOME}/.radicle/storage`). The archives can be found
[here](https://hardenedbsd.org/~shawn/radicle/archives/).

These steps will bootstrap our larger repos for use with Radicle. Please note
that the use of `#` constitutes a comment, not a command to run as root.

```
$ cd ${HOME}
# Create your radicle identity and node config if you haven't already with this
# next single command:
$ rad auth

# If you have already started the Radicle node, we're going to be manipulating
# Radicle's local storage directory (a directory only Radicle should touch).
# So let's stop the Radicle node if it is running to try to prevent problems.
$ rad node stop

# Make sure that Radicle connects to HardenedBSD's primary Radicle seed node.
# Only do this once.
$ rad config set node.connect \
    z6MknwwMpmZET1PcvQjPYhA6hGY7wkYzxb9YtSRh5j2qSQdG@rad.hardenedbsd.org:8776

# Bootstrap src
$ fetch -o src.tar.xz \
    https://hardenedbsd.org/~shawn/radicle/archives/src.z2HLHXgL1xevBNQsf8BmQW7MpJmtm.2026-05-19.tar.xz
$ tar -xf src.tar.xz -C ${HOME}/.radicle/storage

# Start the Radicle node temporarily so we can bootstrap issues and patches.
$ rad node start

# Clone the src repo to its final destination (assuming /usr/src). Then instruct
# Radicle to bootstrap the list of issues and patches.
$ rad clone rad:z2HLHXgL1xevBNQsf8BmQW7MpJmtm /usr/src
$ cd /usr/src
$ rad issue cache
$ rad patch cache

# Stop the Radicle node again if we want to bootstrap ports. Otherwise, you're
# done! Skip down to the comment starting with "Congratulations!" for
# conclusions.
$ rad node stop

# Bootstrap ports
$ fetch -o ports.tar.xz \
   https://hardenedbsd.org/~shawn/radicle/archives/ports.z2XrdvALg77ycnuZRXgScb27yb3wM.2026-05-19.tar.xz
$ tar -xf ports.tar.xz - C ${HOME}/.radicle/storage

# Start the Radicle node temporarily so we can bootstrap issues and patches.
$ rad node start

# Clone the ports repo to its final destination (assuming /usr/ports). Then
# instruct Radicle to bootstrap the list of issues and patches.
$ rad clone rad:z2XrdvALg77ycnuZRXgScb27yb3wM /usr/ports
$ cd /usr/ports
$ rad issue cache
$ rad patch cache

# Congratulations! You should be able to use your src and ports trees. Note that
# Radicle uses `rad/` as the default remote name, rather than `origin`. So users
# accustomed to origin/hardened/current/master, for example, would now need to
# reference rad/hardened/current/master.
```

Users do not need to run a full Radicle node to fetch the repos. The repos can
be cloned using `git clone` like normal, but using this template command.
Replace `<RID>` with the Repository ID.

`$ git clone https://rad.hardenedbsd.org/<RID>.git`

For example, if I wanted to clone the src tree without having to deploy Radicle,
I would run the following command:

```
$ git clone \
    https://rad.hardenedbsd.org/rad:z2HLHXgL1xevBNQsf8BmQW7MpJmtm.git /usr/src
```

HardenedBSD's official projects on Radicle include:

| RID                               | Repository                            |
|-----------------------------------|---------------------------------------|
| rad:z2HLHXgL1xevBNQsf8BmQW7MpJmtm | Source Tree (src)                     |
| rad:z2XrdvALg77ycnuZRXgScb27yb3wM | Ports Tree (ports)                    |
| rad:z4Aucnb2nozutuek6o8PC9YfaBeTm | HardenedBSD Documentation             |
| rad:z3QDZAW2FAfuLvihrhiyDC9fAD8G9 | HardenedBSD Package Manager (pkg)     |
| rad:zAcKb74s1brWWpmrsyed2hWiGbuG  | HardenedBSD Build Scripts             |
| rad:z5p6VcE97HCTVkiNtjBhMtW5mEnW  | HardenedBSD Security Administration   |
| rad:zZzwtG13zar5mKyyyeAGTByghVqD  | hbsdmon                               |
| rad:z2hVyd5Ea5Sm8xfY5ovym67wTwrKo | vm-bhyve-hbsd                         |
| rad:z4BsvtNJUeUWWUQyGyL6deGh8JkkG | Repo AutoSync (Rync)                  |

When submitting bug reports, please include the following information:

* HardenedBSD version
* Architecture
* If the report concerns a kernel panic, the backtrace of the panic
* Steps to reproduce the bug

## HardenedBSD Development Process

HardenedBSD development branches:

| Branch           			        | Repository		| Binary Updates    | Purpose                               |
|-----------------------------------|-------------------|-------------------|---------------------------------------|
| hardened/current/master		    | HardenedBSD		| amd64             | Main development branch (16-CURRENT)  |
| hardened/current/cross-dso-cfi    | HardenedBSD		| amd64             | Cross-DSO CFI development branch      |
| hardened/current/pledge           | HardenedBSD		| amd64             | Pledge port development branch        |
| hardened/15-stable/main           | HardenedBSD		| amd64             | 15-STABLE development                 |
| hardened/15-stable/pledge         | HardenedBSD		| amd64             | 15-STABLE Pledge port development     |

For the most part, the normal FreeBSD development process can be followed.
Perform a git clone if the intended branch into `/usr/src` and perform the
following steps:

1. `cd /usr/src`
1. `make -j$(sysctl -n hw.ncpu) buildworld buildkernel`
1. `make installkernel` and reboot if necessary
1. `make installworld`
1. Usually a reboot is a good idea at the end

Making use of ZFS and ZFS boot environments in particular is highly recommended,
especially for those performing custom builds.

New features and bug fixes are expected to land in the `hardened/current/master`
branch first. After some soak time, commits might become candidates to be
brought into supported stable branches. Commits should be explicitly tagged as
being slated for cherry-picked into the stable branches with an "MFC-to" line.

At times, there may be bugs specific to a given stable branch. Direct commits to
the stable branch should be explicitly mentioned in the commit log message.
Commits to stable that would break ABI, API, KBI, or KPI must receive explicit
approval by the HardenedBSD Core Team (`core@hardenedbsd.org`) prior to
acceptance.

Situations that would require the use of force pushing (`git push --force` or
`git push --force-with-lease`) require explicit approval by the HardenedBSD Core
Team (`core@hardenedbsd.org`).

HardenedBSD does not willfully accept AI/LLM/etc generated patches, including
for documentation, for any project we maintain. If the project has an upstream,
like our src and ports repos have FreeBSD as their upstream, we cannot control
what that upstream accepts (or doesn't accept.)

# Ports and Packages Collection

The HardenedBSD Ports and Packages offers a simple way to install applications.

The Ports Collection lives outside the context of the base OS.
We automatically sync every six hours with FreeBSD.
For 15-stable and 16-current there is only one git branch dedicated to ports,
namely: "[hardenedbsd/main](https://radicle.network/nodes/rad.hardenedbsd.org/rad:z2XrdvALg77ycnuZRXgScb27yb3wM)

We don't support [FreeBSD's quarterly ports branches](https://wiki.freebsd.org/Ports/QuarterlyBranch)
because we don't have a ports team specifically to track backporting security
fixes for all the ports in the tree.

The package repos are built from the ports repo. Ports are generally more
up-to-date than packages due to the build time required to produce the packages.
You can follow the building of the packages from the following links:
* [15-STABLE/amd64 package builder](https://hbsd-pkg-15-stable-01.hardenedbsd.org/)
* [16-CURRENT/amd64 package builder](https://hbsd-pkg-current-01.hardenedbsd.org/)

Another detail, HardenedBSD has some ports that FreeBSD does not have, here is the list:
- games/scratch
- hardenedbsd/hardenedbsd-meta
- hardenedbsd/hbsdmon
- hardenedbsd/kernel-nodebug
- hardenedbsd/liblattutil
- hardenedbsd/portzap
- hardenedbsd/rubygem-bsdcontrol-rb
- hardenedbsd/secadm
- hardenedbsd/secadm-kmod
- hardenedbsd/sourcezap
- hardenedbsd/testmprotect
- hardenedbsd/testpie
- net/libpushover
- net-p2p/heartwood
- net-p2p/heartwood-cli
- net-p2p/heartwood-httpd
- net-p2p/heartwood-node
- net-p2p/heartwood-remote-helper
- net-p2p/heartwood-tools
- security/gibson
- security/paxtest
- sysutils/cbsd-plugin-wsqueue
- sysutils/clonos-ws
- sysutils/pc-sysinstall
- www/clonos
- x11/station-tweak

# Updating HardenedBSD

HardenedBSD does not use
[freebsd-update(8)](https://www.freebsd.org/cgi/man.cgi?query=freebsd-update&sektion=8&manpath=freebsd-release-ports).
Instead, HardenedBSD uses an utility known as hbsd-update. hbsd-update
does not use deltas for publishing updates, but rather distributes the
base operating system as a whole. Not utilizing deltas incurs a
bandwidth overhead, but is easier to maintain and mirror. hbsd-update
relies on DNSSEC-signed TXT records for distributing version information.

hbsd-update is configured via a config file placed at
`/etc/hbsd-update.conf`. hbsd-update works on a branch level, meaning it
tracks branches within HardenedBSD's source tree. Thus, updating from
one major version to another requires changing the dnsrec and branch
variables in `hbsd-update.conf`. For example, the `hbsd-update.conf`
for the hardened/current/master branch in the HardenedBSD repo:

```
dnsrec="$(uname -m).master.current.hardened.hardenedbsd.updates.hardenedbsd.org"
capath="/usr/share/keys/hbsd-update/trusted"
branch="hardened/current/master"
baseurl="http://updates.hardenedbsd.org/pub/HardenedBSD/updates/${branch}/$(uname -m)"
```

And as another example, the `hbsd-update.conf` for the
hardened/15-stable/main branch in the HardenedBSD repo:

```
dnsrec="$(uname -m).main.15-stable.hardened.hardenedbsd.updates.hardenedbsd.org"
capath="/usr/share/keys/hbsd-update/trusted"
branch="hardened/15-stable/main"
baseurl="http://updates.hardenedbsd.org/pub/HardenedBSD/updates/${branch}/$(uname -m)"
```

Thus, generating a diff between the two configuration files would result in:

```
--- hbsd-update_current.conf
+++ hbsd-update_4-stable.conf
@@ -1,4 +1,4 @@
-dnsrec="$(uname -m).master.current.hardened.hardenedbsd.updates.hardenedbsd.org"
+dnsrec="$(uname -m).main.15-stable.hardened.hardenedbsd.updates.hardenedbsd.org"
 capath="/usr/share/keys/hbsd-update/trusted"
-branch="hardened/current/master"
+branch="hardened/15-stable/main"
 baseurl="http://updates.hardenedbsd.org/pub/HardenedBSD/updates/${branch}/$(uname -m)"
```

# Accessing HardenedBSD Resources Through Tor

Tor can be deployed in various ways. These instructions assume that Tor is
configured as a SOCKS 5 proxy on the same machine. If Tor is configured as a
SOCKS 5 proxy on a separate machine, simply rename all "localhost" references to
the hostname/IP of the Tor proxy machine.

Note that configuring Tor itself is out-of-scope for this documentation. Users
are encouraged to configure Tor according to their risk profiles.

## Supporting the Package Repos Over Tor

1. Create the `/usr/local/etc/pkg/repos` directory if it doesn't already exist.
1. Create a file, `/usr/local/etc/pkg/repos/HardenedBSD.conf` and set it to the
   following contents:
```
HardenedBSD: {
    enabled: no
}
```
1. Create a file, `/usr/local/etc/pkg/repos/HardenedBSD.tor.conf` and set it to
   the following contents:
```
pkg_env: {
    ALL_PROXY: socks5h://localhost:9050
}

HardenedBSD_Tor: {
    enabled: yes
}
```

When using Tor as a transparent proxy, there is no need for the `pkg_env` lines.
Simply enable the `HardenedBSD_Tor` repo.

## Using hbsd-update Over Tor

1. Set the `SOCKS_PROXY` environment variable to `localhost:9050`
1. Pass in the `-c /etc/hbsd-update.tor.conf` option to the `hbsd-update`
   command.

An example command could be:

```
# env SOCKS_PROXY=localhost:9050 hbsd-update -c /etc/hbsd-update.tor.conf
```

When using Tor as a transparent proxy, there is no need for the `SOCKS_PROXY`
environment variable. Simply use the `/etc/hbsd-update.tor.conf` config file.

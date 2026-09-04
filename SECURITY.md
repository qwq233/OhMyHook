# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.0 | Yes |
| < 0.1.0 | No |

Oh My Hook is pre-1.0. Only the latest published `0.x` release receives fixes;
older releases are not patched. Upgrade rather than requesting a backport.

## Reporting a Vulnerability

Report suspected vulnerabilities through **GitHub private vulnerability
reporting**: open the repository's **Security** tab and choose **Report a
vulnerability**. This creates a private advisory visible only to the
maintainers.

Please do not open a public issue, pull request, or discussion for an unfixed
vulnerability.

A useful report includes the affected version, the target architecture and
libc, the kernel or Android version, and the smallest reproducer you have.
State whether the trigger requires an untrusted input or only an unusual but
legitimate program layout. Expect an acknowledgement within seven days.

## Scope

This crate reads ELF structures out of live process memory, decodes instructions
at a caller-supplied entry, and writes function pointers and code bytes into the
running process. The interesting boundary is therefore the data the crate does
not produce itself.

In scope:

- A path from parsed ELF metadata, `/proc/<pid>/maps` text, or a caller-supplied
  symbol name to a write at an address that was never validated.
- An out-of-bounds read, unaligned access, integer truncation, or panic reached
  by parsing a malformed but reachable image.
- A safe function that can cause undefined behaviour, or that can terminate the
  process, without the caller violating a documented contract.
- Selection of the wrong relocation slot or a patch that extends beyond the
  analyzed entry.
- A failure path that leaves a page writable, a code range half-written, or a
  hook partially installed without reporting it.

Out of scope:

- Consequences of violating a documented `# Safety` contract. In particular,
  executing a target page while it is being patched is the caller's obligation
  to exclude; see the whole-page quiescence chapter of the guide.
- Deliberate process termination on an unrecoverable invariant failure. It is
  documented behaviour, not a denial of service.
- The ability of a process to modify its own memory. That is what this library
  is for; it grants no privilege the calling process did not already have.
- Hardening requests without a concrete reachable failure.

## Disclosure

Fixes are released as a new `0.x` version, with the impact and affected targets
described in the GitHub advisory and the release notes. Reporters are credited
unless they ask not to be.

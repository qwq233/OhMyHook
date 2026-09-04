# Agent Guide

## Project Boundaries

- Before adding a method, helper, abstraction, configuration field, or utility, inspect the
  directly relevant modules for equivalent behavior. Reuse or minimally extend existing code.
- Compatibility scope: Android 12-17; Common Linux distros; Linux kernels 4.14-6.18 and newer LTS kernels.
  Preserve behavior across this range, and do not claim a platform was validated without evidence.
- Do not introduce new non-Rust product or runtime code without explicit approval. Existing Python
  build/deployment scripts and shell packaging assets are tooling, not precedent for new runtime
  components.

## Repository Conventions

- Use targeted `rg` searches. Keep edits ASCII unless the file already uses non-ASCII.
- Production Rust code and in-tree tests must not emit diagnostics with `println!`,
  `eprintln!`, `print!`, `eprint!`, `dbg!`, or similar direct output functions.
  Use the `log` crate at the appropriate level instead. Examples and book snippets are exempt.

## Review Triage

- Treat a scenario as a low-probability extreme event only when it requires implausible simultaneous
  preconditions or resource/input scales outside supported deployments and cannot reasonably be
  triggered by an untrusted party. Do not report it as a review finding or change code to address it.
- If such a scenario is encountered during review, mention it only as a non-finding and state its
  concrete trigger conditions and why its occurrence or exposure is negligibly low. Do not justify
  dismissal with an unsupported label such as "unlikely" alone.

## Validation and Deployment

- For Rust code changes, run the repository's formatting and Clippy gate before handoff:

  ```sh
  sh .cargo-husky/hooks/pre-commit
  ```

  Run regular unit/integration tests and doctests separately; `cargo clippy` and `cargo doc` are not
  substitutes for either. A `no_run` doctest must still compile.

- Never validate a single hook feature in isolation. Do not pass
  `--no-default-features --features plt` or `--no-default-features --features inline` to Cargo
  validation commands. Run the complete default-feature workspace test suite with both features
  enabled (`cargo test --workspace`).
  Doc test is included.

- When an authorized aarch64 Android device is available, execute every generated workspace test
  binary on-device. If the device is unavailable, report that the device gate was not run; do not
  present host-side compilation as full validation. Documentation-only changes do not require
  regular code tests, but Rust documentation examples must pass doctests.

- Run every WSL command through Bash explicitly. Use `wsl.exe bash -lc '<command>'`; never invoke a
  command through bare `wsl.exe` or rely on the distribution's default shell. For example:

  ```powershell
  wsl.exe bash -lc 'echo hello world'
  ```

  Use WSL for testing. All test binaries must be in the project folder or `/tmp`.

- Do not add `#[allow(...)]` solely to silence Clippy. Any necessary exception must have a concrete,
  documented reason and direct approval from user.

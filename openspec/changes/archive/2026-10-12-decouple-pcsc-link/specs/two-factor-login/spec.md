# decouple-pcsc-link Delta

## ADDED Requirements

### Requirement: Exec-safe default build (no pcsclite link)

The default CLI build SHALL NOT link `libpcsclite`: its ELF SHALL carry
no pcsclite `DT_NEEDED` entry, so it execs and operates on hosts without
pcsclite, failing typed (exit codes 3/4/5) instead of the loader's 127.
CCID/NFC support SHALL remain available through the opt-in `fidoh-pcsc`
feature, whose flavor is behavior-identical to the pre-decoupling
default.

#### Scenario: exec-compat default binary

- **WHEN** the workspace is built with default features and `ldd` is
  applied to the produced CLI binary
- **THEN** no `libpcsclite` entry appears in its NEEDED list
- **AND** the binary executes successfully on a host without pcsclite

#### Scenario: packager flavor unchanged

- **WHEN** the CLI is built with `--features fidoh-pcsc` on a host with
  pcsclite dev headers
- **THEN** the build succeeds and the binary links pcsclite with CCID/NFC
  transport enabled, behavior-identical to the pre-decoupling default

#### Scenario: exec-compat-pcsc-diagnostic

- **WHEN** a default (no-binding) build runs a CTAP2 ceremony and no USB
  HID key is attached
- **THEN** the discovery diagnostics name the pcsc transport unavailable
  by its own cause (not linked into this build) alongside the HID
  result
- **AND** the exit is the typed transport error (exit 4), never a
  missing-library abort

# Changelog

Notable changes to this project will be documented in this file.

## Unreleased

### Changed

- Replaced Linux `dconf` and `gsettings` subprocesses with runtime-loaded,
  in-process GIO configuration reads and change notifications.
- Raised the minimum supported Rust version to 1.94.

## 0.4.0

### Fixed

- Terminated Linux `dconf` and `gsettings` proxy watchers when their owning
  process exits without running Rust destructors.
- Prevented Linux proxy watchers from inheriting unrelated file descriptors,
  including Chromium shared-memory resources.

### Documentation

- Directed support requests to the `microsoft/vscode` issue tracker.

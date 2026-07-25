# Changelog
<!-- markdownlint-disable MD024 -->

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) since version 1.0.2,
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-07-25

### Security

- Updated golang.org/x/crypto from 0.45.0 to 0.52.0 #46

## [1.0.1] - 2025-11-21

### Security

- Updated golang.org/x/crypto from 0.36.0 to 0.45.0 #44

## [1.0.0] - 2025-08-04

### Changed

- The file format default has been switched to version 3.
  To generate file format versions 1 and 2, you must explicitly use the -F 1 or -F 2 option.
  Decryption will automatically detect the format version.

## [0.0.10] - 2025-07-16

### Added

- Added support for file format version 3 (v3).
  Use -F 3 option to generate v3 files.
  Default remains v1 for compatibility.
  v3 includes updated signature scheme with stronger algorithms (see README for details).
  Decryption automatically detects format version.

## [0.0.9] - 2025-06-29

### Added

- Added support for file format version 2 (v2).
  Use -F 2 option to generate v2 files.
  Default remains v1 for compatibility.
  v2 includes updated encryption scheme with stronger algorithms (see README for details).
  Decryption automatically detects format version.

### Changed

- Minimum required Go version updated from 1.23 to 1.24 (due to HKDF usage)

## [0.0.8] - 2025-06-12

### Fixed

- fix: update public key handling to use pointer types and add tests for multi-type public keys #10

## [0.0.7] - 2025-03-04

### Fixed

- fix: toX25519PublicKey() in toX25519.go #4

## [0.0.6] - 2023-05-18

### Added

- Homebrew support #3

## [0.0.5] - 2023-05-17

### Fixed

- fix: ToCaesarPubKey() in pubkey.go

## [0.0.4] - 2023-05-17

### Fixed

- fix: get version information in main.go

## [0.0.3] - 2023-05-17

### Fixed

- fix: When there are 0 recipient public keys
- fix: GetAuthKey() in rsa.PrivateKey

## [0.0.2] - 2023-05-14

### Fixed

- fix: Check when public key is omitted

## [0.0.1] - 2023-05-14

### Added

- Initial release

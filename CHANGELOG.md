# Changelog

## [0.1.4] - 2026-11-15

### Added
- X.509 certificate inspection using cryptography.
- TLS integration tests covering valid, expired, untrusted,
  and hostname-mismatched certificates.

### Improved
- Separate certificate metadata retrieval from TLS validation.
- Preserve certificate validation failures while retrieving
  expiry metadata.
- Report HTTP reachability, certificate metadata, and
  certificate validation independently.

### Dependencies
- Add cryptography 46.0.4 for X.509 certificate parsing.

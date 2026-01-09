# vault-support-thisismyurl
Vault System for the thisismyurl.com Shared Code Suite - secure original storage, encryption, journaling, and cloud offload for media files

## Overview

The Vault Support module provides enterprise-grade media asset protection for WordPress. It offers:

- **Secure Storage:** Randomized, protected vault directories with multi-layer access control
- **Encryption:** AES-256-GCM encryption with key rotation support
- **Integrity:** SHA-256 hash verification and tamper detection
- **Journaling:** Complete audit trail of all operations
- **Cloud Offload:** Google Drive integration with additional providers planned
- **Rollback:** Restore individual files or complete snapshots to previous states
- **GDPR Compliance:** EXIF stripping and personal data erasure capabilities
- **WP-CLI:** Comprehensive command-line tools for automation

## Features

### Currently Implemented
- Granular restore for individual files
- Off-site backup encryption (AES-256-GCM)
- Automatic backup verification with SHA-256 hashing
- WP-CLI backup commands
- File integrity monitoring
- Metadata privacy controls (EXIF stripping)
- Instant rollback capabilities
- Google Drive integration

### Roadmap
See [FEATURE_IDEAS.md](FEATURE_IDEAS.md) for the complete feature roadmap including:
- One-click media library backups
- Scheduled and incremental backups
- Export wizards and migration tools
- Malware scanning
- Cross-site sync
- And much more...

## Installation

This module is part of the TIMU Core Module Loader system and requires:
- **Media Support** module (hub)
- TIMU Core Support framework

## Usage

### Admin Interface
Access Vault settings through the WordPress admin menu under TIMU Core → Vault.

### WP-CLI Commands
```bash
# Restore files from vault
wp timu vault rehydrate [--attachment-id=<id>]

# Verify vault integrity
wp timu vault verify [--sample=<count>]

# Check vault status
wp timu vault status

# Migrate attachments to vault
wp timu vault migrate [--batch-size=<size>]

# Erase user personal data (GDPR)
wp timu vault erase-user-data --user-id=<id>
```

## Documentation

- [FEATURE_IDEAS.md](FEATURE_IDEAS.md) - Complete feature roadmap and implementation status
- [module.php](module.php) - Module initialization and hooks
- [includes/class-timu-vault.php](includes/class-timu-vault.php) - Core vault implementation

## Contributing

Contributions are welcome! Please:
1. Review [FEATURE_IDEAS.md](FEATURE_IDEAS.md) for planned features
2. Open an issue to discuss new features or enhancements
3. Submit pull requests with comprehensive tests
4. Follow WordPress coding standards

## License

Part of the thisismyurl.com Shared Code Suite

## Support

For issues, questions, or feature requests, please use the GitHub issue tracker.

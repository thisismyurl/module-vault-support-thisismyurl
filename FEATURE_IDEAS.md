# Vault Feature Ideas & Roadmap

This document tracks all proposed features for the Vault Support module. Each feature includes implementation status, priority, and technical considerations.

## Status Legend
- 🟢 **Implemented** - Feature is complete and tested
- 🟡 **In Progress** - Feature is currently being developed
- 🔴 **Planned** - Feature is planned but not yet started
- 🔵 **Under Review** - Feature is being evaluated

## Priority Legend
- **P0** - Critical / Must Have
- **P1** - High Priority
- **P2** - Medium Priority
- **P3** - Low Priority / Nice to Have

---

## Backup & Restore Features

### 1. One-Click Media Library Backup
**Status:** 🔴 Planned  
**Priority:** P1

Export all media files and metadata in a single click.

**Technical Requirements:**
- Create unified export interface in admin UI
- Package media files with associated metadata (titles, alt text, captions)
- Include attachment relationships and taxonomy
- Generate manifest file for reconstruction
- Support background processing for large libraries

**Dependencies:** None

---

### 2. Scheduled Backups
**Status:** 🔴 Planned  
**Priority:** P1

Automate daily/weekly backups of media assets.

**Technical Requirements:**
- Integrate with WordPress cron system
- Allow configurable backup intervals (hourly, daily, weekly, monthly)
- Support backup retention policies
- Email notifications on backup completion/failure
- Admin UI for schedule management

**Dependencies:** Feature #1 (One-Click Media Library Backup)

---

### 3. Incremental Backups
**Status:** 🔴 Planned  
**Priority:** P1

Only back up new or changed files to save time and storage.

**Technical Requirements:**
- Track file modification timestamps
- Store checksums for change detection
- Implement differential backup algorithm
- Maintain backup chain integrity
- Support full+incremental restore workflow

**Dependencies:** Feature #2 (Scheduled Backups)

---

### 4. Restore Points
**Status:** 🔴 Planned  
**Priority:** P0

Create restore points for the entire Media Library before major updates.

**Technical Requirements:**
- Snapshot current vault state
- Tag snapshots with descriptive names and timestamps
- Store metadata about WordPress version, active plugins
- Quick restore interface
- Rollback validation and integrity checks

**Dependencies:** Existing vault infrastructure

---

### 5. Granular Restore
**Status:** 🟢 Implemented  
**Priority:** P0

Restore individual files or folders without rolling back the entire site.

**Technical Notes:**
- Currently implemented via `rehydrate()` method
- Individual attachment restore available in metabox
- Journal-based rollback for single attachments
- WP-CLI commands: `wp timu vault rehydrate [--attachment-id=<id>]`

**Related Code:** `class-timu-vault.php` - `rehydrate()`, `rollback_attachment()`

---

### 6. Backup to Multiple Destinations
**Status:** 🟡 In Progress  
**Priority:** P1

Local server, cloud storage (Google Drive, Dropbox, OneDrive), and S3-compatible services.

**Technical Notes:**
- ✅ Google Drive integration implemented
- ✅ Local vault storage implemented
- ⏳ Dropbox integration planned
- ⏳ OneDrive integration planned
- ⏳ S3-compatible services planned

**Technical Requirements:**
- Abstraction layer for storage providers
- Provider-specific authentication flows
- Unified backup/restore interface
- Connection health monitoring
- Failover handling

**Related Code:** `class-timu-vault.php` - Google Drive methods (`gdrive_*`)

---

### 7. Off-Site Backup Encryption
**Status:** 🟢 Implemented  
**Priority:** P0

Encrypt backups before sending them to external storage.

**Technical Notes:**
- AES-256-GCM encryption implemented
- Key rotation support available
- Encryption key management (const or database)
- IV and authentication tag generation
- Legacy CBC format support for backward compatibility

**Related Code:** `class-timu-vault.php` - `encrypt_file_gcm()`, `decrypt_file()`

---

### 8. Backup Verification
**Status:** 🟢 Implemented  
**Priority:** P0

Automatic integrity checks to ensure backups are valid.

**Technical Notes:**
- SHA-256 hash verification for stored files
- Separate hashes for raw and stored (compressed/encrypted) files
- Integrity verification on rehydration
- WP-CLI verify command available
- Metadata signature validation

**Related Code:** `class-timu-vault.php` - `verify_attachment_integrity()`, `verify_sample()`

---

### 9. Versioned Backups
**Status:** 🟡 In Progress  
**Priority:** P2

Keep multiple versions of backups for rollback flexibility.

**Technical Notes:**
- ✅ Journal system tracks all operations
- ✅ Rollback to previous states implemented
- ⏳ Automatic version pruning needed
- ⏳ Version comparison UI needed

**Technical Requirements:**
- Version retention policies
- Storage optimization for versions
- Diff view between versions
- Version labels and annotations

**Related Code:** `class-timu-vault.php` - `add_journal_entry()`, `rollback_attachment()`

---

### 10. WP-CLI Backup Commands
**Status:** 🟢 Implemented  
**Priority:** P1

Command-line tools for power users to back up and restore media.

**Technical Notes:**
- ✅ `wp timu vault rehydrate [--attachment-id=<id>]` - Restore files from vault
- ✅ `wp timu vault verify [--sample=<count>]` - Verify integrity
- ✅ `wp timu vault status` - Check vault status and statistics
- ✅ `wp timu vault migrate [--batch-size=<size>]` - Migrate attachments to vault in batches
- ✅ `wp timu vault erase-user-data --user-id=<id>` - GDPR-compliant personal data erasure

**Related Code:** `class-timu-vault.php` - `cli_*()` methods

---

## Export & Migration Features

### 11. Media Export Wizard
**Status:** 🟡 In Progress  
**Priority:** P1

Export media with metadata, tags, and usage info for migration.

**Technical Notes:**
- ✅ Export bundle functionality exists
- ✅ Journal export implemented
- ⏳ GUI wizard needed
- ⏳ Usage tracking needed

**Technical Requirements:**
- Step-by-step export interface
- Metadata mapping configuration
- Progress tracking for large exports
- Export format selection (ZIP, TAR, etc.)
- Import companion tool

**Related Code:** `class-timu-vault.php` - `handle_export_bundle()`

---

### 12. Selective Export
**Status:** 🔴 Planned  
**Priority:** P2

Export by date range, file type, or category.

**Technical Requirements:**
- Advanced filtering UI
- Query builder for complex selections
- Preview before export
- Batch processing for large selections
- Export manifest with filter criteria

**Dependencies:** Feature #11 (Media Export Wizard)

---

### 13. Bulk Download with Structure
**Status:** 🔴 Planned  
**Priority:** P2

Download media in organized folders matching taxonomy.

**Technical Requirements:**
- Preserve directory structure
- Map taxonomies to folder hierarchy
- ZIP archive generation
- Maintain file relationships
- Include README with structure explanation

**Dependencies:** Feature #11 (Media Export Wizard)

---

### 14. Cross-Site Sync
**Status:** 🔴 Planned  
**Priority:** P2

Sync media between multiple WordPress sites.

**Technical Requirements:**
- Site-to-site authentication mechanism
- Bi-directional sync capabilities
- Conflict resolution strategy
- Network support for multisite
- Sync scheduling and monitoring
- Bandwidth throttling

**Dependencies:** None (but complements multisite features)

---

### 15. CDN Integration for Redundancy
**Status:** 🔴 Planned  
**Priority:** P3

Push media to CDN for performance and backup.

**Technical Requirements:**
- Integration with major CDN providers (CloudFlare, Fastly, AWS CloudFront)
- Automatic URL rewriting
- Cache invalidation on updates
- Fallback to origin on CDN failure
- Analytics and performance monitoring

**Dependencies:** None

---

## Safety & Security Enhancements

### 16. Malware & Virus Scanning
**Status:** 🔴 Planned  
**Priority:** P1

Scan uploaded files for malicious code.

**Technical Requirements:**
- Integration with ClamAV or similar
- API-based scanning (VirusTotal, etc.)
- Quarantine infected files
- Email alerts for threats
- Schedule periodic rescans
- Whitelist management

**Dependencies:** External scanning service or library

---

### 17. File Integrity Monitoring
**Status:** 🟢 Implemented  
**Priority:** P0

Detect unauthorized changes to media files.

**Technical Notes:**
- SHA-256 hashing on ingest
- Hash verification on access
- Integrity check commands
- Tampering detection and alerts
- Ledger tracks all operations

**Related Code:** `class-timu-vault.php` - Hash verification throughout

---

### 18. Role-Based Upload Permissions
**Status:** 🟡 In Progress  
**Priority:** P1

Restrict who can upload, replace, or delete media.

**Technical Notes:**
- ✅ Contributor upload flagging implemented
- ✅ Review workflow for non-editors
- ⏳ Granular capability mapping needed
- ⏳ Admin UI for permission management

**Technical Requirements:**
- Custom capabilities for vault operations
- Role-based access control matrix
- Audit log for permission changes
- Integration with members plugins

**Related Code:** `class-timu-vault.php` - `maybe_flag_pending_review()`

---

### 19. Safe SVG Handling
**Status:** 🔴 Planned  
**Priority:** P1

Sanitize SVG uploads to prevent XSS attacks.

**Technical Requirements:**
- SVG sanitization library (DOMPurify or similar)
- Whitelist allowed SVG elements and attributes
- Strip JavaScript and event handlers
- Validate XML structure
- Re-encode after sanitization
- Security headers for SVG delivery

**Dependencies:** SVG sanitization library

---

### 20. Metadata Privacy Controls
**Status:** 🟢 Implemented  
**Priority:** P1

Strip sensitive EXIF data (GPS, camera info) on upload.

**Technical Notes:**
- EXIF stripping implemented via Imagick or GD
- Supports JPEG, PNG, WebP formats
- Automatic on anonymization
- GDPR compliance feature

**Technical Requirements:**
- User-selectable privacy levels
- Preview EXIF before upload
- Selective EXIF preservation (copyright, attribution)
- Bulk EXIF removal tool

**Related Code:** `class-timu-vault.php` - `strip_exif_from_file()`, `strip_exif_from_attachment()`

---

## Disaster Recovery & Redundancy

### 21. Auto-Failover Storage
**Status:** 🔴 Planned  
**Priority:** P2

Mirror media to secondary storage for redundancy.

**Technical Requirements:**
- Real-time or near-real-time mirroring
- Health checks for storage endpoints
- Automatic failover on primary failure
- Transparent fallback for read operations
- Sync verification and repair

**Dependencies:** Feature #6 (Backup to Multiple Destinations)

---

### 22. Instant Rollback
**Status:** 🟢 Implemented  
**Priority:** P0

Roll back to last known good state after corruption or hack.

**Technical Notes:**
- Journal-based rollback implemented
- Step-by-step rollback to any operation
- Derivative rebuilding on rollback
- WP-CLI rollback commands available

**Related Code:** `class-timu-vault.php` - `rollback_attachment()`

---

### 23. Cloud Sync with Conflict Resolution
**Status:** 🔴 Planned  
**Priority:** P2

Sync media to cloud and resolve conflicts automatically.

**Technical Requirements:**
- Three-way merge algorithm
- Conflict detection (timestamp, hash, version)
- Resolution strategies (last-write-wins, manual, metadata-based)
- Conflict log and review interface
- Test mode for conflict resolution strategies

**Dependencies:** Feature #6 (Backup to Multiple Destinations), Feature #14 (Cross-Site Sync)

---

### 24. Offline Archive Mode
**Status:** 🔴 Planned  
**Priority:** P3

Archive old media to cold storage while keeping metadata searchable.

**Technical Requirements:**
- Age-based archival policies
- Seamless retrieval from archive
- Metadata indexing for archived items
- Cost optimization for cloud storage tiers
- Admin interface for archive management
- Restore SLA indicators

**Dependencies:** Feature #6 (Backup to Multiple Destinations)

---

### 25. Backup Health Dashboard
**Status:** 🔴 Planned  
**Priority:** P1

Show backup status, last run, and restore options in one place.

**Technical Requirements:**
- Real-time status widgets
- Last backup timestamp and size
- Success/failure rates
- Storage capacity monitoring
- Quick restore actions
- Export logs and reports
- Alert configuration

**Dependencies:** Multiple backup features

---

## Implementation Priority

### Phase 1 (Critical - Already Implemented)
- ✅ Feature #5: Granular Restore
- ✅ Feature #7: Off-Site Backup Encryption
- ✅ Feature #8: Backup Verification
- ✅ Feature #10: WP-CLI Backup Commands
- ✅ Feature #17: File Integrity Monitoring
- ✅ Feature #20: Metadata Privacy Controls
- ✅ Feature #22: Instant Rollback

### Phase 2 (High Priority - Next)
- 🔴 Feature #1: One-Click Media Library Backup
- 🔴 Feature #2: Scheduled Backups
- 🔴 Feature #3: Incremental Backups
- 🔴 Feature #4: Restore Points
- 🟡 Feature #6: Backup to Multiple Destinations (extend)
- 🔴 Feature #16: Malware & Virus Scanning
- 🔴 Feature #19: Safe SVG Handling
- 🔴 Feature #25: Backup Health Dashboard

### Phase 3 (Medium Priority)
- 🟡 Feature #9: Versioned Backups (enhance)
- 🟡 Feature #11: Media Export Wizard (enhance)
- 🔴 Feature #12: Selective Export
- 🔴 Feature #13: Bulk Download with Structure
- 🔴 Feature #14: Cross-Site Sync
- 🟡 Feature #18: Role-Based Upload Permissions (enhance)
- 🔴 Feature #21: Auto-Failover Storage
- 🔴 Feature #23: Cloud Sync with Conflict Resolution

### Phase 4 (Low Priority)
- 🔴 Feature #15: CDN Integration for Redundancy
- 🔴 Feature #24: Offline Archive Mode

---

## Technical Architecture Notes

### Current Implementation Highlights

**Vault Core:**
- Secure randomized vault directory names
- Multi-layer protection (.htaccess, web.config, index.php)
- Raw and ZIP storage modes with configurable compression
- SHA-256 integrity verification

**Encryption:**
- AES-256-GCM with authentication tags
- Key rotation support
- Backward compatibility with CBC legacy format
- Configurable key source (constant or database)

**Journaling:**
- Per-attachment operation journal
- Global ledger across all attachments
- Disk mirroring for crash resilience
- Full audit trail for compliance

**Integration Points:**
- WordPress attachment hooks
- WP-CLI command support
- Admin UI with metaboxes
- Network admin for multisite

### Areas for Enhancement

1. **User Interface:** More intuitive backup/restore wizards
2. **Reporting:** Enhanced analytics and health monitoring
3. **Automation:** More sophisticated scheduling and policies
4. **Integration:** Additional cloud providers and CDN services
5. **Performance:** Optimization for very large media libraries
6. **Testing:** Comprehensive test coverage for all features

---

## Contributing

To propose a new feature or enhancement:

1. Check if the feature is already listed in this document
2. Review the technical requirements and dependencies
3. Open a discussion issue to gather feedback
4. Create a detailed implementation plan
5. Submit a pull request with your implementation

## References

- [WordPress Media Handling](https://developer.wordpress.org/apis/media/)
- [GDPR Personal Data Guidelines](https://wordpress.org/about/privacy/)
- [WordPress Security White Paper](https://wordpress.org/about/security/)
- [WP-CLI Commands](https://make.wordpress.org/cli/handbook/)

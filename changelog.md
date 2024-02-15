# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Find module
    - Site servers and Management Points are broken out to their own table
    - Added `-resolve` flag to handle unrolling group membership. 
    - Added CAS, SMSprovider, and Config columns to Site Servers table
    - Added SMSProvider to Computers Table
- SMB module
    - Added SMS Provider check
    - Added Management Point check
    - Added Active/Passive config check
    - Added Central Administration Site check
- HTTP module
    - Added "stop on success" logic if credentials are recovered
    - NPT DONE: Added `-sleep` flag to set time to wait until requesting policies following registration
    - NOT DONE: Added `-uuid` and `-computername` flags to allow the operator to manually request policie
- MSSQL module
    - Added `-stacked` flag to provide a stacked MSSQL query for relaying rather than individual queries
- Admin module
    - Added `show_admins` command to list current admin accounts
- Show module
    - Added `-json` and `-csv` flags to export tables 
    - NOTE DONE: Added `-creds` flag to show recovered credentials from HTTP or DPAPI

### Changed
- Updated all data storage methods to SQLite
- Changed banner

### Removed

### Fixed
- Find module
    - Refactored code and fixed bug to not properly handle LDAP searches
- SMB module
    - Fixed a bug where discovered site servers and management points weren't being added for service checks


## [0.0.3] - 2023-12-04

### Added

- DPAPI module [added](https://github.com/garrettfoster13/sccmhunter/pull/30) by [@s1zzzz](https://twitter.com/s1zzzz)


## [0.0.2] - 2023-10-06

### Added

- Added admin module 
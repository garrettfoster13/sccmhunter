# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.0.6] - 2024-08-15

### Fixed

- Fixed a bug where site servers weren't being added to the computers table causing further profiling to fail
- Fixed a bug in `MSSQL` where SID translation failed when using Kerberos authentication


### Added
- Find module
    - Added distribution point check in LDAP
- SMB module
    - Added distribution point profiling to determine if the found host is SCCM or WDS related
- Admin module
    - Added "approver credentials" check to ensure credentials are valid when script approval is required for the hierarchy

## [1.0.5] - 2024-06-9

### Fixed

- Fixed a bug where an arbitrary security group would get removed when running the `delete_admin` command in the Admin module
- Fixed a bug where an existing admin account would not be located due to a displayname vs logonname conflict




## [1.0.4] - 2024-05-28

### Fixed

- Updated `MSSQL` module's stacked query to check if the account already exists by [@_Mayyhem](https://twitter.com/_Mayyhem)

### Added
- Additional DPAPI module features added by [@s1zzzz](https://twitter.com/s1zzzz)


## [1.0.3] - 2024-04-9

### Fixed

- Fixed bug where `find` would hard fail if a computer object did not have a dNSHostName attribute


## [1.0.2] - 2024-04-3

### Fixed

- Fixed bug where the `SMB` module would fail while spidering the "REMINST" share if the "SMSTemp" directory did not exist

## [1.0.1] - 2024-3-20

### Fixed

- Fixed Kerberos auth bug where LDAP parsing failed

## [1.0.0] - 2024-2-27

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
    - Added `-sleep` flag to set time to wait until requesting policies following registration
    - Added `-uuid` and `-mp` flags to allow the operator to manually request policies
- MSSQL module
    - Added `-stacked` flag to provide a stacked MSSQL query for relaying rather than individual queries
- Admin module
    - Added `show_admins` command to list current admin accounts
- Show module
    - Added `-json` and `-csv` flags to export tables 
    - Added `-creds` flag to show recovered credentials from HTTP or DPAPI

### Changed
- Updated all data storage methods to SQLite
- Changed banner



### Fixed
- Find module
    - Refactored code and fixed bug to not properly perform LDAP searches
- SMB module
    - Fixed a bug where discovered site servers and management points weren't being added for service checks
- HTTP module
    - Fixed a bug where errors weren't properly handled if the database was missing (caused by not running the find module)
    - Fixed a bug where Management Points weren't being pulled from the Computers table


## [0.0.3] - 2023-12-04

### Added

- DPAPI module [added](https://github.com/garrettfoster13/sccmhunter/pull/30) by [@s1zzzz](https://twitter.com/s1zzzz)


## [0.0.2] - 2023-10-06

### Added

- Added admin module 

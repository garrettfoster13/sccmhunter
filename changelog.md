# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.11] - 2025-10-30

## Added 

- HTTP Module
    - Added AES-256 support for credential decryption to fix #96


## [1.1.10] - 2025-08-06

## Added
- Relay Module
    - Added a new module to support [TAKEOVER-5](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-5/takeover-5_description.md). Operators can relay coerced authentication to the SMS Provider role to compromise SCCM. 

- HTTP Module
    - Thanks to @MrFey for adding client push functionality to the HTTP in #93. SCCMHunter now supports abusing [ELEVATE-2](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/ELEVATE/ELEVATE-2/ELEVATE-2_description.md) from Linux.

## [1.0.10] - 2025-04-03

## Added
- SMB Module
    - Added remote registry check on site servers to enumerate remote site database servers

## [1.0.9] - 2025-04-03

### Fixed

- Find Module
    - Fixed a bug where ldap auth was missing paramaters

## [1.0.8] - 2025-03-03

### Added

- Admin Module
    - Added `get_creds` command to pull credential blobs from SCCM
    - Added `get_azurecreds` command to pull Azure co-management application blobs
    - Added `get_azuretenant` commant to pull Azure tenant info
    - Added `get_pxepassword` command to pull PXE boot blobs if configured
    - Added `get_forestkey` command to pull forest discovery session key blobs
    - Added `decrypt` command to decrypt passed credential blob
    - Added `decryptEx` command to decrypt forest discovery credential blobs
        - You've got to be "interactive" with the SCCM primary site server for decryption to work 
        - This means the site server must be a client 
        - Uses script execution
    - Updates thanks to [Parzel](https://bsky.app/profile/parzel.bsky.social):
    - Added `list_script` command to list scripts published to SCCM
    - Added `delete_script` commmand to delete a target script from SCCM 
   
## [1.0.7] - 2025-02-28

## Fixed
- HTTP Module
    - Fixed a bug where `-mp` flag wasn't correctly setting the policy request target

## Added

- Find module
    - Channel binding is now supported when using NTLM auth
- MSSQL module
    - Channel binding is now supported when using NTLM auth
    
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

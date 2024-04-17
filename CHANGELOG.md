# CHANGELOG
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) 
and this project adheres to [Semantic Versioning](http://semver.org/).

<!-- Template
### Fixed
### Added
### Changed
### Security
### Deprecated
### Removed
-->

## Unreleased

<!--
### Fixed
### Added
### Changed
### Security
### Deprecated
### Removed
-->

## [5.1.1] - 2022-11-03

### Fixed

* A formatting issue related to -v 10 option has been fixed.

## [5.1] - 2022-10-31

### Added

* Introduces thirteen options related to InQuest Labs.

### Fixed

* Fix an issue related to -b 6 option from ThreatFox.

## [5.0.3] - 2022-06-29

### Added

* Includes the possibility of getting information from 
* Includes macOS as operating system supported to run Malwoverview.
  Hybrid-Analysis using a SHA256 hash or the malware file.

### Removed

* Removes all options related to ThreatCrowd.

### Fixed

* Fix an issue related to downloading from Malshare.

## [5.0.2] - 2022-03-29

### Fixed

* Includes a small fix for options -v 1 and -v 8. 

## [5.0.0] - 2022-03-17

### Added

* Includes upgrades of all Virus Total options from API v.2 
  to API v.3.
* Introduces a new option to check hashes within a given
  file using Virus Total.
* Introduces a new option to submit large files (>= 32 MB) to
  Virus Total.
* Introduces a new purpose for -D option.

### Changed

* Changes all Virus Total options.
* Changes all Malshare options.
* Inverts Malpedia options ("m" and "M") purposes.
* Changes all URLhaus options.
* Changes all Polyswarm options.
* Changes -d option to Virus Total APIi v.3 with a new content.
* Upgrades, fixes and merges Android options.
* Updates Android options to Android 11 version.
* Swaps options -q and -Q from Threatcrowd.
* Changes configuration, setup and requirement files.

### Removed

* Removes Malshare option to check a binary.
* Removes all Valhalla options completely.
* Removes -g option.
* Removes -S and -z options.
* Removes -t and T options.
* Removes several support functions.
* Removes many option's letters used in previous versions.

### Fixed

* Fixes and changes Hybrid Analysis options.
* Fixes tag option from Triage.
* Fixes URL formatting issues from URLhaus.
* Fixes several color issues.
* Fixes descriptions.

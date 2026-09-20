# Changelog

All notable changes to this project will be documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

Per-version release notes for tagged releases are published on the [GitHub Releases page](https://github.com/WYRE-AI/cork-mcp/releases) - `semantic-release` generates them from commit history at release time.

## [Unreleased]

### Added

- Initial v1 release: 23 read-only, non-credential-exposing tools covering clients (with warranty status and Cork Cyber Score history), risk & compliance events, software vulnerabilities (CVE/CVSS/EPSS/KEV), a read-only subset of integrations, invoices, distributor partners, and a read-only subset of software-installer metadata. Bearer API key authentication (generated in Cork's Admin UI). See README's Scope section for the full list of deliberately excluded credential-exposing, bulk-raw-data, and write/provisioning endpoints.

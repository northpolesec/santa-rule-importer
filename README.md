# Santa Rule Importer (santa-rule-importer)

This project reads all rules out of: a
[Moroz](https://github.com/groob/moroz) TOML config, a
[Rudolph](https://github.com/airbnb/rudolph/tree/master) [CSV rule
export](https://github.com/airbnb/rudolph/blob/master/docs/rules.md#importing-or-exporting-rules),
a Zentral server, or a Santa [File Access Authorization](https://northpole.dev/configuration/faa/)
policy plist, and imports it into a Workshop instance using the API.

# Table of Contents

- [Quick Start](#quick-start)
- [Building](#building)
- [Usage](#usage)

# Quick Start

Run the following:
- `make deps`
- `make build`
- Export `WORKSHOP_API_KEY` with your Workshop API key which must have the `write:rules` permission
- run ./santa-rule-importer

# Building

```
prompt$ make build # build the binary
```

# Usage

```
$  ./santa-rule-importer --help
Usage: ./santa-rule-importer [OPTIONS] <path to config.toml|path to config.csv> <server>

santa-rule-importer - tool to import rules from Moroz, Rudolph, and Zentral to Workshop

This tool expects the Workshop API Key to be in the WORKSHOP_API_KEY env var
For Zentral imports, set ZENTRAL_API_KEY env var with your Zentral API token

  -insecure
    	Use insecure connection
  -use-custom-msg-as-comment
    	Use custom message as comment (moroz only)
  -zentral-config-id int
    	Filter Zentral rules by configuration ID
  -zentral-target-identifier string
    	Filter Zentral rules by target identifier
  -zentral-target-type string
    	Filter Zentral rules by target type (BINARY, CERTIFICATE, etc.)
  -zentral-url string
    	Zentral base URL (e.g., zentral.example.com)

  Example Usage:
	./santa-rule-importer global.toml nps.workshop.cloud
	./santa-rule-importer faa_policy.plist nps.workshop.cloud
```

## File Access Authorization (FAA) Import

The tool supports importing Santa [File Access Authorization](https://northpole.dev/configuration/faa/)
rules from:

- **Standalone `.plist` files** containing an FAA policy directly
- **`.mobileconfig` files** that embed a `FileAccessPolicy` dictionary (FAA rules are imported alongside any StaticRules)

The FAA policy's `WatchItems` are converted to Workshop file access rules. Key mappings:

| Santa Config | Workshop API |
|---|---|
| `AuditOnly` (default: true) | `BlockViolations` (inverted) |
| `AllowReadAccess` (default: true) | `AllowReadAccess` |
| `Paths` with `IsPrefix=false` | `PathLiterals` |
| `Paths` with `IsPrefix=true` | `PathPrefixes` |
| `PlatformBinary=true` + `SigningID` | `ProcessSigningIds` as `platform:<SigningID>` |

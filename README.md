# Santa Rule Importer (santa-rule-importer)

This project reads all rules out of: a
[Moroz](https://github.com/groob/moroz) TOML config, a
[Rudolph](https://github.com/airbnb/rudolph/tree/master) [CSV rule
export](https://github.com/airbnb/rudolph/blob/master/docs/rules.md#importing-or-exporting-rules),
a Zentral server, or an FAA (File Access Authorization) plist file, and imports
it into a Workshop instance using the API.

**Note:** All rules imported by this tool are added to the global tag (no tag specified).

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
Usage: ./santa-rule-importer [OPTIONS] <path to config.toml|path to config.csv|path to plist> <server>

santa-rule-importer - tool to import rules from Moroz, Rudolph, Zentral, or FAA plist to Workshop

This tool expects the Workshop API Key to be in the WORKSHOP_API_KEY env var
For Zentral imports, set ZENTRAL_API_KEY env var with your Zentral API token

  -faa string
    	Path to FAA plist file for file access rules
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
	./santa-rule-importer --zentral-url zentral.example.com nps.workshop.cloud
	./santa-rule-importer --faa faa.plist nps.workshop.cloud
```

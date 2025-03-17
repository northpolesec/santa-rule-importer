# Santa Rule Importer (santaruleimporter)

This project reads all rules out of either a [Moroz](https://github.com/groob/moroz) TOML config or [Rudolph](https://github.com/airbnb/rudolph/tree/master) [CSV rule export](https://github.com/airbnb/rudolph/blob/master/docs/rules.md#importing-or-exporting-rules) and imports it into a Workshop instance using the API.

# Table of Contents

- [Quick Start](#quick-start)
- [Building](#building)
	- [Build Details](#build-details)
- [Usage](#usage)

# Quick Start

Run the following:
- `make deps`
- `make build`
- Export `WORKSHOP_API_KEY` with your Workshop API key which must have the superadmin role.
- run ./santa-rule-importer

## Example

```shell
$  make deps
export GOPRIVATE="buf.build/gen/go,"
buf registry login
Opening your browser to complete authorization process.

If your browser doesn't open automatically, please open this URL in a browser to complete the process:

https://buf.build/settings/user/device?code=MXXX-XXXX

Logged in as user. Credentials saved to /Users/user/.netrc.
go mod tidy
[ user@Mac (11:45PM) ~/santaruleimporter  ]
$  make build
go build -o santa-rule-importer ./cmd/main.go
[ user@Mac (11:45PM) ~/santaruleimporter  ]
$  ./santa-rule-importer -insecure ./internal/morozconfig/testdata/global.toml nps.workshop.cloud
2/2 rules added successfully!
```

# Building

You need access to NPS' prebuilt Go packages that are hosted in a private
registry on buf.build.

Assuming you have access to the registry you can run:

```shell
prompt$ make deps  # get the dependencies and buf
prompt$ make build # build the binary
```

## Build Details

This does the following:

```shell
prompt$ export GOPRIVATE="buf.build/gen/go,${GOPRIVATE}"
prompt$ buf registry login
Opening your browser to complete authorization process.

If your browser doesn't open automatically, please open this URL in a browser to complete the process:

https://buf.build/settings/user/device?code=[REDACTED]

Logged in as user. Credentials saved to /Users/user/.netrc.
prompt$ go mod download
```

You can now build the importer.

```shell
prompt$ go build -o moroz-rule-importer ./cmd/main.go
```

# Usage

```
$  ./santa-rule-importer 
Usage: ./santa-rule-importer [OPTIONS] <path to config.toml|path to config.csv> <server>

santa-rule-importer - tool to import rules from Moroz and Rudolph to Workshop

This tool expects the Workshop API Key to be in the WORKSHOP_API_KEY env var

  -insecure
    	Use insecure connection

  Example Usage:
	./santa-rule-importer global.toml nps.workshop.cloud
```

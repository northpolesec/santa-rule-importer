module github.com/northpolesec/santa-rule-importer

go 1.24.0

require (
	buf.build/gen/go/northpolesec/workshop-api/grpc/go v1.6.1-20260325193457-b769703ebb01.1
	buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go v1.36.11-20260325193457-b769703ebb01.1
	github.com/pelletier/go-toml/v2 v2.2.3
	github.com/shoenig/test v1.12.1
	google.golang.org/grpc v1.78.0
	howett.net/plist v1.0.1
)

require (
	buf.build/gen/go/northpolesec/protos/protocolbuffers/go v1.36.11-20260320155918-251ad97cbbf5.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

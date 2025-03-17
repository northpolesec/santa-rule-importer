// Utility to add rules from Moroz or Rudolph to a Workshop instance.
// Copyright (c) 2025 North Pole Security, Inc.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/northpolesec/santa-rule-importer/internal/morozconfig"
	"github.com/northpolesec/santa-rule-importer/internal/rudolph"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <path to config.toml|path to config.csv> <server>\n", os.Args[0])
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "santa-rule-importer - tool to import rules from Moroz and Rudolph to Workshop\n")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "This tool expects the Workshop API Key to be in the WORKSHOP_API_KEY env var\n")
	fmt.Fprintln(os.Stderr)
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Example Usage:")
	fmt.Fprintf(os.Stderr, "\t%s global.toml nps.workshop.cloud\n", os.Args[0])
	os.Exit(1)
}

func main() {
	useInsecure := flag.Bool("insecure", false, "Use insecure connection")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	// Check if a filename and server addr was provided as an argument
	if len(args) < 2 {
		usage()
	}

	apiKey := os.Getenv("WORKSHOP_API_KEY")
	if apiKey == "" {
		println("Please set WORKSHOP_API_KEY environment variable with your API key.")
		os.Exit(1)
	}

	filename := args[0]
	server := args[1]

	var (
		rules      []*apipb.Rule
		ruleSrcErr error
	)

	// Check the file extension and parse CSVs from rudolph or TOML files from
	// moroz.
	if strings.HasSuffix(filename, ".csv") {
		rules, ruleSrcErr = rudolph.ParseRulesFromFile(filename)
	} else if strings.HasSuffix(filename, ".toml") {
		// Read the file content
		rules, ruleSrcErr = morozconfig.ParseRulesFromFile(filename)
	} else {
		println("Unsupported file format. Please provide a .toml or .csv file.")
		os.Exit(1)
	}

	if ruleSrcErr != nil {
		log.Fatalf("Failed to read config file: %s %v", filename, ruleSrcErr)
	}

	opts := []grpc.DialOption{
		grpc.WithPerRPCCredentials(apiKeyAuthorizer(apiKey)),
	}

	if *useInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	conn, err := grpc.NewClient(fmt.Sprintf("dns:%s", server), opts...)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}

	// Create a gRPC client
	client := svcpb.NewWorkshopServiceClient(conn)
	req := &apipb.CreateRuleRequest{}

	successes := len(rules)

	// Iterate over the rules and add them to the Workshop instance
	for i, rule := range rules {
		req.Rule = rule
		_, err := client.CreateRule(context.Background(), req)

		if err != nil {
			log.Printf("Failed to add rule %d: %s %v\n", i, rule.GetIdentifier(), err)
			successes--
			continue
		}
	}

	fmt.Printf("%d/%d rules added successfully!\n", successes, len(rules))
}

// apiKeyAuthorizer is a custom authorizer that adds the API key to the request
// metadata.
type apiKeyAuthorizer string

func (k apiKeyAuthorizer) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"Authorization": string(k)}, nil
}
func (k apiKeyAuthorizer) RequireTransportSecurity() bool {
	return false
}

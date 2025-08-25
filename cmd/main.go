// Utility to add rules from Moroz, Rudolph, or Zentral to a Workshop instance.
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
	"github.com/northpolesec/santa-rule-importer/internal/santactl"
	"github.com/northpolesec/santa-rule-importer/internal/zentral"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <path to config.toml|path to config.csv> <server>\n", os.Args[0])
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "santa-rule-importer - tool to import rules from Moroz, Rudolph, and Zentral to Workshop\n")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "This tool expects the Workshop API Key to be in the WORKSHOP_API_KEY env var\n")
	fmt.Fprintf(os.Stderr, "For Zentral imports, set ZENTRAL_API_TOKEN env var with your Zentral API token\n")
	fmt.Fprintln(os.Stderr)
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Example Usage:")
	fmt.Fprintf(os.Stderr, "\t%s global.toml nps.workshop.cloud\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\t%s --zentral-url zentral.example.com nps.workshop.cloud\n", os.Args[0])
	os.Exit(1)
}

func main() {
	useInsecure := flag.Bool("insecure", false, "Use insecure connection")
	useCustomMsgAsComment := flag.Bool("use-custom-msg-as-comment", false, "Use custom message as comment (moroz only)")
	zentBaseURL := flag.String("zentral-url", "", "Zentral base URL (e.g., zentral.example.com)")
	zentTargetType := flag.String("zentral-target-type", "", "Filter Zentral rules by target type (BINARY, CERTIFICATE, etc.)")
	zentTargetIdentifier := flag.String("zentral-target-identifier", "", "Filter Zentral rules by target identifier")
	zentConfigID := flag.Int("zentral-config-id", 0, "Filter Zentral rules by configuration ID")

	flag.Usage = usage
	flag.Parse()

	args := flag.Args()

	apiKey := os.Getenv("WORKSHOP_API_KEY")
	if apiKey == "" {
		println("Please set WORKSHOP_API_KEY environment variable with your API key.")
		os.Exit(1)
	}

	var (
		rules      []*apipb.Rule
		ruleSrcErr error
		server     string
	)

	// Check if using Zentral API or file input
	if *zentBaseURL != "" {
		// Handle Zentral API import
		if len(args) < 1 {
			println("Server address required for Zentral imports.")
			usage()
		}
		server = args[0]

		zentToken := os.Getenv("ZENTRAL_API_TOKEN")
		if zentToken == "" {
			println("Please set ZENTRAL_API_TOKEN environment variable for Zentral imports.")
			os.Exit(1)
		}

		baseURL := *zentBaseURL
		if !strings.HasPrefix(baseURL, "http") {
			baseURL = "https://" + baseURL
		}

		rules, ruleSrcErr = zentral.GetRulesFromZentral(baseURL, zentToken, *zentTargetType, *zentTargetIdentifier, *zentConfigID)
	} else {
		// Handle file input
		if len(args) < 2 {
			usage()
		}
		filename := args[0]
		server = args[1]

		// Check the file extension and parse CSVs from rudolph or TOML files from moroz.
		if strings.HasSuffix(filename, ".csv") {
			rules, ruleSrcErr = rudolph.ParseRulesFromFile(filename)
		} else if strings.HasSuffix(filename, ".toml") {
			rules, ruleSrcErr = morozconfig.ParseRulesFromFile(filename, *useCustomMsgAsComment)
		} else if strings.HasSuffix(filename, ".json") {
			rules, ruleSrcErr = santactl.ParseRulesFromFile(filename)
		} else {
			println("Unsupported file format. Please provide a .toml, .csv, or .json file.")
			os.Exit(1)
		}
	}

	if ruleSrcErr != nil {
		if *zentBaseURL != "" {
			log.Fatalf("Failed to retrieve rules from Zentral: %v", ruleSrcErr)
		} else {
			log.Fatalf("Failed to read config file: %v", ruleSrcErr)
		}
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

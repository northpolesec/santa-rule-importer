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

	"github.com/northpolesec/santa-rule-importer/internal/auth"
	"github.com/northpolesec/santa-rule-importer/internal/morozconfig"
	"github.com/northpolesec/santa-rule-importer/internal/rudolph"
	"github.com/northpolesec/santa-rule-importer/internal/santactl"
	"github.com/northpolesec/santa-rule-importer/internal/staticrules"
	"github.com/northpolesec/santa-rule-importer/internal/zentral"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	svcpb "buf.build/gen/go/northpolesec/workshop-api/grpc/go/workshop/v1/workshopv1grpc"
	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <path to input file> <server>\n", os.Args[0])
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "santa-rule-importer - tool to import rules from Moroz, Rudolph, Zentral, and StaticRules to Workshop\n")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Auth: set WORKSHOP_API_KEY env var, or run '%s -login <server>' to authenticate via SSO\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "For Zentral imports, set ZENTRAL_API_KEY env var with your Zentral API token\n")
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
	loginServer := flag.String("login", "", "Login to the specified Workshop server and store the token")

	flag.Usage = usage
	flag.Parse()

	if *loginServer != "" {
		if err := auth.GetAndStoreToken(context.Background(), *loginServer, *useInsecure); err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	args := flag.Args()

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

		zentAPIKey := os.Getenv("ZENTRAL_API_KEY")
		if zentAPIKey == "" {
			println("Please set ZENTRAL_API_KEY environment variable for Zentral imports.")
			os.Exit(1)
		}

		baseURL := *zentBaseURL
		if !strings.HasPrefix(baseURL, "http") {
			baseURL = "https://" + baseURL
		}

		rules, ruleSrcErr = zentral.GetRulesFromZentral(baseURL, zentAPIKey, *zentTargetType, *zentTargetIdentifier, *zentConfigID)
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
		} else if strings.HasSuffix(filename, ".mobileconfig") {
			rules, ruleSrcErr = staticrules.ParseRulesFromFile(filename)
		} else {
			println("Unsupported file format. Please provide a .toml, .csv, .json, or .mobileconfig file.")
			os.Exit(1)
		}
	}

	if ruleSrcErr != nil {
		if *zentBaseURL != "" {
			log.Fatalf("Failed to retrieve rules from Zentral: %v", ruleSrcErr)
		} else {
			log.Fatalf("Failed to read input file: %v", ruleSrcErr)
		}
	}

	rpcCreds, err := auth.APIKeyOrToken(context.Background(), server, *useInsecure)
	if err != nil {
		log.Fatal(err.Error())
	}

	opts := []grpc.DialOption{
		grpc.WithPerRPCCredentials(rpcCreds),
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
		// TODO: Support setting the tag
		rule.SetTag("global")
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

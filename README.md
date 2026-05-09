# rtawscan

[![Go Reference](https://pkg.go.dev/badge/github.com/cipherops-io/rtawscan.svg)](https://pkg.go.dev/github.com/cipherops-io/rtawscan)
[![Go Report Card](https://goreportcard.com/badge/github.com/cipherops-io/rtawscan)](https://goreportcard.com/report/github.com/cipherops-io/rtawscan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Go package for scanning AWS Trusted Advisor checks and generating structured findings.

## Overview

rtawscan connects to AWS Trusted Advisor, retrieves check results, and formats them into findings that can be used for security assessments, cost optimization reviews, and observability monitoring. The package handles AWS API authentication, processes flagged resources, categorizes findings by segment, and generates deep links to AWS console resources.

## Features

- **Automatic AWS Authentication**: Uses standard AWS credential providers chain
- **Comprehensive Trusted Advisor Integration**: Fetches all available checks and their results
- **Intelligent Categorization**: Automatically categorizes findings into Security, FinOps (cost optimization), and Observability segments
- **Deep Link Generation**: Creates direct links to AWS console resources for quick investigation
- **Error Resilience**: Gracefully handles AWS API errors including subscription requirements
- **Concurrent Processing**: Uses worker pools for efficient parallel check processing
- **Structured Output**: Outputs findings as JSON for easy integration with other tools

## Installation

```bash
go get github.com/cipherops-io/rtawscan
```

## Usage

### Basic Usage

```go
package main

import (
	"fmt"
	"log"
	
	"github.com/cipherops-io/rtawscan"
)

func main() {
	// Fetch findings from AWS Trusted Advisor
	trustedAdvAvailable, err := rtawscan.FetchTrustedAdvisorFindings()
	if err != nil {
		log.Fatalf("Failed to fetch AWS Trusted Advisor data: %v", err)
	}
	
	if trustedAdvAvailable {
		fmt.Println("Successfully retrieved Trusted Advisor findings")
	} else {
		fmt.Println("Trusted Advisor is not available (subscription required)")
	}
}
```

### Advanced Usage with Custom Configuration

For more control over AWS configuration, you can use the underlying functions directly:

```go
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/support"
	"github.com/cipherops-io/rtawscan"
	"github.com/cipherops-io/rsvcmodel"
)

func main() {
	// Create custom AWS config
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-west-2"),
		// Add other config options as needed
	)
	if err != nil {
		log.Fatalf("Unable to load AWS config: %v", err)
	}

	// Create AWS Support client
	client := support.NewFromConfig(cfg)

	// Fetch findings using custom client
	findings, err := FetchWithClient(ctx, client)
	if err != nil {
		log.Fatalf("Failed to fetch findings: %v", err)
	}

	// Output findings as JSON
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(findings); err != nil {
		log.Fatalf("Failed to encode findings: %v", err)
	}
}

// FetchWithClient fetches findings using a pre-configured AWS client
func FetchWithClient(ctx context.Context, client *support.Support) ([]*rsvcmodel.Finding, error) {
	// Implementation would follow similar pattern to FetchTrustedAdvisorFindings but use provided client
	// This is a simplified example - see source code for full implementation
	return nil, nil
}
```

## Output Format

The package outputs findings in JSON format containing:

- **Segment**: Security, FinOps, or Observability
- **Check Title**: Name of the Trusted Advisor check
- **Category**: AWS category for the check
- **Items**: Array of affected resource identifiers (pretty names)
- **Severity**: Critical, High, Medium, Low, or Info
- **Provider**: Always "aws"
- **ResourceIDs**: Original AWS resource IDs
- **Metadata**: Additional information including console deep links

Example JSON output:
```json
[
  {
    "segment": "security",
    "title": "Amazon S3 Bucket Permissions",
    "category": "security",
    "items": ["my-public-bucket"],
    "severity": "critical",
    "provider": "aws",
    "resourceIDs": ["arn:aws:s3:::my-public-bucket"],
    "metadata": {
      "links": ["https://s3.console.aws.amazon.com/s3/buckets/my-public-bucket?region=us-east-1"]
    }
  }
]
```

## Godocs Documentation

For detailed API documentation, visit: [https://pkg.go.dev/github.com/cipherops-io/rtawscan](https://pkg.go.dev/github.com/cipherops-io/rtawscan)

## Requirements

- Go 1.16 or higher
- AWS account with appropriate permissions to access Trusted Advisor
- AWS credentials configured via standard methods (environment variables, shared config, etc.)

## Dependencies

- [AWS SDK for Go v2](https://github.com/aws/aws-sdk-go-v2)
- [rsvcmodel](https://github.com/cipherops-io/rsvcmodel) (for finding data structures)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- AWS Trusted Advisor service for providing the assessment data
- The rsvcmodel project for providing the finding data structures

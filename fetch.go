package rtawscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/support"
	"github.com/aws/aws-sdk-go-v2/service/support/types"
	"github.com/aws/smithy-go"

	"github.com/cipherops-io/rsvcmodel"
)

func isSubscriptionError(err error) bool {
	if err == nil {
		return false
	}
	// Unwrap the error to check if it's an AWS API error
	if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
		// Check the specific error code
		if apiErr.ErrorCode() == "SubscriptionRequiredException" {
			return true
		}
	}
	return false
}
func FetchAWS() (bool, error) {
	trustedAdv := false
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return trustedAdv, err
	}
	client := support.NewFromConfig(cfg)

	checksResp, err := client.DescribeTrustedAdvisorChecks(ctx, &support.DescribeTrustedAdvisorChecksInput{
		Language: aws.String("en"),
	})
	if err != nil {
		if isSubscriptionError(err) {
			return trustedAdv, nil
		}
		return trustedAdv, err
	}
	trustedAdv = true
	resultsChan := make(chan *rsvcmodel.Finding, len(checksResp.Checks))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, check := range checksResp.Checks {
		wg.Add(1)
		go func(c types.TrustedAdvisorCheckDescription) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			res, err := client.DescribeTrustedAdvisorCheckResult(ctx, &support.DescribeTrustedAdvisorCheckResultInput{
				CheckId: c.Id,
			})
			if err != nil || res.Result == nil || *res.Result.Status == "ok" || *res.Result.Status == "not_available" {
				return
			}

			severity := rsvcmodel.SeverityMedium
			if *res.Result.Status == "error" {
				severity = rsvcmodel.SeverityCritical
			}

			checkTitle := aws.ToString(c.Name)
			category := aws.ToString(c.Category)
			segment := mapCategoryToSegment(category)

			var items []string
			var resourceIDs []string
			var links []string

			for _, r := range res.Result.FlaggedResources {
				rawMeta := make(map[string]any)
				rawID := aws.ToString(r.ResourceId)
				isAccessAnalyzer := strings.Contains(checkTitle, "Access Analyzer")

				for i, hPtr := range c.Metadata {
					header := aws.ToString(hPtr)
					val := aws.ToString(r.Metadata[i])
					rawMeta[header] = val
					if isAccessAnalyzer && strings.ToLower(header) == "resource" {
						rawID = val
					}
				}

				prettyID := findPrettyName(c.Metadata, r.Metadata, rawID)
				items = append(items, prettyID)
				resourceIDs = append(resourceIDs, rawID)
				links = append(links, buildDeepLink(checkTitle, rawID, prettyID, rawMeta))
			}

			finding := rsvcmodel.NewFinding(segment, checkTitle, category, items)
			finding.Severity = severity
			finding.Provider = "aws"
			finding.Summary = aws.ToString(c.Description)
			finding.ResourceIDs = resourceIDs
			finding.Metadata = map[string]any{
				"links":   links,
				"service": extractService(checkTitle),
			}

			resultsChan <- finding
		}(check)
	}

	go func() { wg.Wait(); close(resultsChan) }()

	var allFindings []*rsvcmodel.Finding
	for f := range resultsChan {
		allFindings = append(allFindings, f)
	}

	jsonBytes, _ := json.MarshalIndent(allFindings, "", "  ")
	//fmt.Printf("SUCCESS: Report saved to %s\n", outputFile)
	fmt.Println(string(jsonBytes))
	//return os.WriteFile(outputFile, jsonBytes, 0644)
	return trustedAdv, nil
}

func mapCategoryToSegment(category string) rsvcmodel.Segment {
	switch strings.ToLower(category) {
	case "cost_optimizing":
		return rsvcmodel.SegmentFinOps
	case "security":
		return rsvcmodel.SegmentSecurity
	default:
		return rsvcmodel.SegmentObservability
	}
}

const defaultRegion = "us-east-1"
const trustedAdvisorURL = "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/dashboard"

func buildDeepLink(checkName, resourceID, prettyID string, metadata map[string]any) string {
	region := resolveRegion(metadata)
	id := resourceID

	if link := buildARNLink(id, region); link != "" {
		return link
	}

	name := strings.ToLower(checkName)
	switch {
	case strings.Contains(name, "s3"):
		return buildS3Link(prettyID, id, region)
	case strings.Contains(name, "ec2") || strings.Contains(name, "ebs"):
		return buildEC2Link(id, region)
	case strings.Contains(name, "rds"):
		return fmt.Sprintf("https://%s.console.aws.amazon.com/rds/home?region=%s#database:id=%s", region, region, id)
	case strings.Contains(name, "iam"):
		return buildIAMLink(prettyID, id, metadata)
	case strings.Contains(name, "lambda"):
		return buildLambdaLink(prettyID, id, region)
	}
	return trustedAdvisorURL
}

func resolveRegion(metadata map[string]any) string {
	for _, k := range []string{"Region", "Resource Region", "Location", "Region Name"} {
		if val, ok := metadata[k].(string); ok && val != "" {
			return val
		}
	}
	return defaultRegion
}

func buildARNLink(id, region string) string {
	if !strings.HasPrefix(id, "arn:aws:") {
		return ""
	}
	parts := strings.Split(id, ":")
	if len(parts) <= 5 {
		return ""
	}
	switch parts[2] {
	case "s3":
		bucket := strings.Split(parts[5], "/")[0]
		return fmt.Sprintf("https://s3.console.aws.amazon.com/s3/buckets/%s", bucket)
	case "iam":
		return "https://console.aws.amazon.com/iam/home#/roles"
	case "kms":
		keyID := strings.TrimPrefix(parts[5], "key/")
		return fmt.Sprintf("https://%s.console.aws.amazon.com/kms/home?region=%s#/kms/keys/%s", region, region, keyID)
	case "lambda":
		if len(parts) > 6 {
			return fmt.Sprintf("https://%s.console.aws.amazon.com/lambda/home?region=%s#/functions/%s", region, region, parts[6])
		}
	}
	return ""
}

func buildS3Link(prettyID, id, region string) string {
	bucket := prettyID
	if bucket == "" {
		bucket = id
	}
	return fmt.Sprintf("https://s3.console.aws.amazon.com/s3/buckets/%s?region=%s", bucket, region)
}

func buildEC2Link(id, region string) string {
	if strings.HasPrefix(id, "i-") {
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#InstanceDetails:instanceId=%s", region, region, id)
	}
	if strings.HasPrefix(id, "vol-") {
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#VolumeDetails:volumeId=%s", region, region, id)
	}
	return trustedAdvisorURL
}

func buildIAMLink(prettyID, id string, metadata map[string]any) string {
	user := resolveUser(prettyID, id, metadata)
	if user != "" && user != id && user != "N/A" {
		return fmt.Sprintf("https://console.aws.amazon.com/iam/home?#/users/%s", user)
	}
	return "https://console.aws.amazon.com/iam/home?#/users"
}

func resolveUser(prettyID, id string, metadata map[string]any) string {
	if prettyID != "" && prettyID != id && prettyID != "N/A" {
		return prettyID
	}
	for _, key := range []string{"User Name", "IAM User"} {
		if u, ok := metadata[key].(string); ok && u != "" {
			return u
		}
	}
	return prettyID
}

func buildLambdaLink(prettyID, id, region string) string {
	function := prettyID
	if function == "" || function == "N/A" {
		function = id
	}
	if strings.HasPrefix(function, "arn:aws:lambda:") {
		parts := strings.Split(function, ":")
		if len(parts) > 6 {
			function = parts[6]
		}
	}
	return fmt.Sprintf("https://%s.console.aws.amazon.com/lambda/home?region=%s#/functions/%s", region, region, function)
}

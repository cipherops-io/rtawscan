package rtawscan

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/support"
	"github.com/aws/aws-sdk-go-v2/service/support/types"
	"github.com/aws/smithy-go"

	"github.com/cipherops-io/rsvcmodel"
)

// ScanResult wraps Trusted Advisor findings together with the AWS account
// context in which they were collected.
type ScanResult struct {
	AccountID    string               `json:"accountId"`
	AccountAlias string               `json:"accountAlias"`
	Findings     []*rsvcmodel.Finding `json:"findings"`
}

// isSubscriptionError checks if the given AWS error indicates that the account
// does not have the required AWS Support subscription plan (Business/Enterprise)
// to access the Trusted Advisor API.
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

// FetchTrustedAdvisorFindings queries the AWS Trusted Advisor API for security,
// cost, and observability findings. It returns a boolean indicating if Trusted
// Advisor is enabled (i.e. has the required support subscription), a ScanResult
// containing account context and findings, and any non-subscription errors.
func FetchTrustedAdvisorFindings() (bool, *ScanResult, error) {
	trustedAdv := false
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return trustedAdv, nil, err
	}

	// Resolve account ID and alias upfront so every finding carries full context.
	accountID := resolveAccountID(ctx, cfg)
	accountAlias := resolveAccountAlias(ctx, cfg)

	client := support.NewFromConfig(cfg)

	checksResp, err := client.DescribeTrustedAdvisorChecks(ctx, &support.DescribeTrustedAdvisorChecksInput{
		Language: aws.String("en"),
	})
	if err != nil {
		if isSubscriptionError(err) {
			return trustedAdv, nil, err
		}
		return trustedAdv, nil, err
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
			var links []string

			for _, r := range res.Result.FlaggedResources {
				rawMeta := make(map[string]any)
				rawID := resolveResourceID(c.Metadata, r.Metadata, aws.ToString(r.ResourceId))

				for i, hPtr := range c.Metadata {
					header := aws.ToString(hPtr)
					val := aws.ToString(r.Metadata[i])
					rawMeta[header] = val
				}

				// Stamp the category so buildDeepLink can branch on it.
				rawMeta["_category"] = category

				// Service-limit checks have no per-resource AWS ID — the meaningful
				// identifier is the region (one quota entry per region).
				if category == "service_limits" {
					rawID = resolveRegion(rawMeta)
				}

				// AZ balance checks store the meaningful identifier in an AZ column.
				// findPrettyName skips all "zone" headers, so we override rawID here so
				// it becomes the fallback that findPrettyName returns as prettyID.
				if strings.Contains(strings.ToLower(checkTitle), "availability zone balance") {
					if az := resolveAZ(rawMeta); az != "" {
						rawID = az
					}
				}

				prettyID := findPrettyName(c.Metadata, r.Metadata, rawID)
				items = append(items, prettyID)
				links = append(links, buildDeepLink(checkTitle, rawID, prettyID, rawMeta))
			}

			finding := rsvcmodel.NewFinding(segment, checkTitle, category, items)
			finding.Severity = severity
			finding.Provider = "aws"
			finding.Summary = aws.ToString(c.Description)
			finding.Metadata = map[string]any{
				"links":   links,
				"service": extractService(checkTitle),
			}

			resultsChan <- finding
		}(check)
	}

	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var allFindings []*rsvcmodel.Finding
	for f := range resultsChan {
		allFindings = append(allFindings, f)
	}

	return trustedAdv, &ScanResult{
		AccountID:    accountID,
		AccountAlias: accountAlias,
		Findings:     allFindings,
	}, err
}

// resolveAccountID returns the AWS account ID for the current credentials,
// or an empty string if the STS call fails.
func resolveAccountID(ctx context.Context, cfg aws.Config) string {
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Printf("[rtawscan] could not resolve account ID via STS: %v", err)
		return ""
	}
	return aws.ToString(out.Account)
}

// resolveAccountAlias returns the first IAM account alias, or an empty string
// if the account has no alias set or the IAM call fails (e.g. missing
// iam:ListAccountAliases permission).
func resolveAccountAlias(ctx context.Context, cfg aws.Config) string {
	out, err := iam.NewFromConfig(cfg).ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil {
		log.Printf("[rtawscan] could not resolve account alias via IAM (iam:ListAccountAliases may not be granted): %v", err)
		return ""
	}
	if len(out.AccountAliases) == 0 {
		return ""
	}
	return out.AccountAliases[0]
}

// knownIDHeaders is an ordered list of lowercase metadata column headers that
// hold the real AWS resource identifier. The first matching, non-empty value
// wins over the Trusted Advisor-internal hashed resourceId.
var knownIDHeaders = []string{
	"volume id",
	"instance id",
	"snapshot id",
	"nat gateway id",
	"ip address",       // Unassociated Elastic IP Addresses
	"principal arn",    // STS / IAM principal checks
	"principal",
	"hosted zone name", // Route 53 checks
	"distribution id",
	"load balancer arn",
	"load balancer name",
	"target group arn",
	"db instance id",
	"function name",
	"cluster id",
	"key id",
	"security group id",
	"resource", // used by Access Analyzer
}

// resolveResourceID returns the true AWS resource identifier by scanning
// Trusted Advisor check metadata for well-known ID-bearing column headers.
// It falls back to fallback (typically the hashed r.ResourceId) when no
// recognisable value is found.
func resolveResourceID(headers []*string, metadata []*string, fallback string) string {
	for i, hPtr := range headers {
		h := strings.ToLower(aws.ToString(hPtr))
		for _, known := range knownIDHeaders {
			if h == known {
				if i < len(metadata) {
					val := strings.TrimSpace(aws.ToString(metadata[i]))
					if val != "" && val != "-" && val != "N/A" {
						return val
					}
				}
			}
		}
	}
	return fallback
}

// mapCategoryToSegment maps Trusted Advisor categories to rsvcmodel segments.
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

// buildDeepLink attempts to generate a direct AWS Console link for the affected
// resource based on its service, ID, and metadata. It falls back to the Trusted
// Advisor dashboard if a specific deep link cannot be determined.
func buildDeepLink(checkName, resourceID, prettyID string, metadata map[string]any) string {
	region := resolveRegion(metadata)
	id := resourceID

	// Service-limit checks: rawID is the region; link to Service Quotas for that region.
	if cat, _ := metadata["_category"].(string); cat == "service_limits" {
		return fmt.Sprintf("https://%s.console.aws.amazon.com/servicequotas/home", region)
	}

	if link := buildARNLink(id, region); link != "" {
		return link
	}

	name := strings.ToLower(checkName)
	switch {
	case strings.Contains(name, "s3"):
		return buildS3Link(prettyID, id, region)
	case strings.Contains(name, "elastic ip"):
		return buildEIPLink(id, region)
	case strings.Contains(name, "availability zone balance"):
		az := id // rawID is the AZ name after the loop override above
		if az == "" || !strings.Contains(az, "-") {
			az = region
		}
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#Instances:availabilityZone=%s", region, region, az)
	case strings.Contains(name, "ec2") || strings.Contains(name, "ebs"):
		return buildEC2Link(id, region)
	case strings.Contains(name, "rds"):
		return fmt.Sprintf("https://%s.console.aws.amazon.com/rds/home?region=%s#database:id=%s", region, region, id)
	case strings.Contains(name, "access analyzer"):
		// Each item is a region where the analyzer is missing; link directly to
		// the Access Analyzer console for that region.
		analyzerRegion := id // rawID is the region for this check type
		if analyzerRegion == "" || !strings.Contains(analyzerRegion, "-") {
			analyzerRegion = region
		}
		return fmt.Sprintf("https://%s.console.aws.amazon.com/access-analyzer/home?region=%s#/analyzer", analyzerRegion, analyzerRegion)
	case strings.Contains(name, "iam") || strings.Contains(name, "sts"):
		return buildIAMLink(prettyID, id, metadata)
	case strings.Contains(name, "lambda"):
		return buildLambdaLink(prettyID, id, region)
	case strings.Contains(name, "route 53") || strings.Contains(name, "route53"):
		return buildRoute53Link(prettyID)
	case strings.Contains(name, "security group") || strings.HasPrefix(id, "sg-"):
		label := prettyID
		if label == "" || label == id {
			label = id
		}
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#SecurityGroups:search=%s", region, region, label)
	case strings.Contains(name, "vpc endpoint") || strings.HasPrefix(id, "vpce-"):
		return fmt.Sprintf("https://%s.console.aws.amazon.com/vpc/home?region=%s#Endpoints:vpcEndpointId=%s", region, region, id)
	case strings.Contains(name, "nat"):
		return buildNATGatewayLink(id, region)
	case strings.Contains(name, "target group"):
		label := prettyID
		if label == "" || label == id {
			label = id
		}
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#TargetGroups:search=%s", region, region, label)
	case strings.Contains(name, "load balancer") || strings.Contains(name, "elb"):
		label := prettyID
		if label == "" || label == id {
			label = id
		}
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#LoadBalancers:search=%s", region, region, label)
	}
	return trustedAdvisorURL
}

// buildRoute53Link generates a console link to the Route 53 hosted zones page.
// If a domain name is available (e.g. "darknoc.gocommotion.com."), the trailing
// dot is stripped and the domain is used to pre-filter the hosted zones list.
func buildRoute53Link(domain string) string {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return "https://console.aws.amazon.com/route53/v2/hostedzones"
	}
	return fmt.Sprintf("https://console.aws.amazon.com/route53/v2/hostedzones#?searchFilter=%s", domain)
}

// buildNATGatewayLink generates a console link to the VPC NAT Gateways page
// filtered to the specific gateway ID.
func buildNATGatewayLink(id, region string) string {
	if id == "" {
		return trustedAdvisorURL
	}
	return fmt.Sprintf("https://%s.console.aws.amazon.com/vpc/home?region=%s#NatGateways:natGatewayId=%s", region, region, id)
}

// buildEIPLink generates a direct console link to the Elastic IP address page.
// If ip is a real IPv4 address it filters to that specific IP; otherwise it
// links to the EIPs list for the region (e.g. for service-limit checks where
// only a hash is available).
func buildEIPLink(ip, region string) string {
	if ip == "" {
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#Addresses:", region, region)
	}
	if isIPv4(ip) {
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#Addresses:PublicIp=%s", region, region, ip)
	}
	return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#Addresses:", region, region)
}

// isIPv4 returns true when s looks like a dotted-decimal IPv4 address.
func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// azPattern matches a single AWS availability zone (e.g. us-east-1a, ap-southeast-2b).
var azPattern = regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d+[a-z]$`)

// resolveAZ extracts an availability zone from Trusted Advisor metadata by trying
// known column headers first, then scanning all values for an AZ-shaped string.
func resolveAZ(metadata map[string]any) string {
	for _, k := range []string{"Availability Zone", "availability zone", "AZ", "Zone"} {
		if val, ok := metadata[k].(string); ok && azPattern.MatchString(strings.TrimSpace(val)) {
			return strings.TrimSpace(val)
		}
	}
	// Scan all values — Trusted Advisor column names vary across check versions.
	for _, v := range metadata {
		if s, ok := v.(string); ok && azPattern.MatchString(strings.TrimSpace(s)) {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// resolveRegion extracts the AWS region from Trusted Advisor metadata,
// falling back to "us-east-1" if not found.
func resolveRegion(metadata map[string]any) string {
	for _, k := range []string{"Region", "Resource Region", "Location", "Region Name"} {
		if val, ok := metadata[k].(string); ok && val != "" {
			return val
		}
	}
	return defaultRegion
}

// buildARNLink attempts to construct a deep link purely by parsing the
// structure of an AWS ARN.
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
	case "elasticloadbalancing":
		return buildELBARNLink(parts[5], region)
	}
	return ""
}

// buildELBARNLink produces a console deep-link from the resource portion of an
// elasticloadbalancing ARN (parts[5]).
// Load balancer ARN resource: "loadbalancer/app/<name>/<id>"  → EC2 Load Balancers page filtered by name.
// Target group ARN resource:  "targetgroup/<name>/<id>"       → EC2 Target Groups page filtered by name.
func buildELBARNLink(resource, region string) string {
	segments := strings.Split(resource, "/")
	switch {
	case strings.HasPrefix(resource, "loadbalancer/") && len(segments) >= 3:
		name := segments[2] // loadbalancer/<type>/<name>/<id>
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#LoadBalancers:search=%s", region, region, name)
	case strings.HasPrefix(resource, "targetgroup/") && len(segments) >= 2:
		name := segments[1] // targetgroup/<name>/<id>
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#TargetGroups:search=%s", region, region, name)
	}
	return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#LoadBalancers:", region, region)
}

// buildS3Link generates a console link for an S3 bucket.
func buildS3Link(prettyID, id, region string) string {
	bucket := prettyID
	if bucket == "" {
		bucket = id
	}
	return fmt.Sprintf("https://s3.console.aws.amazon.com/s3/buckets/%s?region=%s", bucket, region)
}

// buildEC2Link generates a console link for EC2 instances or EBS volumes.
func buildEC2Link(id, region string) string {
	if strings.HasPrefix(id, "i-") {
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#InstanceDetails:instanceId=%s", region, region, id)
	}
	if strings.HasPrefix(id, "vol-") {
		return fmt.Sprintf("https://%s.console.aws.amazon.com/ec2/v2/home?region=%s#VolumeDetails:volumeId=%s", region, region, id)
	}
	return trustedAdvisorURL
}

// buildIAMLink generates a console link for an IAM user or the IAM dashboard.
func buildIAMLink(prettyID, id string, metadata map[string]any) string {
	user := resolveUser(prettyID, id, metadata)
	if user != "" && user != id && user != "N/A" {
		return fmt.Sprintf("https://console.aws.amazon.com/iam/home?#/users/%s", user)
	}
	return "https://console.aws.amazon.com/iam/home?#/users"
}

// resolveUser attempts to extract a valid IAM username from the finding's
// pretty ID, raw ID, or metadata map.
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

// buildLambdaLink generates a console link for a Lambda function.
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

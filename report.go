package rtawscan

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/cipherops-io/rsvcmodel"
)

func GenerateHTML() error {
	jsonFile := os.Getenv("TS_SCAN_JSON")
	if jsonFile == "" {
		return fmt.Errorf("TS_SCAN_JSON environment variable is not set")
	}
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("file %s not found. Run fetch mode first", jsonFile)
	}
	var findings []*rsvcmodel.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return err
	}
	fmt.Print(generateHTMLTable(findings))
	return nil
}

func generateHTMLTable(findings []*rsvcmodel.Finding) string {
	var sb strings.Builder
	sb.WriteString("<html><head><style>")
	sb.WriteString("table { border-collapse: collapse; width: 100%; font-family: sans-serif; font-size: 11px; }")
	sb.WriteString("th, td { border: 1px solid #ddd; padding: 4px; text-align: left; }")
	sb.WriteString("th { background-color: #f2f2f2; }")
	sb.WriteString(".svc-row { background-color: #e9ecef; font-weight: bold; }")
	sb.WriteString(".crit { color: red; font-weight: bold; }")
	sb.WriteString("a { color: #0066cc; text-decoration: none; }")
	sb.WriteString("</style></head><body>")
	sb.WriteString("<table><tr><th>Segment</th><th>Category</th><th>AWS Service</th><th>Finding</th><th>Description</th><th>Severity</th><th>Resource Name</th></tr>")

	for _, f := range findings {
		sevClass := ""
		if f.Severity == rsvcmodel.SeverityCritical {
			sevClass = " class='crit'"
		}

		service, _ := f.Metadata["service"].(string)
		if service == "" {
			service = extractService(f.Title)
		}
		links, ok := f.Metadata["links"].([]any)

		for i, item := range f.Items {
			link := "#"
			if ok && i < len(links) {
				if strLink, isStr := links[i].(string); isStr {
					link = strLink
				}
			}

			sb.WriteString("<tr>")
			sb.WriteString(fmt.Sprintf("<td>%s</td>", f.Segment))
			sb.WriteString(fmt.Sprintf("<td>%s</td>", f.Category))
			sb.WriteString(fmt.Sprintf("<td>%s</td>", service))
			sb.WriteString(fmt.Sprintf("<td>%s</td>", f.Title))
			sb.WriteString(fmt.Sprintf("<td>%s</td>", f.Summary))
			sb.WriteString(fmt.Sprintf("<td%s>%s</td>", sevClass, f.Severity))
			sb.WriteString(fmt.Sprintf("<td><a href='%s' target='_blank'>%s</a></td>", link, item))
			sb.WriteString("</tr>")
		}
	}
	sb.WriteString("</table></body></html>")
	return sb.String()
}

// regionPattern matches AWS region strings like us-east-1, ap-south-1, eu-west-2, etc.
var regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+-\d+)$`)

func findPrettyName(headers []*string, metadata []*string, fallback string) string {
	for i, hPtr := range headers {
		h := strings.ToLower(aws.ToString(hPtr))
		// Skip headers that are clearly region/location fields
		if strings.Contains(h, "region") || strings.Contains(h, "location") || strings.Contains(h, "zone") || strings.Contains(h, "status") {
			continue
		}
		if i < len(metadata) && (strings.Contains(h, "name") || strings.Contains(h, "user") || strings.Contains(h, "domain") || h == "resource" || strings.Contains(h, "function") || strings.Contains(h, "bucket")) {
			val := strings.TrimSpace(aws.ToString(metadata[i]))
			if val != "" && val != "-" && val != "N/A" && !regionPattern.MatchString(val) {
				return val
			}
		}
	}
	return fallback
}

var serviceKeywords = []struct {
	keyword string
	service string
}{
	{"s3", "S3"},
	{"lambda", "Lambda"},
	{"iam", "IAM"},
	{"sts", "STS"},
	{"cloudfront", "CloudFront"},
	{"cloudtrail", "CloudTrail"},
	{"cloudwatch", "CloudWatch"},
	{"ec2", "EC2"},
	{"ebs", "EBS"},
	{"rds", "RDS"},
	{"elb", "ELB"},
	{"route 53", "Route 53"},
	{"sns", "SNS"},
	{"sqs", "SQS"},
	{"dynamodb", "DynamoDB"},
	{"redshift", "Redshift"},
	{"elasticache", "ElastiCache"},
	{"auto scaling", "Auto Scaling"},
	{"vpc", "VPC"},
	{"eks", "EKS"},
	{"ecs", "ECS"},
	{"kms", "KMS"},
	{"guardduty", "GuardDuty"},
	{"waf", "WAF"},
}

func extractService(title string) string {
	lower := strings.ToLower(title)
	for _, entry := range serviceKeywords {
		if strings.Contains(lower, entry.keyword) {
			return entry.service
		}
	}
	return "AWS"
}

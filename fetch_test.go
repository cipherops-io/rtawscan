package rtawscan

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestResolveResourceID(t *testing.T) {
	tests := []struct {
		name     string
		headers  []*string
		metadata []*string
		fallback string
		expected string
	}{
		{
			name:     "EBS Volume ID extracted",
			headers:  []*string{aws.String("Status"), aws.String("Region"), aws.String("Volume ID"), aws.String("Volume Name")},
			metadata: []*string{aws.String("warning"), aws.String("us-east-1"), aws.String("vol-0abc123def456"), aws.String("my-volume")},
			fallback: "tGgFXj8sRanBcMfKsCWpXxv8mWPcyOE4lJvG1NHkbkk",
			expected: "vol-0abc123def456",
		},
		{
			name:     "EBS Volume ID no name tag",
			headers:  []*string{aws.String("Status"), aws.String("Region"), aws.String("Volume ID"), aws.String("Volume Name")},
			metadata: []*string{aws.String("warning"), aws.String("us-east-1"), aws.String("vol-0abc123def456"), aws.String("-")},
			fallback: "tGgFXj8sRanBcMfKsCWpXxv8mWPcyOE4lJvG1NHkbkk",
			expected: "vol-0abc123def456",
		},
		{
			name:     "EC2 Instance ID extracted",
			headers:  []*string{aws.String("Status"), aws.String("Region"), aws.String("Instance ID"), aws.String("Instance Name")},
			metadata: []*string{aws.String("warning"), aws.String("us-west-2"), aws.String("i-0123456789abcdef0"), aws.String("web-server")},
			fallback: "hashedvalue",
			expected: "i-0123456789abcdef0",
		},
		{
			name:     "Access Analyzer resource extracted",
			headers:  []*string{aws.String("Status"), aws.String("Region"), aws.String("Resource")},
			metadata: []*string{aws.String("warning"), aws.String("us-east-1"), aws.String("arn:aws:s3:::my-bucket")},
			fallback: "hashedvalue",
			expected: "arn:aws:s3:::my-bucket",
		},
		{
			name:     "Elastic IP address extracted",
			headers:  []*string{aws.String("Region"), aws.String("IP Address")},
			metadata: []*string{aws.String("us-east-1"), aws.String("54.210.167.204")},
			fallback: "tGgFXj8sRanBcMfKsCWpXxv8mWPcyOE4lJvG1NHkbkk",
			expected: "54.210.167.204",
		},
		{
			name:     "Target group ARN extracted",
			headers:  []*string{aws.String("Status"), aws.String("Region"), aws.String("Target Group ARN")},
			metadata: []*string{aws.String("warning"), aws.String("us-east-1"), aws.String("arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/my-tg/abc")},
			fallback: "hashedvalue",
			expected: "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/my-tg/abc",
		},
		{
			name:     "Load balancer ARN extracted",
			headers:  []*string{aws.String("Status"), aws.String("Region"), aws.String("Load Balancer ARN")},
			metadata: []*string{aws.String("warning"), aws.String("us-east-1"), aws.String("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc")},
			fallback: "hashedvalue",
			expected: "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
		},
		{
			name:     "Falls back when ID column is placeholder",
			headers:  []*string{aws.String("Status"), aws.String("Volume ID")},
			metadata: []*string{aws.String("warning"), aws.String("N/A")},
			fallback: "hashedvalue",
			expected: "hashedvalue",
		},
		{
			name:     "Falls back when no known ID header present",
			headers:  []*string{aws.String("Status"), aws.String("Region"), aws.String("Reason")},
			metadata: []*string{aws.String("warning"), aws.String("us-east-1"), aws.String("something")},
			fallback: "hashedvalue",
			expected: "hashedvalue",
		},
		{
			name:     "Falls back when metadata index out of range",
			headers:  []*string{aws.String("Volume ID")},
			metadata: []*string{},
			fallback: "hashedvalue",
			expected: "hashedvalue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveResourceID(tt.headers, tt.metadata, tt.fallback)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestBuildDeepLink(t *testing.T) {
	tests := []struct {
		name       string
		checkName  string
		resourceID string
		prettyID   string
		metadata   map[string]any
		expected   string
	}{
		{
			name:       "S3 Bucket ARN",
			checkName:  "Amazon S3 Bucket Permissions",
			resourceID: "arn:aws:s3:::my-secure-bucket",
			prettyID:   "my-secure-bucket",
			metadata:   map[string]any{"Region": "us-west-2"},
			expected:   "https://s3.console.aws.amazon.com/s3/buckets/my-secure-bucket",
		},
		{
			name:       "IAM Role ARN",
			checkName:  "IAM Access Analyzer",
			resourceID: "arn:aws:iam::123456789012:role/my-role",
			prettyID:   "my-role",
			metadata:   map[string]any{},
			expected:   "https://console.aws.amazon.com/iam/home#/roles",
		},
		{
			name:       "KMS Key ARN",
			checkName:  "AWS KMS Key Rotation",
			resourceID: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			prettyID:   "1234abcd-12ab-34cd-56ef-1234567890ab",
			metadata:   map[string]any{"Region Name": "us-east-1"},
			expected:   "https://us-east-1.console.aws.amazon.com/kms/home?region=us-east-1#/kms/keys/1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			name:       "S3 Name Fallback",
			checkName:  "S3 Bucket Versioning",
			resourceID: "my-bucket",
			prettyID:   "my-bucket",
			metadata:   map[string]any{"Region": "us-west-1"},
			expected:   "https://s3.console.aws.amazon.com/s3/buckets/my-bucket?region=us-west-1",
		},
		{
			name:       "S3 UUID",
			checkName:  "Amazon S3 Bucket Permissions",
			resourceID: "6y5n5aurtlYSKSYlCOkbrQPx8uFF7IbXX1_v6Uc7LOA",
			prettyID:   "my-actual-bucket",
			metadata:   map[string]any{"Region": "ap-south-1"},
			expected:   "https://s3.console.aws.amazon.com/s3/buckets/my-actual-bucket?region=ap-south-1",
		},
		{
			name:       "Route 53 MX SPF check links to hosted zones filtered by domain",
			checkName:  "Amazon Route 53 MX Resource Record Sets and Sender Policy Framework",
			resourceID: "darknoc.gocommotion.com.",
			prettyID:   "darknoc.gocommotion.com.",
			metadata:   map[string]any{},
			expected:   "https://console.aws.amazon.com/route53/v2/hostedzones#?searchFilter=darknoc.gocommotion.com",
		},
		{
			name:       "IAM Access Analyzer check links to Access Analyzer console per region",
			checkName:  "IAM Access Analyzer - external access",
			resourceID: "ap-northeast-1",
			prettyID:   "ap-northeast-1",
			metadata:   map[string]any{"Region": "ap-northeast-1"},
			expected:   "https://ap-northeast-1.console.aws.amazon.com/access-analyzer/home?region=ap-northeast-1#/analyzer",
		},
		{
			name:       "STS global endpoint check falls back to IAM console",
			checkName:  "AWS STS global endpoint usage across AWS Regions",
			resourceID: "24599c399dca2d033cfb83be57ecf18fac72f4fca724e71ee95afde91064e25b",
			prettyID:   "24599c399dca2d033cfb83be57ecf18fac72f4fca724e71ee95afde91064e25b",
			metadata:   map[string]any{"Region": "us-east-1"},
			expected:   "https://console.aws.amazon.com/iam/home?#/users",
		},
		{
			name:       "STS check with extracted IAM role ARN",
			checkName:  "AWS STS global endpoint usage across AWS Regions",
			resourceID: "arn:aws:iam::123456789012:role/my-role",
			prettyID:   "my-role",
			metadata:   map[string]any{"Region": "us-east-1"},
			expected:   "https://console.aws.amazon.com/iam/home#/roles",
		},
		{
			name:       "Inactive NAT Gateway",
			checkName:  "Inactive NAT Gateways",
			resourceID: "nat-00f37fd97cebcf425",
			prettyID:   "nat-00f37fd97cebcf425",
			metadata:   map[string]any{"Region": "us-east-1"},
			expected:   "https://us-east-1.console.aws.amazon.com/vpc/home?region=us-east-1#NatGateways:natGatewayId=nat-00f37fd97cebcf425",
		},
		{
			name:       "ELB target imbalance links to LoadBalancers filtered by name",
			checkName:  "ELB - Target Imbalance",
			resourceID: "hashedvalue",
			prettyID:   "core-apps-tier0-ofc-lb",
			metadata:   map[string]any{"Region": "us-east-1"},
			expected:   "https://us-east-1.console.aws.amazon.com/ec2/v2/home?region=us-east-1#LoadBalancers:search=core-apps-tier0-ofc-lb",
		},
		{
			name:       "ALB target group ARN",
			checkName:  "Application Load Balancer Target Groups encrypted protocol",
			resourceID: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-tg/abc123",
			prettyID:   "my-tg",
			metadata:   map[string]any{"Region": "us-east-1"},
			expected:   "https://us-east-1.console.aws.amazon.com/ec2/v2/home?region=us-east-1#TargetGroups:search=my-tg",
		},
		{
			name:       "ALB load balancer ARN",
			checkName:  "Application Load Balancer Request Routing",
			resourceID: "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/my-alb/abc123",
			prettyID:   "my-alb",
			metadata:   map[string]any{"Region": "eu-west-1"},
			expected:   "https://eu-west-1.console.aws.amazon.com/ec2/v2/home?region=eu-west-1#LoadBalancers:search=my-alb",
		},
		{
			name:       "Elastic IP address",
			checkName:  "Unassociated Elastic IP Addresses",
			resourceID: "54.210.167.204",
			prettyID:   "54.210.167.204",
			metadata:   map[string]any{"Region": "us-east-1"},
			expected:   "https://us-east-1.console.aws.amazon.com/ec2/v2/home?region=us-east-1#Addresses:PublicIp=54.210.167.204",
		},
		{
			name:       "EC2 Instance",
			checkName:  "Amazon EC2 Reserved Instances Optimization",
			resourceID: "i-0123456789abcdef0",
			prettyID:   "web-server-1",
			metadata:   map[string]any{"Region": "us-east-2"},
			expected:   "https://us-east-2.console.aws.amazon.com/ec2/v2/home?region=us-east-2#InstanceDetails:instanceId=i-0123456789abcdef0",
		},
		{
			name:       "EC2 Volume",
			checkName:  "Amazon EBS Public Snapshots",
			resourceID: "vol-0123456789abcdef0",
			prettyID:   "vol-0123456789abcdef0",
			metadata:   map[string]any{"Location": "eu-west-1"},
			expected:   "https://eu-west-1.console.aws.amazon.com/ec2/v2/home?region=eu-west-1#VolumeDetails:volumeId=vol-0123456789abcdef0",
		},
		{
			name:       "RDS Instance",
			checkName:  "Amazon RDS Public Snapshots",
			resourceID: "db-ABCDEF123456",
			prettyID:   "my-database",
			metadata:   map[string]any{"Region": "ap-southeast-1"},
			expected:   "https://ap-southeast-1.console.aws.amazon.com/rds/home?region=ap-southeast-1#database:id=db-ABCDEF123456",
		},
		{
			name:       "IAM User Default",
			checkName:  "IAM Password Policy",
			resourceID: "N/A",
			prettyID:   "N/A",
			metadata:   map[string]any{},
			expected:   "https://console.aws.amazon.com/iam/home?#/users",
		},
		{
			name:       "IAM User Specific User Name",
			checkName:  "IAM Access Keys",
			resourceID: "AKIAIOSFODNN7EXAMPLE",
			prettyID:   "bob",
			metadata:   map[string]any{"User Name": "bob"},
			expected:   "https://console.aws.amazon.com/iam/home?#/users/bob",
		},
		{
			name:       "IAM User Specific IAM User",
			checkName:  "IAM Access Keys",
			resourceID: "wS3Frl3Uj_np0NfD4VhfHA1rvysKv7mcZmmUAJZXYsk",
			prettyID:   "cmtn-azure-cross-account-dev3-ai-services-user",
			metadata:   map[string]any{"IAM User": "cmtn-azure-cross-account-dev3-ai-services-user"},
			expected:   "https://console.aws.amazon.com/iam/home?#/users/cmtn-azure-cross-account-dev3-ai-services-user",
		},
		{
			name:       "Lambda ARN",
			checkName:  "AWS Lambda Functions Using Deprecated Runtimes",
			resourceID: "arn:aws:lambda:us-west-2:123456789012:function:my-function",
			prettyID:   "my-function",
			metadata:   map[string]any{"Region": "us-west-2"},
			expected:   "https://us-west-2.console.aws.amazon.com/lambda/home?region=us-west-2#/functions/my-function",
		},
		{
			name:       "Lambda Name Fallback",
			checkName:  "AWS Lambda Functions Using Deprecated Runtimes",
			resourceID: "my-function-name",
			prettyID:   "my-function-name",
			metadata:   map[string]any{"Region": "eu-central-1"},
			expected:   "https://eu-central-1.console.aws.amazon.com/lambda/home?region=eu-central-1#/functions/my-function-name",
		},
		{
			name:       "Fallback General Link",
			checkName:  "Some Unknown Check",
			resourceID: "unknown-id",
			prettyID:   "unknown-id",
			metadata:   map[string]any{},
			expected:   "https://console.aws.amazon.com/trustedadvisor/home?region=us-east-1#/dashboard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildDeepLink(tt.checkName, tt.resourceID, tt.prettyID, tt.metadata)
			if !strings.HasPrefix(result, "http") || result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

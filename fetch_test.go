package rtawscan

import (
	"strings"
	"testing"
)

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

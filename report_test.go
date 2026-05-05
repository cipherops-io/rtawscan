package rtawscan

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/cipherops-io/rsvcmodel"
)

func TestMapCategoryToSegment(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected rsvcmodel.Segment
	}{
		{"Cost Optimizing", "cost_optimizing", rsvcmodel.SegmentFinOps},
		{"Security", "security", rsvcmodel.SegmentSecurity},
		{"Performance", "performance", rsvcmodel.SegmentObservability},
		{"Fault Tolerance", "fault_tolerance", rsvcmodel.SegmentObservability},
		{"General", "other", rsvcmodel.SegmentObservability},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapCategoryToSegment(tt.input)
			if result != tt.expected {
				t.Errorf("mapCategoryToSegment(%q) = %q; expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFindPrettyName(t *testing.T) {
	tests := []struct {
		name     string
		headers  []*string
		metadata []*string
		fallback string
		expected string
	}{
		{
			name:     "Matches Name",
			headers:  []*string{aws.String("Region"), aws.String("Bucket Name")},
			metadata: []*string{aws.String("us-east-1"), aws.String("my-cool-bucket")},
			fallback: "fallback-id",
			expected: "my-cool-bucket",
		},
		{
			name:     "Matches User",
			headers:  []*string{aws.String("User Name")},
			metadata: []*string{aws.String("alice")},
			fallback: "fallback-id",
			expected: "alice",
		},
		{
			name:     "Ignores exact region values",
			headers:  []*string{aws.String("Bucket Name")},
			metadata: []*string{aws.String("ap-south-1")},
			fallback: "fallback-id",
			expected: "fallback-id", // skips because ap-south-1 is a region
		},
		{
			name:     "Allows domain containing region substring",
			headers:  []*string{aws.String("Domain Name")},
			metadata: []*string{aws.String("us-east-1-domain")},
			fallback: "fallback-id",
			expected: "us-east-1-domain", // not an exact region match, so allowed
		},
		{
			name:     "Skips Region Name header entirely",
			headers:  []*string{aws.String("Region Name"), aws.String("Bucket Name")},
			metadata: []*string{aws.String("ap-south-1"), aws.String("my-bucket")},
			fallback: "fallback-id",
			expected: "my-bucket", // skips "Region Name" header, finds "Bucket Name"
		},
		{
			name:     "Fallback when no match",
			headers:  []*string{aws.String("Status"), aws.String("Reason")},
			metadata: []*string{aws.String("OK"), aws.String("None")},
			fallback: "fallback-id",
			expected: "fallback-id",
		},
		{
			name:     "Out of bounds metadata gracefully handled",
			headers:  []*string{aws.String("Resource")},
			metadata: []*string{},
			fallback: "fallback-id",
			expected: "fallback-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findPrettyName(tt.headers, tt.metadata, tt.fallback)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGenerateHTMLTable(t *testing.T) {
	findings := []*rsvcmodel.Finding{
		{
			Segment:     rsvcmodel.SegmentSecurity,
			Category:    "security",
			Title:       "S3 Bucket Public Access",
			Severity:    rsvcmodel.SeverityCritical,
			Items:       []string{"public-bucket"},
			ResourceIDs: []string{"arn:aws:s3:::public-bucket"},
			Metadata: map[string]any{
				"links": []any{"https://s3.console.aws.amazon.com/s3/buckets/public-bucket"},
			},
		},
	}

	html := generateHTMLTable(findings)
	if html == "" {
		t.Errorf("generateHTMLTable returned empty string")
	}

	expectedStrings := []string{
		"<html>",
		"<td>security</td>",
		"<td>S3 Bucket Public Access</td>",
		"<td class='crit'>critical</td>",
		"<td><a href='https://s3.console.aws.amazon.com/s3/buckets/public-bucket' target='_blank'>public-bucket</a></td>",
	}

	for _, str := range expectedStrings {
		if !strings.Contains(html, str) {
			t.Errorf("HTML output missing expected string: %s", str)
		}
	}
}

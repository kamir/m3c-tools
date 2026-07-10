package plaud

import "testing"

// TestIsAllowedS3URL locks the SEC L7 hardening: https-only, S3 bucket-style
// hosts only, CloudFront pinned to the explicit distribution. A compromised or
// MITM'd Plaud API response hands us these URLs, so the allowlist is a real
// trust boundary.
func TestIsAllowedS3URL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool
	}{
		// allowed
		{"explicit s3", "https://s3.amazonaws.com/bucket/key.json", true},
		{"explicit regional", "https://s3.us-west-2.amazonaws.com/b/k.gz", true},
		{"pinned cloudfront", "https://d2mzb0q2lbfnv7.cloudfront.net/x.json", true},
		{"bucket-style virtual host", "https://my-bucket.s3.amazonaws.com/k.json", true},
		{"bucket-style regional", "https://my-bucket.s3.eu-central-1.amazonaws.com/k", true},
		{"bucket-style dash region", "https://my-bucket.s3-us-west-2.amazonaws.com/k", true},

		// rejected — scheme downgrade
		{"http downgrade explicit", "http://s3.amazonaws.com/b/k", false},
		{"http downgrade bucket", "http://my-bucket.s3.amazonaws.com/k", false},

		// rejected — over-broad AWS subdomain (old wildcard would have allowed)
		{"arbitrary aws subdomain", "https://evil.amazonaws.com/k", false},
		{"ec2-style aws host", "https://ec2-1-2-3-4.compute.amazonaws.com/k", false},

		// rejected — arbitrary cloudfront (old wildcard would have allowed)
		{"unpinned cloudfront", "https://attacker.cloudfront.net/k", false},

		// rejected — unrelated / malformed
		{"unrelated host", "https://example.com/k", false},
		{"lookalike suffix", "https://amazonaws.com.evil.test/k", false},
		{"empty", "", false},
		{"garbage", "://not a url", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAllowedS3URL(tc.url); got != tc.want {
				t.Errorf("isAllowedS3URL(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

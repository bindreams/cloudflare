package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
)

// TestCloudflareLongTXTRoundTrip exercises a long (>255 byte) TXT record
// through Append → Get → Delete to verify RFC 1035 §3.3.14 chunking works
// end-to-end against the real Cloudflare API.
//
// Reproduces the failure mode in https://github.com/libdns/cloudflare/issues/32:
// before the fix, GetRecords surfaced embedded `" "` segment separators inside
// TXT.Text, and DeleteRecords silently returned zero deletions because the
// match comparator never saw the chunked stored form.
func TestCloudflareLongTXTRoundTrip(t *testing.T) {
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	zoneToken := os.Getenv("CLOUDFLARE_ZONE_TOKEN")
	testZone := os.Getenv("CLOUDFLARE_TEST_ZONE")

	if apiToken == "" || testZone == "" {
		t.Skip("Skipping: CLOUDFLARE_API_TOKEN and/or CLOUDFLARE_TEST_ZONE not set")
	}
	if !strings.HasSuffix(testZone, ".") {
		t.Fatal("CLOUDFLARE_TEST_ZONE must end with a dot")
	}

	p := &cloudflare.Provider{APIToken: apiToken, ZoneToken: zoneToken}

	// 410-byte DKIM-shaped value (matches issue reproduction).
	value := "v=DKIM1; k=rsa; p=" + strings.Repeat("ABCDEFGH", 49)
	name := "test-long-txt-roundtrip._domainkey"
	rec := libdns.TXT{Name: name, Text: value, TTL: 5 * time.Minute}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Best-effort cleanup in case any assertion fires before the delete step.
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_, _ = p.DeleteRecords(cleanupCtx, testZone, []libdns.Record{rec})
	})

	appended, err := p.AppendRecords(ctx, testZone, []libdns.Record{rec})
	if err != nil {
		t.Fatalf("AppendRecords failed: %v", err)
	}
	if len(appended) != 1 {
		t.Fatalf("AppendRecords returned %d records, want 1", len(appended))
	}

	all, err := p.GetRecords(ctx, testZone)
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	var found bool
	for _, r := range all {
		rr := r.RR()
		if rr.Type != "TXT" || rr.Name != name {
			continue
		}
		found = true
		if rr.Data != value {
			firstDiff := -1
			for i := 0; i < len(rr.Data) && i < len(value); i++ {
				if rr.Data[i] != value[i] {
					firstDiff = i
					break
				}
			}
			t.Errorf("TXT round-trip corrupted: input len=%d, got len=%d, first byte diff at %d",
				len(value), len(rr.Data), firstDiff)
		}
		break
	}
	if !found {
		t.Fatalf("GetRecords did not return the appended TXT record %q", name)
	}

	deleted, err := p.DeleteRecords(ctx, testZone, []libdns.Record{rec})
	if err != nil {
		t.Fatalf("DeleteRecords failed: %v", err)
	}
	if len(deleted) != 1 {
		t.Errorf("DeleteRecords returned %d, want 1 (silent no-op symptom from issue #32)", len(deleted))
	}

	all, err = p.GetRecords(ctx, testZone)
	if err != nil {
		t.Fatalf("post-delete GetRecords failed: %v", err)
	}
	for _, r := range all {
		rr := r.RR()
		if rr.Type == "TXT" && rr.Name == name {
			t.Errorf("TXT record %q still present after DeleteRecords", name)
		}
	}
}

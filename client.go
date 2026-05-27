package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/libdns/libdns"
)

func (p *Provider) createRecord(ctx context.Context, zoneInfo cfZone, record libdns.Record) (cfDNSRecord, error) {
	cfRec, err := cloudflareRecord(record)
	if err != nil {
		return cfDNSRecord{}, err
	}
	jsonBytes, err := json.Marshal(cfRec)
	if err != nil {
		return cfDNSRecord{}, err
	}

	reqURL := fmt.Sprintf("%s/zones/%s/dns_records", baseURL, zoneInfo.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return cfDNSRecord{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	var result cfDNSRecord
	_, err = p.doAPIRequest(req, &result)
	if err != nil {
		return cfDNSRecord{}, err
	}

	return result, nil
}

// updateRecord updates a DNS record. oldRec must have both an ID and zone ID.
// Only the non-empty fields in newRec will be changed.
func (p *Provider) updateRecord(ctx context.Context, oldRec, newRec cfDNSRecord) (cfDNSRecord, error) {
	reqURL := fmt.Sprintf("%s/zones/%s/dns_records/%s", baseURL, oldRec.ZoneID, oldRec.ID)
	jsonBytes, err := json.Marshal(newRec)
	if err != nil {
		return cfDNSRecord{}, err
	}

	// PATCH changes only the populated fields; PUT resets Type, Name, Content, and TTL even if empty
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, reqURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return cfDNSRecord{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	var result cfDNSRecord
	_, err = p.doAPIRequest(req, &result)
	return result, err
}

func (p *Provider) getDNSRecords(ctx context.Context, zoneInfo cfZone, rec libdns.Record, matchContent bool) ([]cfDNSRecord, error) {
	rr, err := cloudflareRecord(rec)
	if err != nil {
		return nil, err
	}

	qs := make(url.Values)
	qs.Set("type", rr.Type)
	qs.Set("name", libdns.AbsoluteName(rr.Name, zoneInfo.Name))

	var unwrappedContent string
	if matchContent {
		if rr.Type == "TXT" {
			// Match TXT locally on unwrapped content (see below) to be robust against
			// Cloudflare's chunked wire format for records >255 bytes (RFC 1035 §3.3.14).
			// Don't put the (potentially long) content into the URL filter.
			unwrappedContent = unwrapContent(rr.Content)
		} else if rr.Type != "SRV" && rr.Type != "HTTPS" && rr.Type != "SVCB" {
			// SRV, HTTPS, SVCB records don't support content.exact filtering in Cloudflare API
			// They will be matched by type and name only
			qs.Set("content.exact", rr.Content)
		}
	}

	reqURL := fmt.Sprintf("%s/zones/%s/dns_records?%s", baseURL, zoneInfo.ID, qs.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	var results []cfDNSRecord
	_, err = p.doAPIRequest(req, &results)
	if err != nil {
		return nil, err
	}

	// TXT matching is structural (on unwrapped content) so it works regardless of
	// whether the API returns chunked or single-segment form.
	if matchContent && rr.Type == "TXT" {
		for i := range results {
			if unwrapContent(results[i].Content) == unwrappedContent {
				return []cfDNSRecord{results[i]}, nil
			}
		}
		return []cfDNSRecord{}, nil
	}

	return results, nil
}

func (p *Provider) getZoneInfo(ctx context.Context, zoneName string) (cfZone, error) {
	p.zonesMu.Lock()
	defer p.zonesMu.Unlock()

	// if we already got the zone info, reuse it
	if p.zones == nil {
		p.zones = make(map[string]cfZone)
	}
	if zone, ok := p.zones[zoneName]; ok {
		return zone, nil
	}

	qs := make(url.Values)
	qs.Set("name", zoneName)
	reqURL := fmt.Sprintf("%s/zones?%s", baseURL, qs.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return cfZone{}, err
	}

	if p.ZoneToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.ZoneToken)
	}
	var zones []cfZone
	_, err = p.doAPIRequest(req, &zones)
	if err != nil {
		return cfZone{}, err
	}
	if len(zones) != 1 {
		return cfZone{}, fmt.Errorf("expected 1 zone, got %d for %s", len(zones), zoneName)
	}

	// cache this zone for possible reuse
	p.zones[zoneName] = zones[0]

	return zones[0], nil
}

// getClient returns http client to use
func (p *Provider) getClient() HTTPClient {
	if p.HTTPClient == nil {
		return http.DefaultClient
	}
	return p.HTTPClient
}

// doAPIRequest does the round trip, adding Authorization header if not already supplied.
// It returns the decoded response from Cloudflare if successful; otherwise it returns an
// error including error information from the API if applicable. If result is a
// non-nil pointer, the result field from the API response will be decoded into
// it for convenience.
func (p *Provider) doAPIRequest(req *http.Request, result any) (cfResponse, error) {
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+p.APIToken)
	}

	resp, err := p.getClient().Do(req)
	if err != nil {
		return cfResponse{}, err
	}
	defer resp.Body.Close()

	var respData cfResponse
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return cfResponse{}, err
	}

	if resp.StatusCode >= 400 {
		return cfResponse{}, fmt.Errorf("got error status: HTTP %d: %+v", resp.StatusCode, respData.Errors)
	}
	if len(respData.Errors) > 0 {
		return cfResponse{}, fmt.Errorf("got errors: HTTP %d: %+v", resp.StatusCode, respData.Errors)
	}

	if len(respData.Result) > 0 && result != nil {
		err = json.Unmarshal(respData.Result, result)
		if err != nil {
			return cfResponse{}, err
		}
		respData.Result = nil
	}

	return respData, err
}

const baseURL = "https://api.cloudflare.com/client/v4"

// txtChunkSize is the maximum length of a single RFC 1035 §3.3.14 character-string.
// TXT record content longer than this must be split into multiple character-strings
// on the wire.
const txtChunkSize = 255

// unwrapContent decodes Cloudflare's stored TXT representation, which is one or
// more double-quoted RFC 1035 §3.3.14 character-strings separated by whitespace,
// into the concatenated byte sequence. Each segment is decoded with
// [strconv.Unquote], so backslash escapes that [fmt.Sprintf] %q emits (including
// \xNN for non-printable bytes) round-trip correctly.
//
// If content doesn't look like quoted form (e.g. legacy or malformed data), or
// if any segment fails to parse, it is returned unchanged.
func unwrapContent(content string) string {
	if !strings.HasPrefix(content, `"`) {
		return content
	}
	var sb strings.Builder
	sb.Grow(len(content))
	i := 0
	for i < len(content) {
		for i < len(content) && isTXTSeparator(content[i]) {
			i++
		}
		if i >= len(content) {
			break
		}
		if content[i] != '"' {
			return content
		}
		end := i + 1
		for end < len(content) {
			if content[end] == '\\' && end+1 < len(content) {
				end += 2
				continue
			}
			if content[end] == '"' {
				break
			}
			end++
		}
		if end >= len(content) {
			return content
		}
		seg, err := strconv.Unquote(content[i : end+1])
		if err != nil {
			return content
		}
		sb.WriteString(seg)
		i = end + 1
	}
	return sb.String()
}

// isTXTSeparator reports whether b is one of the ASCII whitespace bytes that
// can appear between character-strings in an RFC 1035 zone-file-style RDATA.
func isTXTSeparator(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// wrapContent encodes TXT content as one or more double-quoted RFC 1035 §3.3.14
// character-strings. Content longer than [txtChunkSize] is split into chunks
// (at byte boundaries — character-strings are byte-counted), each formatted
// with %q and joined with a single space. Content up to [txtChunkSize] bytes
// produces a single quoted segment, matching the wire format Cloudflare returns.
func wrapContent(content string) string {
	if len(content) <= txtChunkSize {
		return fmt.Sprintf("%q", content)
	}
	var sb strings.Builder
	sb.Grow(len(content) + (len(content)/txtChunkSize+1)*3)
	for i := 0; i < len(content); i += txtChunkSize {
		if i > 0 {
			sb.WriteByte(' ')
		}
		end := i + txtChunkSize
		if end > len(content) {
			end = len(content)
		}
		fmt.Fprintf(&sb, "%q", content[i:end])
	}
	return sb.String()
}

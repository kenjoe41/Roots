package shardprobe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"testing"
)

func TestParseShard_HalfYear(t *testing.T) {
	key, ok := parseShard("https://ct.googleapis.com/logs/us1/argon2026h2/")
	if !ok {
		t.Fatal("expected a half-year shard to parse")
	}
	if key.year != 2026 || key.half != 2 {
		t.Errorf("year/half = %d/%d, want 2026/2", key.year, key.half)
	}
	if got := key.url(); got != "https://ct.googleapis.com/logs/us1/argon2026h2/" {
		t.Errorf("url() round-trip = %q, want original", got)
	}
}

func TestParseShard_YearOnly(t *testing.T) {
	key, ok := parseShard("https://ct.cloudflare.com/logs/nimbus2026/")
	if !ok {
		t.Fatal("expected a year-only shard to parse")
	}
	if key.year != 2026 || key.half != 0 {
		t.Errorf("year/half = %d/%d, want 2026/0", key.year, key.half)
	}
	if got := key.url(); got != "https://ct.cloudflare.com/logs/nimbus2026/" {
		t.Errorf("url() round-trip = %q, want original", got)
	}
}

// TestParseShard_RepeatedYear covers operators like TrustAsia that repeat
// the same year in both the hostname and the path
// ("hetu2027.trustasia.com/hetu2027/") - every literal occurrence of the
// detected year must fold into the template, or generated candidates end
// up with a mismatched hostname/path year.
func TestParseShard_RepeatedYear(t *testing.T) {
	key, ok := parseShard("https://hetu2027.trustasia.com/hetu2027/")
	if !ok {
		t.Fatal("expected a repeated-year shard to parse")
	}
	if got := key.url(); got != "https://hetu2027.trustasia.com/hetu2027/" {
		t.Errorf("url() round-trip = %q, want original", got)
	}

	older := key.prev()
	want := "https://hetu2026.trustasia.com/hetu2026/"
	if got := older.url(); got != want {
		t.Errorf("prev().url() = %q, want %q (both year occurrences must move together)", got, want)
	}
}

func TestShardKey_Prev(t *testing.T) {
	cases := []struct {
		name               string
		year, half         int
		wantYear, wantHalf int
	}{
		{"h2 to h1 same year", 2026, 2, 2026, 1},
		{"h1 rolls back a year to h2", 2026, 1, 2025, 2},
		{"year-only decrements", 2026, 0, 2025, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := shardKey{template: "https://example.com/%s/", year: c.year, half: c.half}
			got := k.prev()
			if got.year != c.wantYear || got.half != c.wantHalf {
				t.Errorf("prev() = %d/%d, want %d/%d", got.year, got.half, c.wantYear, c.wantHalf)
			}
		})
	}
}

func TestParseShard_NoDate(t *testing.T) {
	if _, ok := parseShard("https://ct.example.com/bogus/"); ok {
		t.Error("expected a non-dated URL to not parse as a shard")
	}
}

// TestParseShard_IgnoresPortNumber guards against shardYearRe matching a
// trailing 4-digit window of a longer digit run - a 5-digit port number
// like ":34567/" would otherwise be misread as year "4567".
func TestParseShard_IgnoresPortNumber(t *testing.T) {
	if _, ok := parseShard("http://127.0.0.1:34567/bogus/"); ok {
		t.Error("expected a URL whose only 4-digit-shaped substring is part of a port number to not parse as a shard")
	}
}

// TestDiscover_FindsOlderLiveShardsAndStops simulates a family with real
// data from 2023h1 through 2024h2, where only the newest shard (2024h2) is
// in the "known" list - mirroring the real-world case where Google's
// published log list only lists a family's most recent shards. Discover
// should walk backward, find the three older-but-still-live shards, and
// stop after maxConsecutiveMiss misses instead of walking indefinitely.
func TestDiscover_FindsOlderLiveShardsAndStops(t *testing.T) {
	shardRe := regexp.MustCompile(`argon(\d{4})h([12])`)
	var probed []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = append(probed, r.URL.Path)
		m := shardRe.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		year, _ := strconv.Atoi(m[1])
		half, _ := strconv.Atoi(m[2])
		if year < 2023 || (year == 2023 && half < 1) {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"tree_size":100,"timestamp":0,"sha256_root_hash":"","tree_head_signature":""}`)
	}))
	defer srv.Close()

	known := []string{srv.URL + "/logs/argon2024h2/"}

	got := Discover(context.Background(), srv.Client(), known)
	sort.Strings(got)

	want := []string{
		srv.URL + "/logs/argon2023h1/",
		srv.URL + "/logs/argon2023h2/",
		srv.URL + "/logs/argon2024h1/",
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("Discover() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Discover()[%d] = %q, want %q (full: got=%v want=%v)", i, got[i], want[i], got, want)
		}
	}

	// 3 hits (2024h1, 2023h2, 2023h1) + maxConsecutiveMiss misses
	// (2022h2, 2022h1, 2021h2) = 6 probes, then it must stop.
	if len(probed) != 6 {
		t.Errorf("probed %d candidates, want exactly 6 (3 hits + %d misses before stopping): %v",
			len(probed), maxConsecutiveMiss, probed)
	}
}

func TestDiscover_SkipsAlreadyKnownAndUndated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("Discover should not probe anything for a family with no gap to fill or an undated URL, got request for %s", r.URL.Path)
	}))
	defer srv.Close()

	known := []string{
		srv.URL + "/bogus/",    // no date pattern, should be skipped entirely
		srv.URL + "/testtube/", // no date pattern, should be skipped entirely
	}

	got := Discover(context.Background(), srv.Client(), known)
	if len(got) != 0 {
		t.Errorf("Discover() on undated URLs = %v, want empty", got)
	}
}

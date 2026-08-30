// Package shardprobe discovers older shards of date-sharded CT logs that
// have aged out of Google's published log-list feeds but are still live.
//
// Sharded log families (Google argon/xenon, Sectigo mammoth/sabre/elephant/
// tiger, DigiCert wyvern/sphinx, Let's Encrypt oak, Cloudflare nimbus, ...)
// roll over every half year or year, and the published log-list JSON only
// retains roughly the last couple of years of shard names even though the
// servers keep serving indefinitely. As of this package's writing,
// xenon2025h2 and argon2025h2 - both billions of entries - are live and
// return HTTP 200 despite appearing in neither log_list.json nor
// all_logs_list.json.
//
// This only rediscovers shards within a family's CURRENT naming scheme; it
// cannot find a family's pre-rename predecessor (Google's older
// "daedalus"/"submariner" logs use unrelated names, not an older year of
// "argon") - those are only reachable via all_logs_list.json's own
// historical record, which the caller should already be including in the
// known list passed to Discover.
package shardprobe

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// maxBackSteps bounds how far back a single family is walked,
	// regardless of hit/miss streaks - a safety net against a pathological
	// template that happens to keep 200-ing on unrelated content.
	maxBackSteps = 30 // half-year families: ~15 years back.

	// maxConsecutiveMiss stops walking a family once this many candidates
	// in a row don't respond, on the assumption we've walked past the
	// family's actual start.
	maxConsecutiveMiss = 3

	probeTimeout = 5 * time.Second
)

// yearToken and halfToken are sentinel placeholders substituted into a
// shard's URL template in place of its year/half digits. They use a NUL
// byte, which cannot appear in a valid URL, so they can't collide with
// real URL content.
const (
	yearToken = "\x00Y\x00"
	halfToken = "\x00H\x00"
)

var (
	// shardHalfRe matches a <year>h<half> shard token, e.g. "2026h2".
	shardHalfRe = regexp.MustCompile(`(\d{4})h([12])`)
	// shardYearRe matches a bare 4-digit year token at a path boundary
	// (e.g. Cloudflare's ".../nimbus2026/"), avoiding false matches on
	// unrelated digits elsewhere in the URL.
	shardYearRe = regexp.MustCompile(`(\d{4})(/|$)`)
)

// shardKey identifies one shard within a dated log family: the URL
// template with its year/half replaced by sentinel tokens, plus that
// shard's own year/half. half is 0 for year-only families.
type shardKey struct {
	template string
	year     int
	half     int
}

// parseShard extracts a shardKey from a log URL, or ok=false if the URL
// doesn't look like a dated shard (one-off logs, test logs, etc).
//
// Some operators repeat the same year in more than one place (e.g.
// TrustAsia's "https://hetu2027.trustasia.com/hetu2027/" repeats it in both
// host and path); every literal occurrence of the detected year is folded
// into the template, not just the first match, so such families still
// round-trip correctly.
func parseShard(logURL string) (shardKey, bool) {
	if m := shardHalfRe.FindStringSubmatch(logURL); m != nil {
		yearStr, halfStr := m[1], m[2]
		year, _ := strconv.Atoi(yearStr)
		half, _ := strconv.Atoi(halfStr)

		tmpl := strings.Replace(logURL, yearStr+"h"+halfStr, yearToken+"h"+halfToken, 1)
		tmpl = strings.ReplaceAll(tmpl, yearStr, yearToken)
		return shardKey{template: tmpl, year: year, half: half}, true
	}

	if loc := shardYearRe.FindStringSubmatchIndex(logURL); loc != nil {
		start := loc[2]
		// shardYearRe isn't anchored on its left edge, so against a longer
		// digit run (e.g. a 5-digit port number like ":34567/") it will
		// still match the trailing 4-digit window ("4567/"). Reject any
		// match immediately preceded by another digit to rule that out;
		// legitimate shard years are always preceded by a letter, "/", or
		// the start of the string (e.g. "nimbus2026/", "hetu2027/").
		if start == 0 || logURL[start-1] < '0' || logURL[start-1] > '9' {
			yearStr := logURL[loc[2]:loc[3]]
			year, _ := strconv.Atoi(yearStr)
			tmpl := strings.ReplaceAll(logURL, yearStr, yearToken)
			return shardKey{template: tmpl, year: year, half: 0}, true
		}
	}

	return shardKey{}, false
}

// url renders k back into a concrete log URL.
func (k shardKey) url() string {
	s := strings.ReplaceAll(k.template, yearToken, strconv.Itoa(k.year))
	if strings.Contains(k.template, halfToken) {
		s = strings.ReplaceAll(s, halfToken, strconv.Itoa(k.half))
	}
	return s
}

// prev returns the shard immediately preceding k in its family's ordering.
func (k shardKey) prev() shardKey {
	year, half := k.year, k.half
	switch half {
	case 0:
		year--
	case 2:
		half = 1
	default: // 1
		year--
		half = 2
	}
	return shardKey{template: k.template, year: year, half: half}
}

func (k shardKey) olderThan(other shardKey) bool {
	if k.year != other.year {
		return k.year < other.year
	}
	return k.half < other.half
}

// Discover probes for older shards of every dated log family present in
// known, returning the URLs of any that are still live but weren't already
// in known. It only walks backward from each family's oldest known shard,
// stopping early on maxConsecutiveMiss misses or after maxBackSteps.
func Discover(ctx context.Context, probeClient *http.Client, known []string) []string {
	seen := make(map[string]bool, len(known))
	for _, u := range known {
		seen[u] = true
	}

	oldestByFamily := map[string]shardKey{}
	var order []string
	for _, u := range known {
		key, ok := parseShard(u)
		if !ok {
			continue
		}
		if existing, present := oldestByFamily[key.template]; !present || key.olderThan(existing) {
			if !present {
				order = append(order, key.template)
			}
			oldestByFamily[key.template] = key
		}
	}

	var (
		mu    sync.Mutex
		found []string
		wg    sync.WaitGroup
	)
	for _, tmpl := range order {
		wg.Add(1)
		go func(oldestKnown shardKey) {
			defer wg.Done()

			key := oldestKnown.prev()
			misses := 0
			for steps := 0; steps < maxBackSteps && misses < maxConsecutiveMiss; steps++ {
				candidate := key.url()
				if !seen[candidate] {
					if probeLive(ctx, probeClient, candidate) {
						mu.Lock()
						found = append(found, candidate)
						mu.Unlock()
						misses = 0
					} else {
						misses++
					}
				}
				key = key.prev()
			}
		}(oldestByFamily[tmpl])
	}
	wg.Wait()

	return found
}

func probeLive(ctx context.Context, client *http.Client, logURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(logURL, "/")+"/ct/v1/get-sth", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Roots-shardprobe")

	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

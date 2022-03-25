package loglist

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type LogList struct {
	Operators []*Operator `json:"operators"`
}

type Operator struct {
	Logs []*Log `json:"logs"`
}

type Log struct {
	URL string `json:"url"`
}

func Fetch(url string) (*LogList, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching log list from server: %s", err)
	}
	content, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error reading log list respomse body: %s", err)
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("non-2XX response from server: %s", err)
	}
	return Unmarshal(content), nil
}

func Unmarshal(jsonBytes []byte) *LogList {
	list := new(LogList)

	if err := json.Unmarshal(jsonBytes, &list); err != nil {
		return nil
	}
	return list
}

func Min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func Max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
func ValidHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")

	if len(host) == 0 {
		return false
	}

	for i, part := range strings.Split(host, ".") {
		if part == "" {
			// Empty label.
			return false
		}
		if i == 0 && part == "*" {
			// Only allow full left-most wildcards, as those are the only ones
			// we match, and matching literal '*' characters is probably never
			// the expected behavior.
			continue
		}
		for j, c := range part {
			if 'a' <= c && c <= 'z' {
				continue
			}
			if '0' <= c && c <= '9' {
				continue
			}
			if 'A' <= c && c <= 'Z' {
				continue
			}
			if c == '-' && j != 0 {
				continue
			}
			if c == '_' || c == ':' {
				// Not valid characters in hostnames, but commonly
				// found in deployments outside the WebPKI.
				continue
			}
			return false
		}
	}

	return true
}

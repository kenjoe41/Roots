package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/client/backoff"
	"github.com/hashicorp/go-retryablehttp"

	"github.com/kenjoe41/Roots/internal/cert"
	"github.com/kenjoe41/Roots/internal/certscan"
	"github.com/kenjoe41/Roots/internal/loglist"
)

const (
	logListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

	batchSize  = 1000
	startIndex = int64(0)
	numWorkers = 10

	httpRetryMax     = 8
	httpRetryWaitMin = 1 * time.Second
	httpRetryWaitMax = 60 * time.Second
)

// newHTTPClient returns an *http.Client shared by every request Roots makes
// (log list fetch, GetSTH, GetRawEntries). CT log servers rate-limit
// aggressively under load; this transparently retries on 429/5xx and
// connection errors, honoring a server's Retry-After header on 429 instead
// of hammering it on a fixed interval.
func newHTTPClient() *http.Client {
	rc := retryablehttp.NewClient()
	rc.RetryMax = httpRetryMax
	rc.RetryWaitMin = httpRetryWaitMin
	rc.RetryWaitMax = httpRetryWaitMax
	rc.Logger = retryLogger{}
	return rc.StandardClient()
}

// retryLogger adapts retryablehttp's leveled logging to this CLI's plain
// stderr progress style, so rate-limit backoffs are visible instead of
// silently absorbed.
type retryLogger struct{}

func (retryLogger) Error(msg string, kv ...interface{}) { logRetry("error", msg, kv) }
func (retryLogger) Warn(msg string, kv ...interface{})  { logRetry("warn", msg, kv) }
func (retryLogger) Info(msg string, kv ...interface{})  {}

// Debug fires on both "performing request" (every attempt, including the
// first) and "retrying request" (only when a retry was decided) - only the
// latter is worth surfacing, or every request would log a line.
func (retryLogger) Debug(msg string, kv ...interface{}) {
	if msg == "retrying request" {
		logRetry("retry", msg, kv)
	}
}

func logRetry(level, msg string, kv []interface{}) {
	fmt.Fprintf(os.Stderr, "[http %s] %s %v\n", level, msg, kv)
}

func main() {
	fmt.Fprintln(os.Stderr, "Getting CT Logs list...")

	httpClient := newHTTPClient()

	serverLogList, err := loglist.Fetch(logListURL, httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching CT log list: %s\n", err)
		os.Exit(1)
	}

	// Check or create logs folder used to persist per-server resume state.
	if err := cert.CheckLogsFolder(); err != nil {
		fmt.Fprintf(os.Stderr, "Error preparing logs folder: %s\n", err)
		os.Exit(1)
	}

	domainsChan := make(chan string, batchSize*2)

	var domainsCount uint64
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		defer outputWG.Done()
		for domain := range domainsChan {
			fmt.Println(domain)
			domainsCount++
		}
	}()

	var logsWG sync.WaitGroup
	for _, operator := range serverLogList.Operators {
		for _, serverLog := range operator.Logs {
			logsWG.Add(1)
			go func(logserverURL string) {
				defer logsWG.Done()
				if err := processLog(logserverURL, domainsChan, httpClient); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] processing failed: %s\n", logserverURL, err)
				}
			}(serverLog.URL)
		}
	}

	logsWG.Wait()
	close(domainsChan)
	outputWG.Wait()

	fmt.Fprintf(os.Stderr, "Done walking the CT Logs Tree. Found %d domains.\n", domainsCount)
}

func processLog(logserverURL string, domainsChan chan<- string, httpClient *http.Client) error {
	ctClient, err := client.New(logserverURL, httpClient, jsonclient.Options{})
	if err != nil {
		return fmt.Errorf("unable to construct CT log client: %w", err)
	}
	ctx := context.Background()

	ranges := genRanges(ctx, logserverURL, ctClient)
	if ranges == nil {
		return fmt.Errorf("unable to determine tree size")
	}

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runWorker(ctx, logserverURL, ranges, domainsChan, ctClient)
		}()
	}
	wg.Wait()

	return nil
}

func runWorker(ctx context.Context, logserverURL string, ranges <-chan loglist.FetchRange, domainsChan chan<- string, ctClient *client.LogClient) {
	if ctx.Err() != nil { // Prevent spinning when context is canceled.
		return
	}

	for r := range ranges {
		for r.Start <= r.End {
			if ctx.Err() != nil { // Prevent spinning when context is canceled.
				return
			}

			fmt.Fprintf(os.Stderr, "[%s] Fetching entry %d - %d...\n", logserverURL, r.Start, r.End)

			bo := &backoff.Backoff{
				Min:    1 * time.Second,
				Max:    30 * time.Second,
				Factor: 2,
				Jitter: true,
			}

			var resp *ct.GetEntriesResponse
			if err := bo.Retry(ctx, func() error {
				var err error
				resp, err = ctClient.GetRawEntries(ctx, r.Start, r.End)
				return err
			}); err != nil {
				// No error reporting for this worker yet, just retry.
				continue
			}

			for i, entry := range resp.Entries {
				index := r.Start + int64(i)
				rawEntry, err := ct.RawLogEntryFromLeaf(index, &entry)
				if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
					fmt.Fprintf(os.Stderr, "Erroneous certificate: log=%s index=%d err=%v\n",
						logserverURL, index, err)
					continue
				}
				leafCert, err := certscan.Leaf(rawEntry)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Unparseable certificate: log=%s index=%d err=%v\n",
						logserverURL, index, err)
					continue
				}
				for _, host := range certscan.Hostnames(leafCert) {
					domainsChan <- host
				}
			}
			r.Start += int64(len(resp.Entries))

			if err := cert.WriteLogState(cert.LogState{LogServer: logserverURL, LogEndIndex: uint64(r.Start)}); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Failed to persist resume state: %s\n", logserverURL, err)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[%s] Done fetching entries...\n", logserverURL)
}

func genRanges(ctx context.Context, logserverURL string, ctClient *client.LogClient) <-chan loglist.FetchRange {
	batch := int64(batchSize)
	ranges := make(chan loglist.FetchRange)

	var logSTH *ct.SignedTreeHead
	bo := &backoff.Backoff{Min: 1 * time.Second, Max: 30 * time.Second, Factor: 2, Jitter: true}
	if err := bo.Retry(ctx, func() error {
		var err error
		logSTH, err = ctClient.GetSTH(ctx)
		return err
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Failed to get STH: %s\n", logserverURL, err)
		return nil
	}
	endIndex := loglist.Max(startIndex, int64(logSTH.TreeSize))

	// Resume from the last persisted index for this log server, if any.
	start := startIndex
	if state, err := cert.ReadLogState(cert.LogState{LogServer: logserverURL}); err == nil && state.LogEndIndex > 0 {
		start = loglist.Min(int64(state.LogEndIndex), endIndex)
	}

	go func() {
		defer close(ranges)
		for start < endIndex {
			batchEnd := start + loglist.Min(endIndex-start, batch)
			next := loglist.FetchRange{Start: start, End: batchEnd - 1}
			select {
			case <-ctx.Done():
				return
			case ranges <- next:
			}
			start = batchEnd
		}
	}()

	return ranges
}

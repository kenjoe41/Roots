package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/client/backoff"

	"github.com/kenjoe41/Roots/cert"
	"github.com/kenjoe41/Roots/loglist"
)

const (
	LOGLISTURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

	BATCH_SIZE  = 10000
	START_INDEX = int64(0)
	NUM_WORKERS = 10
)

var END_INDEX int64 = 0

func main() {

	fmt.Fprintln(os.Stderr, "Getting CT Logs list...")

	serverLogList, err := getLogslist(LOGLISTURL)
	if err != nil {

		fmt.Fprintf(os.Stderr, "Error: %q\n", err)
	}

	logDirPath, err := cert.GetLogsDir()
	if err != nil {
		panic(err)
	}

	f, err := os.OpenFile(path.Join(logDirPath, "../domains.txt"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0777)
	if err != nil {
		panic(err)
	}

	// Check or create logs folder to write progress and resume data.
	err = cert.CheckLogsFolder()
	if err != nil {
		panic(err)
	}

	var domains_count uint64 = 0
	domainsChan := make(chan string, (BATCH_SIZE * 2))
	logStateChan := make(chan cert.LogState)

	// // Log latest index gotten on particular server
	// // TODO: This is not working yet.
	// var logStateWG sync.WaitGroup
	// logStateWG.Add(1)
	// go func() {
	// 	defer close(logStateChan)
	// 	defer logStateWG.Done()

	// 	for logState := range logStateChan {
	// 		fmt.Printf("We are logging state: %s - %d\n", logState.LogServer, logState.LogEndIndex)
	// 		oldLogState, err := cert.ReadLogState(logState)
	// 		if err != nil {
	// 			// We might not have any log saved yet, save this one and continue
	// 			cert.WriteLogState(logState)
	// 			continue
	// 		}
	// 		if oldLogState.LogEndIndex == logState.LogEndIndex {
	// 			continue
	// 		}
	// 		logState.LogEndIndex = uint64(loglist.Max(int64(oldLogState.LogEndIndex), int64(logState.LogEndIndex)))

	// 		cert.WriteLogState(logState)
	// 	}

	// }()

	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		defer close(domainsChan)
		defer outputWG.Done()
		defer f.Close()

		for domain := range domainsChan {
			f.WriteString(domain + "\n")
			domains_count++
		}
	}()

	var logprocessWG sync.WaitGroup
	// fmt.Printf("Found %d Operators.", len(serverLogList.Operators))
	for i := 0; i < len(serverLogList.Operators); i++ {

		logprocessWG.Add(1)
		go func() {
			defer logprocessWG.Done()
			for _, operator := range serverLogList.Operators {

				for _, serverLog := range operator.Logs {

					err := processLog(serverLog.URL, domainsChan, logStateChan)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Something went terribly wrong this time: %s", err)
					}

				}
			}
		}()
	}

	logprocessWG.Wait()
	outputWG.Wait()
	// logStateWG.Wait()

	fmt.Fprint(os.Stdout, "Done walking the CT Logs Tree...")
	fmt.Fprintf(os.Stderr, " Found %d domains.", domains_count)
}

func processLog(logserverURL string, domainsChan chan string, logStateChan chan cert.LogState) error {

	ctClient, err := client.New(logserverURL, nil, jsonclient.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Unable to construct CT log client: %s\n", logserverURL, err)
	}
	ctx := context.Background()

	// Generate Ranges to get
	ranges := genRanges(ctx, ctClient)

	// Run fetcher workers.
	var wg sync.WaitGroup
	for w, cnt := 0, NUM_WORKERS; w < cnt; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// glog.V(1).Infof("%s: Fetcher worker %d starting...", f.uri, idx)
			runWorker(ctx, logserverURL, ranges, domainsChan, ctClient, logStateChan)
			// glog.V(1).Infof("%s: Fetcher worker %d finished", f.uri, idx)
		}(w)
	}
	wg.Wait()

	// glog.V(1).Infof("%s: Fetcher terminated", f.uri)
	return nil
}

func runWorker(ctx context.Context, logserverURL string, ranges <-chan loglist.FetchRange, domainsChan chan string, ctClient *client.LogClient, logStateChan chan cert.LogState) {

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
				// glog.Errorf("%s: GetRawEntries() failed: %v", f.uri, err)
				// There is no error reporting yet for this worker, so just retry again.
				continue
			}

			for i, entry := range resp.Entries {
				index := int64(r.Start) + int64(i)
				rawEntry, err := ct.RawLogEntryFromLeaf(index, &entry)
				if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
					fmt.Printf("Erroneous certificate: log=%s index=%d err=%v",
						logserverURL, index, err)
					continue
				}
				cert, err := rawEntry.Leaf.X509Certificate()
				if err != nil {
					// TODO: Add error logging later.
					continue
				}
				if len(cert.Subject.CommonName) > 0 && loglist.ValidHostname(cert.Subject.CommonName) {
					domainsChan <- cert.Subject.CommonName
				}
				if len(cert.DNSNames) > 0 {
					// Let's not collect bullsh*t, only valid hostnames
					for _, dnsname := range cert.DNSNames {
						if loglist.ValidHostname(dnsname) {

							domainsChan <- dnsname
						}
					}
				}
			}
			r.Start += int64(len(resp.Entries))

			logStateChan <- cert.LogState{LogServer: logserverURL, LogEndIndex: uint64(r.Start)}
		}

	}
	fmt.Fprintf(os.Stderr, "[%s] Done fetching entries ...\n", logserverURL)

	return
}

func genRanges(ctx context.Context, ctClient *client.LogClient) <-chan loglist.FetchRange {
	batch := int64(BATCH_SIZE)
	ranges := make(chan loglist.FetchRange)

	// Get the size of entries in a log.
	logSTH, err := ctClient.GetSTH(ctx)
	if err != nil {
		// log, failed to get STH of log server, retrn nil
		return nil
	}
	tree_size := int64(logSTH.TreeSize)
	// totalSize := tree_size - 1

	END_INDEX := loglist.Max(END_INDEX, tree_size)

	go func() {
		defer close(ranges)
		start, end := START_INDEX, END_INDEX

		for start < end {

			// if start == end { // Implies f.opts.Continuous == true.
			// 	if err := f.updateSTH(ctx); err != nil {
			// 		glog.Warningf("%s: Failed to obtain bigger STH: %v", f.uri, err)
			// 		return
			// 	}
			// 	end = f.opts.EndIndex
			// }

			batchEnd := int64(start) + loglist.Min(int64(end-start), batch)
			next := loglist.FetchRange{Start: start, End: (batchEnd - 1)}
			select {
			case <-ctx.Done():
				// glog.Warningf("%s: Cancelling genRanges: %v", f.uri, ctx.Err())
				return
			case ranges <- next:
			}
			start = batchEnd
		}
	}()

	return ranges
}

func getLogslist(logsurl string) (*loglist.LogList, error) {
	list, err := loglist.Fetch(logsurl)

	return list, err
}

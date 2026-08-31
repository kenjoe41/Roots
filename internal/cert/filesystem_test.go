package cert

import (
	"os"
	"sync"
	"testing"
)

// TestWriteLogState_ConcurrentWritesNeverRegress is the regression test for
// two bugs found running roots for real: (1) WriteLogState's shared,
// non-unique temp filename raced when multiple workers checkpointed the
// same log concurrently, failing with "rename ... no such file or
// directory"; (2) even with unique temp files, concurrent writers racing
// on which one persists last (not which one has the higher index) could
// silently regress the resume point, causing already-processed entries to
// be re-fetched on the next run.
func TestWriteLogState_ConcurrentWritesNeverRegress(t *testing.T) {
	if err := CheckLogsFolder(); err != nil {
		t.Fatalf("CheckLogsFolder: %v", err)
	}

	logServer := "https://test.roots-concurrency-regression.invalid/"
	filename, err := logserverFilename(LogState{LogServer: logServer})
	if err != nil {
		t.Fatalf("logserverFilename: %v", err)
	}
	t.Cleanup(func() { os.Remove(filename) })
	os.Remove(filename) // in case a previous failed run left one behind

	const workers = 20
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 1; i <= workers; i++ {
		wg.Add(1)
		go func(index uint64) {
			defer wg.Done()
			// Simulate numWorkers goroutines finishing their batches in
			// whatever order, all checkpointing the same log.
			if err := WriteLogState(LogState{LogServer: logServer, LogEndIndex: index * 1000}); err != nil {
				errs <- err
			}
		}(uint64(i))
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent WriteLogState returned an error (the exact failure mode this test guards against): %v", err)
	}

	final, err := ReadLogState(LogState{LogServer: logServer})
	if err != nil {
		t.Fatalf("ReadLogState after concurrent writes: %v", err)
	}
	if want := uint64(workers) * 1000; final.LogEndIndex != want {
		t.Errorf("final LogEndIndex = %d, want %d (the highest index any worker wrote - a lower value means progress regressed)",
			final.LogEndIndex, want)
	}
}

// TestWriteLogState_DoesNotRegressAcrossSequentialCalls covers the simple,
// non-concurrent case directly: a later call with a lower index must not
// overwrite an already-persisted higher one.
func TestWriteLogState_DoesNotRegressAcrossSequentialCalls(t *testing.T) {
	if err := CheckLogsFolder(); err != nil {
		t.Fatalf("CheckLogsFolder: %v", err)
	}

	logServer := "https://test.roots-sequential-regression.invalid/"
	filename, err := logserverFilename(LogState{LogServer: logServer})
	if err != nil {
		t.Fatalf("logserverFilename: %v", err)
	}
	t.Cleanup(func() { os.Remove(filename) })
	os.Remove(filename)

	if err := WriteLogState(LogState{LogServer: logServer, LogEndIndex: 5000}); err != nil {
		t.Fatalf("WriteLogState(5000): %v", err)
	}
	if err := WriteLogState(LogState{LogServer: logServer, LogEndIndex: 2000}); err != nil {
		t.Fatalf("WriteLogState(2000): %v", err)
	}

	final, err := ReadLogState(LogState{LogServer: logServer})
	if err != nil {
		t.Fatalf("ReadLogState: %v", err)
	}
	if final.LogEndIndex != 5000 {
		t.Errorf("LogEndIndex = %d, want 5000 (a later write with a lower index must not regress it)", final.LogEndIndex)
	}
}

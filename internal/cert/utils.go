package cert

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// logserverFilename maps a log server URL to a stable, filesystem-safe path
// under the logs directory, e.g. "https://ct.example.com/log" ->
// "<logsDir>/https_ct_example_com_log.json".
func logserverFilename(logstate LogState) (string, error) {
	dir, err := GetLogsDir()
	if err != nil {
		return "", err
	}

	replacer := strings.NewReplacer("://", "_", "/", "_", ".", "_")
	cleanName := replacer.Replace(logstate.LogServer)
	return filepath.Join(dir, cleanName+".json"), nil
}

// writeJSONFile writes obj to filename via a temp-file-then-rename for
// atomicity. The temp file is created with a unique, process-and-call
// specific name (os.CreateTemp's "*" pattern): a literal "filename+.new"
// shared across every caller races when two callers write the same
// filename concurrently - runWorker's numWorkers goroutines routinely
// checkpoint the same log's resume state at once, and two writers sharing
// one temp file name means whichever renames first deletes the file the
// second is about to rename, which then fails with ENOENT.
func writeJSONFile(filename string, obj interface{}, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	f, err := os.CreateTemp(dir, filepath.Base(filename)+".*.new")
	if err != nil {
		return err
	}
	tempname := f.Name()
	if err := os.Chmod(tempname, perm); err != nil {
		f.Close()
		os.Remove(tempname)
		return err
	}
	if err := json.NewEncoder(f).Encode(obj); err != nil {
		f.Close()
		os.Remove(tempname)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tempname)
		return err
	}
	if err := os.Rename(tempname, filename); err != nil {
		os.Remove(tempname)
		return err
	}
	return nil
}

func readJSONFile(filename string, obj interface{}) error {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filename, err)
	}
	if err := json.Unmarshal(bytes, obj); err != nil {
		return fmt.Errorf("unmarshalling %s: %w", filename, err)
	}
	return nil
}

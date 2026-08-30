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

func writeJSONFile(filename string, obj interface{}, perm os.FileMode) error {
	tempname := filename + ".new"
	f, err := os.OpenFile(tempname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
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

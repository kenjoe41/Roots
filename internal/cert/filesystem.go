package cert

import (
	"os"
	"os/user"
	"path/filepath"
)

// GetLogsDir returns the directory used to persist per-log-server resume
// state, creating it if necessary.
func GetLogsDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, "certwatch", "logs"), nil
}

// CheckLogsFolder ensures the logs directory returned by GetLogsDir exists.
func CheckLogsFolder() error {
	dir, err := GetLogsDir()
	if err != nil {
		return err
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0700)
	}
	return nil
}

// WriteLogState persists the last processed index for a log server so a
// later run can resume from it.
func WriteLogState(logstate LogState) error {
	filename, err := logserverFilename(logstate)
	if err != nil {
		return err
	}
	return writeJSONFile(filename, logstate, 0600)
}

// ReadLogState reads back the last persisted state for a log server. If no
// state has been saved yet, it returns the zero-valued input state.
func ReadLogState(logstate LogState) (LogState, error) {
	filename, err := logserverFilename(logstate)
	if err != nil {
		return logstate, err
	}

	var saved LogState
	if err := readJSONFile(filename, &saved); err != nil {
		return logstate, err
	}
	return saved, nil
}

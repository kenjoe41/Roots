package cert

import (
	"os"
	"os/user"
	"path/filepath"
)

func GetLogsDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, "certwatch/logs/"), nil

}

func CheckLogsFolder() error {

	path, err := GetLogsDir()
	if err != nil {
		return err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.MkdirAll(path, 0700)
		return err
	}
	return nil
}

func WriteLogState(logstate LogState) {
	cleanLogFileName := logserverFilename(logstate)
	err := writeJSONFile(cleanLogFileName, logstate, 0777)
	if err != nil {
		return
	}
}

func ReadLogState(logstate LogState) (LogState, error) {
	cleanLogFileName := logserverFilename(logstate)
	lgstate, err := readJSONFile(cleanLogFileName, logstate)
	if err != nil {
		// lets return the logstate tself to lessen the headache.
		return logstate, err
	}
	// Type Assertion, interface to struct. https://go.dev/ref/spec#Type_assertions
	return lgstate.(LogState), nil

}

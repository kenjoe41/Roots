package cert

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

func logserverFilename(logstate LogState) string {
	cleanFilename := strings.Replace(strings.Replace(strings.Replace(logstate.LogServer, "://", "_", 1), "/", "_", -1), ".", "_", -1)
	return path.Join(cleanFilename, ".json")

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

func readJSONFile(filename string, obj interface{}) (interface{}, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(bytes, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

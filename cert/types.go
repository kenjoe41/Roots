package cert

type LogEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type CertEntries struct {
	LogEntry []LogEntry `json:"entries"`
}

type LogState struct {
	LogServer   string
	LogEndIndex uint64
}

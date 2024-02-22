// Copyright 2023 The MathWorks, Inc.
package json

import (
	"encoding/json"
	"io"
)

// Write a generic struct to JSON
func WriteJSONFile[T any](writer io.Writer, content *T) error {
	encoder := json.NewEncoder(writer)
	err := encoder.Encode(content)
	if err != nil {
		return err
	}
	return nil
}

// Read a JSON file into a generic struct
func ReadJSONFile[T any](reader io.Reader) (*T, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	var content T
	err = json.Unmarshal(data, &content)
	return &content, err
}

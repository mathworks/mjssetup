// Copyright 2025 The MathWorks, Inc.
// Implementation of functions for reading and writing to files.
package filehandler

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type OsFileHandler struct{}

func (f *OsFileHandler) ReadFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening input file: %v", err)
	}
	defer file.Close()
	return io.ReadAll(file)
}

func (f *OsFileHandler) WriteJSON(filename string, objToWrite any) error {
	file, err := openFileForWrite(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	err = encoder.Encode(objToWrite)
	if err != nil {
		return fmt.Errorf("error encoding JSON: %v", err)
	}
	return nil
}

func (f *OsFileHandler) WriteText(filename string, txt string) error {
	file, err := openFileForWrite(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.WriteString(file, txt)
	return err
}

func (f *OsFileHandler) EnsureDirExists(dirname string) error {
	return os.MkdirAll(dirname, os.ModePerm)
}

func (f *OsFileHandler) GetCwd() (string, error) {
	return os.Getwd()
}

func openFileForWrite(filename string) (io.WriteCloser, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening output file: %v", err)
	}
	return file, nil
}

// Copyright 2023-2025 The MathWorks, Inc.
package main

import (
	"fmt"
	"os"

	"github.com/mathworks/mjssetup/internal/commands"
	"github.com/mathworks/mjssetup/internal/filehandler"
	"github.com/mathworks/mjssetup/internal/filekeytool"
	"github.com/mathworks/mjssetup/pkg/certificate"
)

func main() {
	keyTool := filekeytool.New(&filehandler.OsFileHandler{}, certificate.New())
	err := commands.NewCommandRunner(keyTool, &stdoutWriter{}).RunCommand(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type stdoutWriter struct{}

func (w *stdoutWriter) WriteString(s string) {
	fmt.Print(s)
}

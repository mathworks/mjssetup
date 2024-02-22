// Copyright 2023 The MathWorks, Inc.
package main

import (
	"fmt"
	"github.com/mathworks/mjssetup/internal/commands"
	"os"
)

func main() {
	cmdFunc, err := commands.NewCommandGetter().GetCommandFunc(os.Args[1:])
	if err != nil {
		errorAndExit(err)
	}

	err = cmdFunc()
	if err != nil {
		errorAndExit(err)
	}
}

func errorAndExit(err error) {
	fmt.Println(err)
	os.Exit(1)
}

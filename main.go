package main

import (
	"fmt"
	"os"

	"ProgWI/cli"
	"ProgWI/tui"
)

/**
* Start the application
*/
func main() {
	// if no command-line arguments are provided, start the TUI application
	if len(os.Args) == 1 {
		tui.CreateNewApplication()
	} else {
		// use the CLI
		fmt.Println("Polite Wifi\n")
		cli.ParseCLIArguments()
	}
}

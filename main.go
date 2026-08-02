package main

import (
	"fmt"
	"os"

	"github.com/Diniboy1123/usque/cmd"
	"github.com/Diniboy1123/usque/internal"
)

func main() {
	internal.EnableSpeculationMitigation()
	if err := cmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

package main

import (
	"fmt"
	"github.com/jayjaytrn/gophkeeper/internal/client"
	"log"
	"os"
)

var (
	buildVersion string
	buildDate    string
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: gk [register|login|save|get|list]")
		return
	}

	switch os.Args[1] {
	case "register":
		client.Register()
	case "login":
		client.Login()
	case "save":
		client.SaveData()
	case "get":
		if len(os.Args) < 3 {
			fmt.Println("Usage: get <id>")
			return
		}
		client.GetDataByID(os.Args[2])
	case "list":
		client.ListData()
	case "version":
		fmt.Printf("Version: %s\nBuild date: %s",
			buildVersion, buildDate)
	default:
		log.Fatalf("Unknown command: %s", os.Args[1])
	}
}

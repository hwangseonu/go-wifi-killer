package ui

import (
	"fmt"
	"github.com/manifoldco/promptui"
	"log"
	"net"
)

func ShowMainMenu() {
	fmt.Printf("\033[2J") //Clear terminal
	fmt.Printf("\033[1;1H") //Goto 1, 1 of terminal
	for {
		menu := []string{"Scan AP", "Print AP list", "Select AP", "Exit"}
		prompt := promptui.Select{Label: "Select Menu", Items: menu}
		i, _, err := prompt.Run()
		if err != nil {
			log.Fatal(err)
		}
		switch i {
		case 0:
			scanAP()
			break
		case 1:
			printAPList()
			break
		case 2:
			ShowAPMenu()
			break
		case 3:
			println("Bye")
			return
		}
	}
}

func scanAP() {
	stop := make(chan struct{})
	apSniffer.APList = make(map[string][]net.HardwareAddr)
	go apSniffer.Sniff()
	go printAll("Press the Enter to stop scan ap", apSniffer, stop)
	println("Press the Enter to stop scan ap")
	pause(stop, apSniffer.Stop)
}

func printAPList() {
	fmt.Printf("\033[2J")   //Clear terminal
	fmt.Printf("\033[1;1H") //Goto 1, 1 of terminal
	apSniffer.Print()
	println("Press the Enter to next step")
	pause()
}


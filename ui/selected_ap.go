package ui

import (
	"fmt"
	"github.com/hwangseonu/wifi-killer/sniffer"
	"github.com/manifoldco/promptui"
	"log"
	"net"
)

func ShowAPMenu() {
	ap := selectAP()
	except, err := net.InterfaceByName(selectInterface("Select Interface to use internet"))
	if err != nil {
		log.Fatal(err)
	}
	dataSniffer = sniffer.NewDataSniffer(iface, except.HardwareAddr, apSniffer.APList[ap])

	menu := []string{"Print Targets BssID", "Exit"}
	prompt := promptui.Select{Label: "Select Menu", Items: menu}

	for {
		i, _, err := prompt.Run()
		if err != nil {
			log.Fatal(err)
		}
		switch i {
		case 0:
			printBssID()
			break
		case 1:
			return
		}
	}
}

func selectAP() string {
	items := make([]string, 0)
	for k := range apSniffer.APList {
		items = append(items, k)
	}
	prompt := promptui.Select{Label: "Select AP", Items: items}
	_, i, err := prompt.Run()
	if err != nil {
		log.Fatal(err)
	}
	return i
}

func printBssID() {
	fmt.Printf("\033[2J") //Clear terminal
	fmt.Printf("\033[1;1H") //Goto 1, 1 of terminal
	for i, v := range dataSniffer.Targets {
		fmt.Printf("%d. %s\n", i+1, v.String())
		pause("Press the Enter to next step")
	}
}
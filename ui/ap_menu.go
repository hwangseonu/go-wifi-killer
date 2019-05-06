package ui

import (
	"fmt"
	"github.com/hwangseonu/wifi-killer/sniffer"
	"github.com/manifoldco/promptui"
	"log"
	"net"
)

func ShowAPMenu() {
	fmt.Printf("\033[2J") //Clear terminal
	fmt.Printf("\033[1;1H") //Goto 1, 1 of terminal
	ap := selectAP()
	except, err := net.InterfaceByName(selectInterface("Select Interface to use internet"))
	if err != nil {
		log.Fatal(err)
	}
	dataSniffer = sniffer.NewDataSniffer(iface, except.HardwareAddr, apSniffer.APList[ap])

	menu := []string{"Print Targets BssID", "Sniff Data", "Remove All Data", "Send Deauth", "Exit"}
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
			sniffData()
			break
		case 2:
			removeAllData()
			break
		case 3:
			sendDeauth()
			break
		case 4:
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
	}
	println("Press the Enter to next step")
	pause()
}

func sniffData() {
	stop := make(chan struct{})
	go dataSniffer.Sniff()
	go printAll("Press the Enter to stop sniff data", dataSniffer, stop)
	println("Press the Enter to stop sniff data")
	pause(stop, dataSniffer.StopSniff)
}

func removeAllData() {
	dataSniffer.Sniffed = make(map[string][]net.HardwareAddr)
	println("removed all data")
	println("Press the Enter to next step")
	pause()
}

func sendDeauth() {
	go dataSniffer.Sniff()
	println("Press the Enter to stop send deauth")
	pause(dataSniffer.StopDeauth)
}
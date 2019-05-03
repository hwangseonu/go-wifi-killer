package ui

import (
	"fmt"
	"github.com/hwangseonu/wifi-killer/sniffer"
	"github.com/manifoldco/promptui"
	"log"
	"net"
)

var iface string
var s *sniffer.APSniffer

func ShowMainMenu() {
	iface = selectNIC("Select Interface to sniff")
	s = sniffer.NewAPSniffer(iface)
	for {
		menu := []string{"Scan AP", "Print AP list", "Exit"}
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
			fmt.Printf("\033[2J") //Clear terminal
			fmt.Printf("\033[1;1H") //Goto 1, 1 of terminal
			s.Print()
			break
		case 2:
			println("Bye")
			return
		}
	}
}

func scanAP() {
	stop := make(chan struct{})
	s.APList = make(map[string][]net.HardwareAddr)
	go s.Sniff()
	go printAll(s, stop)
	pause(stop, s.Stop)
}
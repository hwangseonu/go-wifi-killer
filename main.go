package main

import (
	"fmt"
	"github.com/buger/goterm"
	"github.com/manifoldco/promptui"
	"log"
	"net"
	"os"
	"time"
)

var sniffer *APSniffer

func init() {
	s, err := NewSniffer("en0")
	if err != nil {
		log.Fatal(err)
	}
	sniffer = s
}

func showMenu() {
	prompt := promptui.Select{
		Label: "Choose Menu",
		Items: []string{"Scan AP", "Select AP", "Exit"},
	}
	s, _, err := prompt.Run()
	if err != nil {
		log.Fatal(err)
	}
	switch s {
	case 0:
		sniffer.APList = make(map[string][]net.HardwareAddr)
		scanAP()
		break
	case 1:
		ssid := selectAP()
		if ssid != "" {
			showAPMenu(ssid)
		}
		break
	case 2:
		os.Exit(0)
	}
}

func scanAP() {
	stopPrint := make(chan struct{})
	go sniffer.Sniff()
	go func() {
		for {
			select {
			case <-stopPrint:
				return
			default:
				sniffer.PrintAll()
				time.Sleep(3 * time.Second)
			}
		}
	}()
	wait(stopPrint)
}

func selectAP() string {
	if len(sniffer.APList) == 0 {
		println("No have AP list. scan AP!")
		time.Sleep(3 * time.Second)
		return ""
	}
	l := make([]string, 0)
	for k := range sniffer.APList {
		l = append(l, k)
	}
	prompt := promptui.Select{
		Label: "Select AP",
		Items: l,
	}
	_, s, err := prompt.Run()
	if err != nil {
		log.Fatal(err)
	}
	return s
}

func showAPMenu(ssid string) {
	prompt := promptui.Select{
		Label: "Choose Menu",
		Items: []string{"Print BSSID", "Send Deauth"},
	}
	s, _, err := prompt.Run()
	if err != nil {
		log.Fatal(err)
	}
	switch s {
	case 0:
		ap := sniffer.APList[ssid]
		for _, v := range ap {
			println(v.String())
		}
		fmt.Println("Press the Enter Key to Next Step")
		_, _ = fmt.Scanln()
		break
	}
}

func wait(stop chan struct{}) {
	fmt.Println("Press the Enter Key to Stop Sniff!")
	_, _ = fmt.Scanln()
	sniffer.Stop <- struct{}{}
	stop <- struct{}{}
	return
}

func main() {
	for {
		goterm.Clear()
		goterm.MoveCursor(1,1)
		showMenu()
		goterm.Flush()
	}
}

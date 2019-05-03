package ui

import (
	"fmt"
	"github.com/buger/goterm"
	"github.com/hwangseonu/wifi-killer/sniffer"
	"github.com/manifoldco/promptui"
	"log"
	"net"
	"time"
)

func printAll(s sniffer.Sniffer, stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
			fmt.Printf("\033[2J") //Clear terminal
			fmt.Printf("\033[1;1H") //Goto 1, 1 of terminal
			s.Print()
			print("Press the Enter key to stop scan ap!")
			time.Sleep(3 * time.Second)
		}
	}
}

func pause(ch ...chan struct{}) {
	_, _ = fmt.Scanln()
	for _, c := range ch {
		c <- struct{}{}
	}
	goterm.Clear()
}

func selectNIC(msg string) string {
	items := make([]string, 0)
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range ifaces {
		items = append(items, v.Name)
	}
	prompt := promptui.Select{Label: msg, Items: items}
	_, s, err := prompt.Run()
	if err != nil {
		log.Fatal(err)
	}
	return s
}
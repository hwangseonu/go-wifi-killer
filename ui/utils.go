package ui

import (
	"fmt"
	"github.com/hwangseonu/wifi-killer/sniffer"
	"github.com/manifoldco/promptui"
	"log"
	"net"
	"time"
)

func printAll(msg string, s sniffer.Sniffer, stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
			fmt.Printf("\033[2J") //Clear terminal
			fmt.Printf("\033[1;1H") //Goto 1, 1 of terminal
			s.Print()
			println(msg)
			time.Sleep(3 * time.Second)
		}
	}
}

func pause(ch ...chan struct{}) {
	_, _ = fmt.Scanln()
	for _, c := range ch {
		c <- struct{}{}
	}
	fmt.Printf("\033[2J") //Clear terminal
	fmt.Printf("\033[1;1H") //Goto 1, 1 of terminal
}

func selectInterface(msg string) string {
	items := make([]string, 0)
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range ifaces {
		items = append(items, v.Name)
	}
	prompt := promptui.Select{Label: msg, Items: items}
	_, i, err := prompt.Run()
	if err != nil {
		log.Fatal(err)
	}
	return i
}
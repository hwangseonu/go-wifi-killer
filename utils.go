package main

import (
	"fmt"
	"github.com/buger/goterm"
	"github.com/hwangseonu/wifi-killer/sniffer"
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
package main

import (
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

type FrameDirection int

const (
	TO_AP   = FrameDirection(1)
	FROM_AP = FrameDirection(2)
	OTHER   = FrameDirection(3)
)

func contains(b []net.HardwareAddr, bssid net.HardwareAddr) bool {
	for _, v := range b {
		if v.String() == bssid.String() {
			return true
		}
	}
	return false
}

func newHandle(iface string) (*pcap.Handle, error) {
	ih, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	err = ih.SetPromisc(true)
	if err != nil {
		return nil, err
	}
	err = ih.SetRFMon(true)
	if err != nil {
		return nil, err
	}
	return ih.Activate()
}

func getFrameDirection(dot11 *layers.Dot11) FrameDirection {
	if dot11.Flags.ToDS() && !dot11.Flags.FromDS() {
		return TO_AP
	} else if !dot11.Flags.ToDS() && dot11.Flags.FromDS() {
		return FROM_AP
	} else {
		return OTHER
	}
 }

func wait(stop chan struct{}) {
	fmt.Println("Press the Enter Key to Stop Sniff!")
	_, _ = fmt.Scanln()
	apSniffer.Stop <- struct{}{}
	stop <- struct{}{}
	return
}
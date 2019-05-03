package sniffer

import (
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

func newHandle(iface string, promisc, rfmon bool) (*pcap.Handle, error) {
	ih, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	err = ih.SetPromisc(promisc)
	if err != nil {
		return nil, err
	}
	err = ih.SetRFMon(rfmon)
	if err != nil {
		return nil, err
	}
	return ih.Activate()
}

func contains(list []net.HardwareAddr, addr net.HardwareAddr) bool {
	for _, v := range list {
		if v.String() == addr.String() {
			return true
		}
	}
	return false
}

func channelToMhz(ch int) layers.RadioTapChannelFrequency {
	return layers.RadioTapChannelFrequency(2407 + (ch * 5))
}

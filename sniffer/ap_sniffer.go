package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

type APSniffer struct {
	APList map[string][]net.HardwareAddr
	iface  string
	Stop   chan struct{}
}

func NewAPSniffer(iface string) *APSniffer {
	return &APSniffer{
		APList: make(map[string][]net.HardwareAddr),
		iface:  iface,
		Stop:   make(chan struct{}),
	}
}

func (s *APSniffer) Sniff() error {
	h, err := newHandle(s.iface, true, true)
	if err != nil {
		return err
	}
	defer h.Close()
	err = h.SetBPFFilter("type mgt subtype beacon")
	if err != nil {
		return err
	}
	s.handle(h)
	return nil
}

func (s *APSniffer) handle(handle *pcap.Handle) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	pk := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-s.Stop:
			return
		case packet = <-pk:
			s.handlePacket(packet)
		}
	}
}

func (s *APSniffer) handlePacket(packet gopacket.Packet) {
	fail := packet.Layer(gopacket.LayerTypeDecodeFailure)
	if fail != nil {
		return
	}
	dot11layer := packet.Layer(layers.LayerTypeDot11)
	if dot11layer == nil {
		return
	}
	dot11 := dot11layer.(*layers.Dot11)
	if !dot11.Flags.FromDS() && !dot11.Flags.ToDS() {
		beaconLayer := packet.Layer(layers.LayerTypeDot11MgmtBeacon)
		if beaconLayer == nil {
			return
		}
		infoLayer := packet.Layer(layers.LayerTypeDot11InformationElement)
		if infoLayer == nil {
			return
		}
		info := infoLayer.(*layers.Dot11InformationElement)
		if info.ID == 0 {
			ssid := string(info.Info)
			addr := dot11.Address2
			if !contains(s.APList[ssid], addr) {
				s.APList[ssid] = append(s.APList[ssid], addr)
			}
		}
	}
}

func (s *APSniffer) Print() {
	i := 1
	for k, v := range s.APList {
		fmt.Printf("%d. SSID: %s, AP_COUNT: %d\n", i, k, len(v))
		i++
	}
}
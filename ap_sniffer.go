package main

import (
	"errors"
	"github.com/buger/goterm"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

type APSniffer struct {
	iface  string
	handle *pcap.Handle
	Stop   chan struct{}
	APList map[string][]net.HardwareAddr
}

func (s APSniffer) newHandle() (*pcap.Handle, error) {
	ih, err := pcap.NewInactiveHandle(s.iface)
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

func NewSniffer(iface string) (*APSniffer, error) {
	s := &APSniffer{
		iface:  iface,
		APList: make(map[string][]net.HardwareAddr),
	}
	h, err := s.newHandle()
	if err != nil {
		return nil, err
	}
	err = h.SetBPFFilter("type mgt subtype beacon")
	if err != nil {
		return nil, err
	}
	s.handle = h

	stop := make(chan struct{})
	s.Stop = stop
	return s, nil
}

func (s *APSniffer) Sniff() error {
	if s.handle == nil {
		return errors.New("handle is nil")
	}
	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for {
		var packet gopacket.Packet
		select {
		case <-s.Stop:
			return nil
		case packet = <-src.Packets():
			s.handlePacket(packet)
		}
	}
}

func (s *APSniffer) PrintAll() {
	goterm.Clear()
	goterm.MoveCursor(1, 1)
	i := 1
	for k, v := range s.APList {
		_, _ = goterm.Printf("%d. SSID: %s, AP_LEN: %d\n", i, k, len(v))
		goterm.Flush()
		i++
	}
}

func (s *APSniffer) handlePacket(packet gopacket.Packet) {
	fail := packet.Layer(gopacket.LayerTypeDecodeFailure)
	if fail != nil {
		return
	}
	dot11l := packet.Layer(layers.LayerTypeDot11)
	if dot11l == nil {
		return
	}
	dot11 := dot11l.(*layers.Dot11)
	if !dot11.Flags.ToDS() && !dot11.Flags.FromDS() {
		beaconl := packet.Layer(layers.LayerTypeDot11MgmtBeacon)
		if beaconl == nil {
			return
		}
		addr := dot11.Address2
		infol := packet.Layer(layers.LayerTypeDot11InformationElement)
		if infol == nil {
			return
		}
		info := infol.(*layers.Dot11InformationElement)
		if info.ID != 0 {
			return
		}
		ssid := string(info.Info)
		if ssid == "" {
			return
		}
		l, ex := s.APList[ssid]
		if ex {
			if contains(l, addr) {
				return
			}
			l = append(l, addr)
		} else {
			l = []net.HardwareAddr{addr}
		}
		s.APList[ssid] = l
	}
}

func contains(b []net.HardwareAddr, bssid net.HardwareAddr) bool {
	for _, v := range b {
		if v.String() == bssid.String() {
			return true
		}
	}
	return false
}

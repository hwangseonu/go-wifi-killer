package main

import (
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

type DataSniffer struct {
	iface   string
	myMac   net.HardwareAddr
	bssid   net.HardwareAddr
	handle  *pcap.Handle
	Targets []net.HardwareAddr
	Stop    chan struct{}
}

func NewDataSniffer(iface string, myMac net.HardwareAddr, bssid net.HardwareAddr) (*DataSniffer, error) {
	s := &DataSniffer{
		iface:   iface,
		myMac:   myMac,
		bssid:   bssid,
		Targets: make([]net.HardwareAddr, 0),
	}
	h, err := newHandle(s.iface)
	if err != nil {
		return nil, err
	}
	err = h.SetBPFFilter("type data subtype data")
	if err != nil {
		return nil, err
	}
	s.handle = h
	return s, nil
}

func (s *DataSniffer) Sniff() error {
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

func (s *DataSniffer) handlePacket(packet gopacket.Packet) {
	fail := packet.Layer(gopacket.LayerTypeDecodeFailure)
	if fail != nil {
		return
	}
	dot11l := packet.Layer(layers.LayerTypeDot11)
	if dot11l == nil {
		return
	}
	dot11 := dot11l.(*layers.Dot11)
	datal := packet.Layer(layers.LayerTypeDot11Data)
	if datal == nil {
		return
	}
	fd := getFrameDirection(dot11)

	switch fd {
	case TO_AP:
		if dot11.Address2.String() != s.myMac.String() && contains(s.Targets, dot11.Address2){
			s.Targets = append(s.Targets, dot11.Address2)
		}
		if dot11.Address3.String() != s.myMac.String() && contains(s.Targets, dot11.Address3){
			s.Targets = append(s.Targets, dot11.Address3)
		}
		break
	case FROM_AP:
		if dot11.Address1.String() != s.myMac.String() && contains(s.Targets, dot11.Address1){
			s.Targets = append(s.Targets, dot11.Address1)
		}
		if dot11.Address3.String() != s.myMac.String() && contains(s.Targets, dot11.Address3){
			s.Targets = append(s.Targets, dot11.Address3)
		}
		break
	}
}

func (s *DataSniffer) isTargetAssociated(d FrameDirection, dot11 *layers.Dot11, packet gopacket.Packet) bool {
	switch d {
	case TO_AP:
		return dot11.Address1.String() == s.bssid.String()
	case FROM_AP:
		return dot11.Address2.String() == s.bssid.String()
	default:
		return false
	}
}

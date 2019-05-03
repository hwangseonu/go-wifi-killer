package sniffer

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

type DataSniffer struct {
	Sniffed map[string][]net.HardwareAddr
	Targets []net.HardwareAddr
	Stop    chan struct{}
	iface   string
	myMac   net.HardwareAddr
}

func NewDataSniffer(iface string, my net.HardwareAddr, targets []net.HardwareAddr) *DataSniffer {
	return &DataSniffer{
		Sniffed: make(map[string][]net.HardwareAddr),
		Targets: targets,
		Stop:    make(chan struct{}),
		iface:   iface,
		myMac:   my,
	}
}

func (s *DataSniffer) Sniff() error {
	h, err := newHandle(s.iface, true, true)
	if err != nil {
		return err
	}
	defer h.Close()
	err = h.SetBPFFilter("type data subtype data")
	if err != nil {
		return err
	}
	s.handle(h)
	return nil
}

func (s *DataSniffer) handle(handle *pcap.Handle) {
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

func (s *DataSniffer) handlePacket(packet gopacket.Packet) {
	fail := packet.Layer(gopacket.LayerTypeDecodeFailure)
	if fail != nil {
		return
	}
	dot11layer := packet.Layer(layers.LayerTypeDot11)
	if dot11layer == nil {
		return
	}
	dot11 := dot11layer.(*layers.Dot11)
	dataLayer := packet.Layer(layers.LayerTypeDot11Data)
	if dataLayer == nil {
		return
	}
	fd := getFrameDirection(dot11)
	for _, bssid := range s.Targets {
		str := bssid.String()
		if !isTargetAssociated(fd, bssid.String(), dot11) {
			continue
		}
		switch fd {
		case ToAp:
			if dot11.Address2.String() != s.myMac.String() && !contains(s.Sniffed[str], dot11.Address2) {
				s.Sniffed[str] = append(s.Sniffed[str], dot11.Address2)
			}
			if dot11.Address3.String() != s.myMac.String() && !contains(s.Sniffed[str], dot11.Address3) {
				s.Sniffed[str] = append(s.Sniffed[str], dot11.Address3)
			}
			break
		case FromAp:
			if dot11.Address1.String() != s.myMac.String() && !contains(s.Sniffed[str], dot11.Address1) {
				s.Sniffed[str] = append(s.Sniffed[str], dot11.Address1)
			}
			if dot11.Address3.String() != s.myMac.String() && !contains(s.Sniffed[str], dot11.Address3) {
				s.Sniffed[str] = append(s.Sniffed[str], dot11.Address3)
			}
			break
		}
	}
}

func (s *DataSniffer) Print() {
	i := 1
	for k, sniffed := range s.Sniffed {
		fmt.Printf("%d. BSSID: %s\n", i, k)
		i++
		for _, v := range sniffed {
			fmt.Printf("\t%s\n", v)
		}
		println()
	}
}

type FrameDirection uint8

const (
	ToAp   = FrameDirection(1)
	FromAp = FrameDirection(2)
	Other  = FrameDirection(3)
)

func isTargetAssociated(d FrameDirection, bssid string, dot11 *layers.Dot11, ) bool {
	switch d {
	case ToAp:
		return dot11.Address1.String() == bssid
	case FromAp:
		return dot11.Address2.String() == bssid
	default:
		return false
	}
}

func getFrameDirection(dot11 *layers.Dot11) FrameDirection {
	switch {
	case dot11.Flags.ToDS() && !dot11.Flags.FromDS():
		return ToAp
	case !dot11.Flags.ToDS() && dot11.Flags.FromDS():
		return FromAp
	default:
		return Other
	}
}

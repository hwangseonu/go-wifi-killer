package sniffer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
)

type DataSniffer struct {
	Data    map[string]net.HardwareAddr
	Targets []net.HardwareAddr
	iface   string
}

func NewDataSniffer(iface string, targets []net.HardwareAddr) *DataSniffer {
	return &DataSniffer{
		Data:    make(map[string]net.HardwareAddr, 0),
		Targets: targets,
		iface:   iface,
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
		if !isTargetAssociated(fd, bssid.String(), dot11) {
			continue
		}
		switch fd {
		case ToAp:
			//TODO
			break
		case FromAp:
			//TODO
			break
		}
	}
}

func isTargetAssociated(d FrameDirection, bssid string, dot11 *layers.Dot11,) bool {
	switch d {
	case ToAp:
		return dot11.Address1.String() == bssid
	case FromAp:
		return dot11.Address2.String() == bssid
	default:
		return false
	}
}

const (
	ToAp   = FrameDirection(1)
	FromAp = FrameDirection(2)
	Other  = FrameDirection(3)
)

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

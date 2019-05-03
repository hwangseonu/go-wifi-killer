package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"hash/crc32"
	"net"
	"testing"
)

func TestRadioTap(t *testing.T) {
	data := makePacket()
	pk := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)
	for _, v := range pk.Layers() {
		println(v.LayerType().String())
	}
	dump(data)
}

func dump(b []byte) {
	for i, v := range b {
		fmt.Printf("%02X ", v)
		if (i+1)%8 == 0 {
			print(" ")
		}
		if (i+1)%16 == 0 {
			println()
		}
	}
	println()
}

func makePacket() []byte {
	radio := RadioTap()
	dot11 := Dot11()
	deauth := Dot11Deauth()
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

func RadioTap() []byte {
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

func Dot11() []byte {
	dot11 := layers.Dot11{}
	dot11.Type = layers.Dot11TypeMgmtDeauthentication
	dot11.Address1 = hwAddr(0xaa)
	dot11.Address2 = hwAddr(0xbb)
	dot11.Address3 = hwAddr(0xcc)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, &dot11)
	return buf.Bytes()
}

func Dot11Deauth() []byte {
	deauth := layers.Dot11MgmtDeauthentication{}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, &deauth)
	return buf.Bytes()
}

func hwAddr(d uint8) net.HardwareAddr {
	return net.HardwareAddr{d, d, d, d, d, d}
}

func channelToMhz(ch int) layers.RadioTapChannelFrequency {
	return layers.RadioTapChannelFrequency(2407 + (ch * 5))
}


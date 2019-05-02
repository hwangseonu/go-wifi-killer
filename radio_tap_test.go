package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, &radio, &dot11)
	return buf.Bytes()
}

func RadioTap() layers.RadioTap {
	radio := layers.RadioTap{}
	radio.Present = 0x482b
	radio.Flags = 0x10
	radio.ChannelFrequency = channelToMhz(1)
	radio.ChannelFlags = layers.RadioTapChannelFlags(0xa0)
	radio.DBMAntennaSignal = -50
	return radio
}


func Dot11() layers.Dot11 {


	dot11 := layers.Dot11{}
	dot11.Type = layers.Dot11TypeMgmtDeauthentication
	dot11.Address1 = hwAddr(0xaa)
	dot11.Address2 = hwAddr(0xbb)
	dot11.Address3 = hwAddr(0xcc)
	return dot11
}

func hwAddr(d uint8) net.HardwareAddr {
	return net.HardwareAddr{d, d, d, d, d, d}
}

func channelToMhz(ch int) layers.RadioTapChannelFrequency {
	return layers.RadioTapChannelFrequency(2407 + (ch * 5))
}


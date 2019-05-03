package ui

import (
	"github.com/hwangseonu/wifi-killer/sniffer"
)

var iface string
var apSniffer *sniffer.APSniffer
var dataSniffer *sniffer.DataSniffer

func init() {
	iface = selectInterface("Select Interface to sniff")
	apSniffer = sniffer.NewAPSniffer(iface)
}

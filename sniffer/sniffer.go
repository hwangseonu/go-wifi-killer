package sniffer

type Sniffer interface {
	Sniff() error
	Print()
}

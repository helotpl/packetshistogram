package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

type counts struct {
	ip        uint64
	nonip     uint64
	tcp       uint64
	udp       uint64
	nontcpudp uint64
	all       uint64
	sizeHist  map[int]uint64
}

func (c *counts) print() {
	fmt.Printf("%d,%d,%d,%d,%d,%d", c.ip, c.nonip, c.tcp, c.udp, c.nontcpudp, c.all)
	for i := 0; i < 16; i++ {
		fmt.Printf(",%d", c.sizeHist[i])
	}
	fmt.Println("")
}

func (c *counts) printt(t time.Time) {
	fmt.Printf("%v,", t)
	c.print()
}

func doEvery(d time.Duration, f func(time.Time)) {
	for x := range time.Tick(d) {
		f(x)
	}
}

func main() {
	var eth layers.Ethernet
	var udp layers.UDP
	var tcp layers.TCP
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &udp, &tcp, &ip4, &ip6)
	decoded := make([]gopacket.LayerType, 0, 5)

	intf := flag.String("int", "en0", "name of interface to capture packets")
	flag.Parse()

	fmt.Println(*intf)

	handle, err := pcap.OpenLive(*intf, 262144, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	counter := counts{}
	counter.sizeHist = make(map[int]uint64)
	doEvery(1000*time.Millisecond, counter.printt)
	parser.IgnoreUnsupported = true
	for {
		packet, err := source.NextPacket()
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Println(len(packet.Data()))
		counter.sizeHist[len(packet.Data())/100] += 1
		err = parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			log.Fatal(err)
		}

		tcp := false
		udp := false
		ip := false

		for _, l := range decoded {
			switch l {
			case layers.LayerTypeUDP:
				udp = true
			case layers.LayerTypeTCP:
				tcp = true
			case layers.LayerTypeIPv4:
				ip = true
			case layers.LayerTypeIPv6:
				ip = true
			}
		}
		if tcp {
			counter.tcp += 1
		}
		if udp {
			counter.udp += 1
		}
		if !tcp && !udp {
			counter.nontcpudp += 1
		}
		if ip {
			counter.ip += 1
		} else {
			counter.nonip += 1
		}
		counter.all += 1

		//counter.print()
	}
	//for packetData := range source.Packets() {
	//	if err := parser.DecodeLayers(packetData, &decoded); err != nil {
	//
	//	}
	//}
}

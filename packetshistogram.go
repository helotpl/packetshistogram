package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"sync"
	"time"
)

type counts struct {
	mu          sync.Mutex
	ip          uint64
	nonip       uint64
	tcp         uint64
	udp         uint64
	nontcpudp   uint64
	all         uint64
	sizeHistTCP map[int]uint64
	sizeHistUDP map[int]uint64
}

func (c *counts) print() {
	fmt.Printf("%d,%d,%d,%d,%d,%d", c.ip, c.nonip, c.tcp, c.udp, c.nontcpudp, c.all)
	for i := 0; i < 16; i++ {
		fmt.Printf(",%d", c.sizeHistTCP[i])
	}
	for i := 0; i < 16; i++ {
		fmt.Printf(",%d", c.sizeHistUDP[i])
	}
	fmt.Println("")
}

func (c *counts) clear() {
	c.ip = 0
	c.nonip = 0
	c.tcp = 0
	c.udp = 0
	c.nontcpudp = 0
	c.all = 0
	c.sizeHistUDP = make(map[int]uint64)
	c.sizeHistTCP = make(map[int]uint64)
}

func (c *counts) printt(t time.Time) {
	fmt.Printf("%v,", t)
	c.print()
}

func doEvery(d time.Duration, c *counts) {
	for x := range time.Tick(d) {
		c.mu.Lock()
		c.printt(x)
		c.clear()
		c.mu.Unlock()
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
	duration := flag.Int("dur", 5, "time in seconds between dumps of stats")
	volume := flag.Bool("v", false, "when set than program counts sum sizes of packets, unset = counts of packets")
	flag.Parse()

	handle, err := pcap.OpenLive(*intf, 262144, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Print("time,ip,nonip,tcp,udp,nontcpudp,all")
	for i := 0; i < 16; i++ {
		if *volume {
			fmt.Printf(",vt%d", i)

		} else {
			fmt.Printf(",t%d", i)
		}
	}
	for i := 0; i < 16; i++ {
		if *volume {
			fmt.Printf(",vu%d", i)
		} else {
			fmt.Printf(",u%d", i)
		}
	}
	fmt.Println("")

	counter := counts{}
	counter.clear()
	go doEvery(1000*time.Duration(*duration)*time.Millisecond, &counter)
	parser.IgnoreUnsupported = true
	parser.IgnorePanic = true
	for {
		packet, err := source.NextPacket()
		if err != nil {
			log.Fatal(err)
		}
		pktSize := len(packet.Data())
		histSize := pktSize / 100
		if histSize > 15 {
			histSize = 15
		}
		//counter.sizeHist[len(packet.Data())/100] += 1
		err = parser.DecodeLayers(packet.Data(), &decoded)
		if err != nil {
			continue
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
		counter.mu.Lock()
		if *volume {
			if tcp {
				counter.tcp += uint64(pktSize)
				counter.sizeHistTCP[histSize] += uint64(pktSize)
			}
			if udp {
				counter.udp += uint64(pktSize)
				counter.sizeHistUDP[histSize] += uint64(pktSize)
			}
			if !tcp && !udp {
				counter.nontcpudp += uint64(pktSize)
			}
			if ip {
				counter.ip += uint64(pktSize)
			} else {
				counter.nonip += uint64(pktSize)
			}
			counter.all += uint64(pktSize)
		} else {
			if tcp {
				counter.tcp += 1
				counter.sizeHistTCP[histSize] += 1
			}
			if udp {
				counter.udp += 1
				counter.sizeHistUDP[histSize] += 1
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
		}
		counter.mu.Unlock()
	}
}

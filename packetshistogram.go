package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
)

func main() {
	intf := flag.String("int", "en0", "name of interface to capture packets")
	flag.Parse()

	fmt.Println(*intf)

	handle, err := pcap.OpenLive(*intf, 262144, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}


}

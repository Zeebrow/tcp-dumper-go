package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// https://www.akitasoftware.com/blog-posts/programmatically-analyze-packet-captures-with-gopacket
/*init() works the same as in Arduino code*/
func init() {
	fmt.Println("start")
}

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

type config struct {
	iface string
	port  string
}

func (c *config) doFlags() {
	flag.StringVar(&c.iface, "iface", "lo", "interface to filter by")
	flag.StringVar(&c.port, "port", "8080", "port to filter by")
	flag.Parse()
}

func printTCPFlags(tcp *layers.TCP) {
	/*
					There are 8 bits in the control bits section of the TCP header:
		              CWR | ECE | URG | ACK | PSH | RST | SYN | FIN
	*/
	fmt.Println("Flags:")

	flags := []bool{tcp.CWR, tcp.ECE, tcp.URG, tcp.ACK, tcp.PSH, tcp.RST, tcp.SYN, tcp.FIN}
	fmt.Println(" CWR | ECE | URG | ACK | PSH | RST | SYN | FIN ")
	for i, f := range flags {
		if f {
			fmt.Printf("  1  ")
		} else {
			fmt.Printf("  0  ")
		}
		if i != 7 {
			fmt.Printf("|")
		}
	}
	fmt.Println()
}

func main() {
	cfg := &config{}
	cfg.doFlags()

	pktCount := 0
	iface := cfg.iface
	port := cfg.port

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Printf("%v\n", sig)
			fmt.Printf("%d packets captured\n", pktCount)
			os.Exit(1)
		}
	}()
	handle, err := pcap.OpenLive(iface, defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("port " + port); err != nil {
		panic(err)
	}
	fmt.Printf("capturing with filter:\ninterface '%s'\nport %s\n", iface, port)

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		pktCount++
		// for _, l := range pkt.Layers() {
		// 	fmt.Println(l.LayerType())
		// }
		// Your analysis here!
		// netflow := pkt.NetworkLayer().NetworkFlow()
		// fmt.Printf("%s\n\n\n\n", pkt.NetworkLayer())
		// fmt.Printf("%+v\n\n\n\n", pkt.ErrorLayer())
		// fmt.Printf("%+v\n\n\n\n", pkt.LinkLayer())
		fmt.Printf("packet %d:\n-----------\n", pktCount)
		printNetworkLayerInfo(pkt)
		printTransportLayerInfo(pkt)
		fmt.Println()

		// printTransportLayerInfo(pkt)
		// panic("qwer")
	}
}

func printNetworkLayerInfo(pkt gopacket.Packet) {
	netPacket := gopacket.NewPacket(pkt.NetworkLayer().LayerPayload(), layers.LayerTypeTCP, gopacket.Default)
	if tcpLayer := netPacket.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		// banner := fmt.Sprintf("\n_________________________Network Layer (%s)_____________________________", tcp.LayerType().String())
		// fmt.Println(banner)
		// fmt.Printf("Flags: %+v\n", tcp.Ack)
		printTCPFlags(tcp)
		// fmt.Printf("%s\n", pkt.NetworkLayer().NetworkFlow().String())
		fmt.Printf("Network Layer-Port Flow: %s\n", tcp.TransportFlow().String())
		fmt.Printf("Window: %d\n", tcp.Window)
		fmt.Printf("Data: %d bytes\n", len(tcp.Payload))
		// fmt.Printf("layer dump:\n%+v\n", gopacket.LayerDump(tcpLayer))
	}

}
func printTransportLayerInfo(pkt gopacket.Packet) {
	transportLayerPacket := gopacket.NewPacket(pkt.TransportLayer().LayerContents(), layers.LayerTypeIPv4, gopacket.Default)
	if transportLayer := transportLayerPacket.Layer(layers.LayerTypeIPv4); transportLayer != nil {
		ipv4, _ := transportLayer.(*layers.IPv4)
		// banner := fmt.Sprintf("\n_________________________Transport Layer (%s)_____________________________", ipv4.LayerType().String())
		// fmt.Println(banner)
		// fmt.Printf("Flags: %+v\n", tcp.Ack)

		// fmt.Printf("\tTransport layer IP Flow: %s %s\n", ipv4.LayerType().String(), ipv4.NetworkFlow().String())
		fmt.Printf("\tTransport layer IP Flow: %s %s\n", ipv4.LayerType().String())
		fmt.Printf("\t%sFlags: %03b\n", ipv4.LayerType().String(), ipv4.Flags)
		// fmt.Printf("\tlayer dump:\n%+v\n", gopacket.LayerDump(transportLayer))
	}
}

// Go program to illustrate the
// concept of main() function

// Declaration of the main package
package main

// Importing packages
import (
	"fmt"
	// "strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/**
	1. Process tls for anything that contains apple
	2. Add the ip to map
	3. In another loop filter for TCP packets mapped to ip, source port
	4. Figure out RTT of handshake
**/

type transport_tuple struct {
	srcIP, dstIP string
	srcPort, dstPort uint16
	transport uint8
}


func (t transport_tuple) toString() string {
	return string(t.dstIP) + string(t.srcIP) + fmt.Sprint(t.dstPort) + fmt.Sprint(t.srcPort) + string(t.transport)
}

type Protocols int

const (
    TCP int = 0
    UDP int = 1
    IPV6 int = 2
    IPv4 int = 3
	DNS int = 4
	TLS int = 5
)

func main() {

	// network_map := make(map[string]uint32)
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var tls layers.TLS
	var dns layers.DNS
	decoded := []gopacket.LayerType{}
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &tls, &dns)
	if handle, err := pcap.OpenOffline("apple1.pcapng"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())	
		for packet := range packetSource.Packets() {
			if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
				// fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
				continue
			}
			var data transport_tuple
			for _, layerType := range decoded {
				switch layerType {
					case layers.LayerTypeIPv6:
						data.srcIP = ip6.SrcIP.String()
						data.dstIP =  ip6.DstIP.String()
						data.transport = uint8(IPV6)
					case layers.LayerTypeIPv4:
						data.srcIP = ip4.SrcIP.String()
						data.dstIP =  ip4.DstIP.String()
						data.transport = uint8(IPv4)
					case layers.LayerTypeTCP:
						data.srcPort = uint16(tcp.SrcPort)
						data.dstPort = uint16(tcp.DstPort)
						data.transport = uint8(TCP)
					case layers.LayerTypeUDP:
						data.srcPort = uint16(udp.SrcPort)
						data.dstPort = uint16(udp.DstPort)
						data.transport = uint8(UDP)
					case layers.LayerTypeTLS:
						// 
						// test := string(tls.Contents)
						// if strings.Contains(test, "apple") {
						// 	fmt.Println(test)
						// }
					case layers.LayerTypeDNS:
						test := dns.Answers
						for x := range test {
							d := test[x]
							name := string(d.Name[:])
							switch d.Type {
							case layers.DNSTypeCNAME:
								
							}
							fmt.Println(d.IP, name, d.Type)
						}
				}

				// fmt.Printf("src IP: %s dst IP: %s src port %d dst port %d transport %d \n", data.srcIP, data.dstIP, data.srcPort, data.dstPort, data.transport)
			}	
		}

	}
	// fmt.Println(network_map)
}



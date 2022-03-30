// Go program to illustrate the
// concept of main() function

// Declaration of the main package
package main

// Importing packages
import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

/**

	Data Structure

	{"apple.com" => {"address one" : 200, "address two" : 250 }}

**/

type httpStreamFactory struct{}

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	return &hstream.r
}

func main() {

	network_map := make(map[string]map[string]time.Duration)
	network_map["apple.com"] = make(map[string]time.Duration)
	RTT_map := make(map[string]time.Time)
	// streamFactory := &httpStreamFactory{}
	// streamPool := tcpassembly.NewStreamPool(streamFactory)
	// assembler := tcpassembly.NewAssembler(streamPool)

	if handle, err := pcap.OpenOffline("apple.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			transport_layer := packet.TransportLayer()
			if ipLayer == nil {
				continue
			}
			ip, _ := ipLayer.(*layers.IPv4)
			if ip == nil {
				continue
			}
			source_ip := ip.SrcIP.String()
			destination_ip := ip.DstIP.String()

			// Get the RTT
			println(transport_layer.TransportFlow().String())
			println(source_ip, destination_ip)

			packet_time := packet.Metadata().Timestamp
			if val, ok := RTT_map[destination_ip]; ok {
				elapsed_time := packet_time.Sub(val)
				if strings.Contains(source_ip, "172") {
					network_map["apple.com"][destination_ip] = elapsed_time
				} else {
					network_map["apple.com"][source_ip] = elapsed_time
				}

			} else {
				RTT_map[source_ip] = packet_time
			}
			// tcp := packet.TransportLayer().(*layers.TCP)
			// assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		}
	}
	fmt.Println(network_map)
}

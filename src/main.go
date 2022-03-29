// Go program to illustrate the
// concept of main() function

// Declaration of the main package
package main

// Importing packages
import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

/**

	Data Structure

	{"apple.com" => {"address one" : 200, "address two" : 250 }}

**/

func main() {

	network_map := make(map[string]map[string]float64)
	network_map["apple.com"] = make(map[string]float64)
	if handle, err := pcap.OpenOffline("apple.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			application_layer := packet.ApplicationLayer()
			if application_layer != nil {
				fmt.Println(string(application_layer.Payload()[:]))
			}
		}
	}
	fmt.Println(network_map)
}

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type transport_tuple struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	transport        uint8
	time             time.Time
}

type dns_record struct {
	a_record map[string][]string
	cname    []string
}

/*
	Each TCP flow is identified with 5 unique values
	Forward and reverse method are used
*/
func (t transport_tuple) forwardString() string {
	return string(t.dstIP) + fmt.Sprint(t.dstPort) + string(t.srcIP) + fmt.Sprint(t.srcPort) + string(t.transport)
}

func (t transport_tuple) reverseString() string {
	return string(t.srcIP) + fmt.Sprint(t.srcPort) + string(t.dstIP) + fmt.Sprint(t.dstPort) + string(t.transport)
}

const (
	TCP  int = 0
	UDP  int = 1
	IPV6 int = 2
	IPv4 int = 3
	DNS  int = 4
	TLS  int = 5
)

func main() {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var tls layers.TLS
	var dns layers.DNS
	dns_records := make(map[string]dns_record)
	tcp_rtt := make(map[string]time.Time)
	ip_to_rtt := make(map[string]time.Duration)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &tls, &dns)
	// network_map := make(map[string]uint32)
	decoded := []gopacket.LayerType{}
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
			data.time = packet.Metadata().Timestamp
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeIPv6:
					process_ipv6(&data, &ip6)
				case layers.LayerTypeIPv4:
					process_ipv4(&data, &ip4)
				case layers.LayerTypeTCP:
					process_tcp(&data, &tcp)
					calculate_rtt(&data, dns_records, &tcp, tcp_rtt, ip_to_rtt)
				case layers.LayerTypeUDP:
					process_udp(&data, &udp)
				case layers.LayerTypeDNS:
					process_dns_query(&dns, dns_records)
				}
			}
		}

	}
	format_output(dns_records, ip_to_rtt)
}

func format_output(dns_records map[string]dns_record, tcp_rtt map[string]time.Duration) {
	for v, k := range dns_records {
		fmt.Printf("Query for %s\n", v)
		fmt.Printf("\tA Type responses:\n")
		for name, ips := range k.a_record {
			fmt.Printf("\t\t%s\n", name)
			for i := range ips {
				fmt.Printf("\t\t\t%s\n", ips[i])
			}
		}
		if len(k.cname) != 0 {
			fmt.Printf("\tCNAME responses:\n")
			for i := range k.cname {
				fmt.Printf("\t\t%s\n", k.cname[i])
			}
		}

		if len(k.a_record) != 0 {
			fmt.Printf("\tRound Trip Times:\n")
			for _, ips := range k.a_record {
				for i := range ips {
					if val, ok := tcp_rtt[ips[i]]; ok {
						fmt.Printf("\t\t%s --> ", ips[i])
						fmt.Println(val)

					}
				}
			}
		}
	}
}

func calculate_rtt(data *transport_tuple, records map[string]dns_record, tcp *layers.TCP, tcp_rtt map[string]time.Time, ip_rtt map[string]time.Duration) {
	if is_apple_ip(data, records) {
		switch {
		case tcp.SYN && !tcp.ACK:
			unique_identifier := data.forwardString()
			tcp_rtt[unique_identifier] = data.time
		case tcp.SYN && tcp.ACK:
			unique_identifier := data.reverseString()
			start_time := tcp_rtt[unique_identifier]
			ip_rtt[data.srcIP] = data.time.Sub(start_time)
		}
	}
}

func is_apple_ip(data *transport_tuple, records map[string]dns_record) bool {
	for _, v := range records {
		for _, ip_array := range v.a_record {
			for ip := range ip_array {
				if ip_array[ip] == data.dstIP || ip_array[ip] == data.srcIP {
					return true
				}
			}
		}
	}
	return false
}

func process_dns_query(dns *layers.DNS, dns_records map[string]dns_record) {

	// If the answer is not empty the dns must be a response
	if len(dns.Answers) == 0 {
		return
	}

	for i := range dns.Questions {
		query_url := string(dns.Questions[i].Name[:])
		// Check if the query url is apple related
		var records dns_record
		records.a_record = make(map[string][]string)
		if strings.Contains(query_url, "apple") {
			for i := range dns.Answers {
				answer := string(dns.Answers[i].Name[:])
				switch dns.Answers[i].Type {
				case layers.DNSTypeA:
					address := dns.Answers[i].IP.String()
					records.a_record[answer] = append(records.a_record[answer], address)
				case layers.DNSTypeCNAME:
					records.cname = append(records.cname, answer)
				}
				dns_records[query_url] = records
			}
		}
	}
}

func process_ipv6(data *transport_tuple, ip6 *layers.IPv6) {
	data.srcIP = ip6.SrcIP.String()
	data.dstIP = ip6.DstIP.String()
	data.transport = uint8(IPV6)
}

func process_ipv4(data *transport_tuple, ip4 *layers.IPv4) {
	data.srcIP = ip4.SrcIP.String()
	data.dstIP = ip4.DstIP.String()
	data.transport = uint8(IPv4)
}

func process_tcp(data *transport_tuple, tcp *layers.TCP) {
	data.srcPort = uint16(tcp.SrcPort)
	data.dstPort = uint16(tcp.DstPort)
	data.transport = uint8(TCP)
}

func process_udp(data *transport_tuple, udp *layers.UDP) {
	data.srcPort = uint16(udp.SrcPort)
	data.dstPort = uint16(udp.DstPort)
	data.transport = uint8(UDP)
}

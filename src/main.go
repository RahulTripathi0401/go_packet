package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/olekukonko/tablewriter"
)

type transport_flow struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	transport        uint8
	start_time       time.Time
	last_packet_time time.Time
	down_bytes       int
	down_packets     int
	up_bytes         int
	up_packets       int
	rtt              time.Duration
	// tls_sni_server   string
	dns_name string
}

type dns_record struct {
	a_record map[string][]string
	cname    []string
}

/*
	Each TCP flow is identified with 5 unique values
	Forward and reverse method are used
*/
func (t transport_flow) forwardString() string {
	return string(t.dstIP) + fmt.Sprint(t.dstPort) + string(t.srcIP) + fmt.Sprint(t.srcPort) + string(t.transport)
}

func (t transport_flow) reverseString() string {
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
	// Get Command lin
	domain := flag.String("domain", "apple", "domain name to process")
	file := flag.String("file", "apple1.pcapng", "pcap file")
	flag.Parse()
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var tls layers.TLS
	var dns layers.DNS
	dns_records := make(map[string]dns_record)
	flow_map := make(map[string]transport_flow)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &tls, &dns)
	// network_map := make(map[string]uint32)
	decoded := []gopacket.LayerType{}
	if handle, err := pcap.OpenOffline(*file); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
				continue
			}
			var data transport_flow
			packet_time := packet.Metadata().Timestamp
			length := packet.Metadata().Length
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeIPv6:
					process_ipv6(&data, &ip6)
				case layers.LayerTypeIPv4:
					process_ipv4(&data, &ip4)
				case layers.LayerTypeTCP:
					process_tcp(&data, &tcp)
					if is_valid_ip(&data, dns_records) {
						calculate_rtt(&data, packet_time, &tcp, flow_map, length)
					}
				case layers.LayerTypeUDP:
					process_udp(&data, &udp)
				case layers.LayerTypeDNS:
					process_dns_query(&dns, dns_records, *domain)
				}
			}
		}

	}
	format_output(dns_records, flow_map)
}

func format_output(dns_records map[string]dns_record, flow_map map[string]transport_flow) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Query", "IP", "DNS", "Src Port", "Dst Port",
		"Start Time", "Last Packet Time", "RTT", "Up Bytes",
		"Up packets", "Down Bytes", "Down Packets"})
	var data [][]string

	for _, flow := range flow_map {
		srcPort := strconv.Itoa(int(flow.srcPort))
		dstPort := strconv.Itoa(int(flow.dstPort))
		upBytes := strconv.Itoa(flow.up_bytes)
		upPackets := strconv.Itoa(flow.up_packets)
		downBytes := strconv.Itoa(flow.down_bytes)
		downPackets := strconv.Itoa(flow.down_packets)
		row := []string{flow.dns_name, flow.dstIP, flow.dns_name, srcPort,
			dstPort, flow.start_time.String(), flow.last_packet_time.String(),
			flow.rtt.String(), upBytes, upPackets, downBytes, downPackets,
		}
		data = append(data, row)
	}
	table.AppendBulk(data)
	table.Render()
	table = tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Query", "A Type", "IP", "CNAME"})
	var dns [][]string
	for query, record := range dns_records {
		for key, val := range record.a_record {
			for i := range val {
				row := []string{query, key, val[i], ""}
				dns = append(dns, row)
			}
		}
		for i := range record.cname {
			row := []string{query, "", "", record.cname[i]}
			dns = append(dns, row)
		}
	}
	table.AppendBulk(dns)
	table.Render()

}

func calculate_rtt(data *transport_flow, time time.Time, tcp *layers.TCP, flow_map map[string]transport_flow, length int) {

	client_to_server := data.forwardString()
	server_to_client := data.reverseString()
	if val, ok := flow_map[client_to_server]; ok {
		val.up_packets++
		val.up_bytes += length
		val.last_packet_time = time
		flow_map[client_to_server] = val
	} else if val, ok := flow_map[server_to_client]; ok {
		val.down_packets++
		val.down_bytes += length
		val.last_packet_time = time
		flow_map[server_to_client] = val
	}

	// Cases for TCP handshake and FIN
	switch {
	case tcp.SYN && !tcp.ACK:
		// Signifies the start of a handshake and insert into map
		data.start_time = time
		data.up_packets = 1
		data.up_bytes = length
		flow_map[client_to_server] = *data
	case tcp.SYN && tcp.ACK:
		// Calculate RTT of handshake
		tuple := flow_map[server_to_client]
		tuple.rtt = time.Sub(tuple.start_time)
		flow_map[server_to_client] = tuple
	}
}

func is_valid_ip(data *transport_flow, records map[string]dns_record) bool {
	for _, v := range records {
		for name, ip_array := range v.a_record {
			for ip := range ip_array {
				if ip_array[ip] == data.dstIP || ip_array[ip] == data.srcIP {
					data.dns_name = name
					return true
				}
			}
		}
	}
	return false
}

func process_dns_query(dns *layers.DNS, dns_records map[string]dns_record, domain string) {

	// If the answer is not empty the dns must be a response
	if len(dns.Answers) == 0 {
		return
	}
	for i := range dns.Questions {
		query_url := string(dns.Questions[i].Name[:])
		// Check if the query url is apple related
		var records dns_record
		records.a_record = make(map[string][]string)
		if strings.Contains(query_url, domain) {
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
			// fmt.Println(dns_records)
		}
	}
}

func process_ipv6(data *transport_flow, ip6 *layers.IPv6) {
	data.srcIP = ip6.SrcIP.String()
	data.dstIP = ip6.DstIP.String()
	data.transport = uint8(IPV6)
}

func process_ipv4(data *transport_flow, ip4 *layers.IPv4) {
	data.srcIP = ip4.SrcIP.String()
	data.dstIP = ip4.DstIP.String()
	data.transport = uint8(IPv4)
}

func process_tcp(data *transport_flow, tcp *layers.TCP) {
	data.srcPort = uint16(tcp.SrcPort)
	data.dstPort = uint16(tcp.DstPort)
	data.transport = uint8(TCP)
}

func process_udp(data *transport_flow, udp *layers.UDP) {
	data.srcPort = uint16(udp.SrcPort)
	data.dstPort = uint16(udp.DstPort)
	data.transport = uint8(UDP)
}

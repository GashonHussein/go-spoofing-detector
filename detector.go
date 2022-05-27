/**
 *
 * detector.go
 *
 *  - Open a .pcap file supplied as a command-line argument, and analyze the TCP,
 *    IP, Ethernet, and ARP layers
 *
 *  - Print the IP addresses that: 1) sent more than 3 times as many SYN packets
 *    as the number of SYN+ACK packets they received, and 2) sent more than 5 SYN
 *    packets in total
 *
 *  - Print the MAC addresses that send more than 5 unsolicited ARP replies
 *
 */

package main

import (
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) != 2 {
		panic("Invalid command-line arguments")
	}
	pcapFile := os.Args[1]

	// Attempt to open file
	if handle, err := pcap.OpenOffline(pcapFile); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		// Key = IP address, value = array of 2 ints representing [syn, synack] counts
		addresses := map[string][2]int{}
		// Key = IP address, value = map whose key = MAC address,
		// and value = int.
		// for pairs of (IP address, MAC address).
		arpRequests := map[string]map[string]int{}
		// Key = MAC address, value = int.

		arpMac := map[string]int{}

		// Loop through packets in file
		for packet := range packetSource.Packets() {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			etherLayer := packet.Layer(layers.LayerTypeEthernet)
			arpLayer := packet.Layer(layers.LayerTypeARP)

			incrementCount := func(i int, ip string) {
				arr := addresses[ip]
				if i == 0 {
					addresses[ip] = [2]int{arr[0] + 1, arr[1]}
				} else {
					addresses[ip] = [2]int{arr[0], arr[1] + 1}
				}
			}

			if tcpLayer != nil && ipLayer != nil && etherLayer != nil {

				// obtain the source and destination IP addresses
				tcpData, _ := tcpLayer.(*layers.TCP)
				ipData, _ := ipLayer.(*layers.IPv4)

				srcIp, dstIp := ipData.SrcIP, ipData.DstIP

				if SYN, ACK := tcpData.SYN, tcpData.ACK; SYN && !ACK {
					incrementCount(0, srcIp.String()) // sent SYN
				} else if SYN && ACK {
					incrementCount(1, dstIp.String()) // received SYN ACK
				}

			} else if arpLayer != nil {
				// Use the arp variable to get (IP address, MAC address)

				// Parse arp to get additional info
				arp, _ := arpLayer.(*layers.ARP)
				if arp.Operation == 1 { // ARP request
					srcIP, dstMAC := net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.DstHwAddress)
					if v, ok := arpRequests[srcIP.String()][dstMAC.String()]; ok {
						arpRequests[srcIP.String()][dstMAC.String()] = v + 1
					} else {
						arpRequests[srcIP.String()] = make(map[string]int)
						arpRequests[srcIP.String()][dstMAC.String()] = 1
					}
					arpRequests[srcIP.String()][dstMAC.String()] += 1 // record request
				} else if arp.Operation == 2 { // ARP reply
					dstIP, srcMAC := net.IP(arp.DstProtAddress), net.HardwareAddr(arp.SourceHwAddress)
					if _, ok := arpRequests[dstIP.String()][srcMAC.String()]; !ok { // unsolicited reply
						arpMac[srcMAC.String()] += 1 // update num offenses
					}
				}
			}
		}
		fmt.Println("Unauthorized SYN scanners:")
		for ip, addr := range addresses { // Print syn scanners
			// the set
			// of IP addresses (one per line) that sent more than 3 times as many SYN packets as the number of
			// SYN+ACK packets they received and also sent more than 5 SYN packets in total.
			if sentSynCount, receivedSynAckCount := addr[0], addr[1]; sentSynCount > 5 && sentSynCount > receivedSynAckCount*3 {
				fmt.Println(ip)
			}
		}

		fmt.Println("Unauthorized ARP spoofers:")
		for mac, count := range arpMac { // Print arp spoofers
			if uReplies := count; uReplies > 5 {
				fmt.Println(mac)
			}
		}
	}
}

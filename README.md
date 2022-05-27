# go-spoofing-detector
Analysis of a PCAP (Packet Capture) file to detect suspicious behavior (ARP spoofing and Port scanning).

## detector.go
 
- Open a .pcap file supplied as a command-line argument, and analyze the TCP, IP, Ethernet, and ARP layers

- Print the IP addresses that: 1) sent more than 3 times as many SYN packets as the number of SYN+ACK packets they received, and 2) sent more than 5 SYN packets in total

- Print the MAC addresses that send more than 5 unsolicited ARP replies

### instructions
`go run detector.go sample.pcap`
/* LAYER 2 */

/* ETHERNET */
#define ETHERNET_DESTINATION "Destination MAC Address\n\nEthernet and IEEE 802.3 addresses are 6 bytes long. Addresses are contained in hardware on the Ethernet and IEEE 802.3 interface cards. The first 3 bytes of the addresses are specified by the IEEE on a vendor-dependent basis, while the last 3 bytes are specified by the Ethernet or IEEE 802.3 vendor. The source address is always a unicast (single node) address, while the destination address may be unicast, multicast (group), or broadcast (all nodes).\n\n[IEEE802.3]"
#define ETHERNET_SOURCE "Source MAC Address\n\nEthernet and IEEE 802.3 addresses are 6 bytes long. Addresses are contained in hardware on the Ethernet and IEEE 802.3 interface cards. The first 3 bytes of the addresses are specified by the IEEE on a vendor-dependent basis, while the last 3 bytes are specified by the Ethernet or IEEE 802.3 vendor. The source address is always a unicast (single node) address, while the destination address may be unicast, multicast (group), or broadcast (all nodes).\n\n[IEEE802.3]"
#define ETHERNET_TYPE "Protocol Type\n\nThis field specifies the upper-layer protocol to receive the data after Ethernet processing is complete.\n\n[IEEE802.3]"

/* SLL (Linux Cooked) */
#define SLL_PACKET_TYPE "Packet Type\n\nThe packet type field is in network byte order (big-endian); it contains a value that is one of:\n\t0, if the packet was specifically sent to us by somebody else;\n\t1, if the packet was broadcast by somebody else;\n\t2, if the packet was multicast, but not broadcast, by somebody else;\n\t3, if the packet was sent to somebody else by somebody else;\n\t4, if the packet was sent by us.\n\n[www.tcpdump.org]"
#define SLL_ARPHRD_TYPE "ARPHRD_ Type\n\nThe ARPHRD_ type field is in network byte order; it contains a Linux ARPHRD_ value for the link-layer device type.\n\n[www.tcpdump.org]"
#define SLL_LLA_LENGTH "Link-layer Address Length\n\nThe link-layer address length field is in network byte order; it contains the length of the link-layer address of the sender of the packet. That length could be zero.\n\n[www.tcpdump.org]"
#define SLL_LLA "Link-layer Address\n\nThe link-layer address field contains the link-layer address of the sender of the packet; the number of bytes of that field that are meaningful is specified by the link-layer address length field. If there are more than 8 bytes, only the first 8 bytes are present, and if there are fewer than 8 bytes, there are padding bytes after the address to pad the field to 8 bytes.\n\n[www.tcpdump.org]"
#define SLL_PROTOCOL "Protocol Type\n\nThe protocol type field is in network byte order; it contains an Ethernet protocol type, or one of:\n\t1, if the frame is a Novell 802.3 frame without an 802.2 LLC header;\n\t4, if the frame begins with an 802.2 LLC header.\n\n[www.tcpdump.org]"

/* LAYER 3 */

/* IPv4 */
#define IPV4_VERSION "Version\n\nThe Version field indicates the format of the internet header.\n\n[RFC791]"
#define IPV4_IHL "Internet Header Length (IHL)\n\nInternet Header Length is the length of the internet header in 32 bit words, and thus points to the beginning of the data. Note that the minimum value for a correct header is 5.\n\n[RFC791]"
#define IPV4_DCSP "Differentiated Services Field Definition (DCSP)\n\nA replacement header field, called the DS field, is defined, which is intended to supersede the existing definitions of the IPv4 TOS octet [RFC791] and the IPv6 Traffic Class octet [IPv6].\n\nSix bits of the DS field are used as a codepoint (DSCP) to select the PHB a packet experiences at each node. A two-bit currently unused (CU) field is reserved and its definition and interpretation are outside the scope of this document. The value of the CU bits are ignored by differentiated services-compliant nodes when determining the per-hop behavior to apply to a received packet.\n\n[RFC2474]"
#define IPV4_ECN "Explicit Congestion Notification (ECN)\n\nThe ECN field in the IP header is used with two bits, making four ECN codepoints, '00' to '11'. The ECN-Capable Transport (ECT) codepoints '10' and '01' are set by the data sender to indicate that the end-points of the transport protocol are ECN-capable; we call them ECT(0) and ECT(1) respectively. The phrase 'the ECT codepoint' in this documents refers to either of the two ECT codepoints. Routers treat the ECT(0) and ECT(1) codepoints as equivalent. Senders are free to use either the ECT(0) or the ECT(1) codepoint to indicate ECT, on a packet-by-packet basis.\n\n[RFC3168]"
#define IPV4_TOTLEN "Total Length\n\nTotal Length is the length of the datagram, measured in octets, including internet header and data. This field allows the length of a datagram to be up to 65,535 octets. Such long datagrams are impractical for most hosts and networks. All hosts must be prepared to accept datagrams of up to 576 octets (whether they arrive whole or in fragments). It is recommended that hosts only send datagrams larger than 576 octets if they have assurance that the destination is prepared to accept the larger datagrams.\n\n[RFC791]"
#define IPV4_IDENTIFICATION "Identification\n\nAn identifying value assigned by the sender to aid in assembling the fragments of a datagram.\n\n[RFC791]"
#define IPV4_FLAG_RESERVED "Flag: Reserved\n\nBit 0: reserved, must be zero\n\n[RFC791]"
#define IPV4_FLAG_DF "Flag: Don't Fragment\n\nBit 1: (DF)\n\t0 = May Fragment,\n\t1 = Don't Fragment.\n\n[RFC791]"
#define IPV4_FLAG_MF "Flag: More Fragments\n\nBit 2: (MF)\n\t0 = Last Fragment,\n\t1 = More Fragments.\n\n[RFC791]"
#define IPV4_FRAGOFF "Fragment Offset\n\nThis field indicates where in the datagram this fragment belongs. The fragment offset is measured in units of 8 octets (64 bits). The first fragment has offset zero.\n\n[RFC791]"
#define IPV4_TTL "Time to Live (TTL)\n\nThis field indicates the maximum time the datagram is allowed to remain in the internet system. If this field contains the value zero, then the datagram must be destroyed. This field is modified in internet header processing. The time is measured in units of seconds, but since every module that processes a datagram must decrease the TTL by at least one even if it process the datagram in less than a second, the TTL must be thought of only as an upper bound on the time a datagram may exist. The intention is to cause undeliverable datagrams to be discarded, and to bound the maximum datagram lifetime.\n\n[RFC791]"
#define IPV4_PROTOCOL "Protocol\n\nThis field indicates the next level protocol used in the data portion of the internet datagram. The values for various protocols are specified in 'Assigned Numbers'.\n\n[RFC791]"
#define IPV4_CHECKSUM "Header Checksum\n\nA checksum on the header only. Since some header fields change (e.g., time to live), this is recomputed and verified at each point that the internet header is processed.\n\nThe checksum algorithm is:\n\nThe checksum field is the 16 bit one's complement of the one's complement sum of all 16 bit words in the header. For purposes of computing the checksum, the value of the checksum field is zero.\n\nThis is a simple to compute checksum and experimental evidence indicates it is adequate, but it is provisional and may be replaced by a CRC procedure, depending on further experience.\n\n[RFC791]"
#define IPV4_SOURCE "Source Address\n\nThe source address.\n\n[RFC791]"
#define IPV4_DESTINATION "Destination Address\n\nThe destination address.\n\n[RFC791]"
#define IPV4_OPTION_FLAG_COPIED "Copied Flag\n\nThe copied flag indicates that this option is copied into all fragments on fragmentation.\n\t0 = not copied\n\t1 = copied\n\n[RFC791]"
#define IPV4_OPTION_CLASS "Option Class\n\nThe option classes are:\n\t0 = control\n\t1 = reserved for future use\n\t2 = debugging and measurement\n\t3 = reserved for future use\n\n[RFC791]"
#define IPV4_OPTION_NUMBER "Option Number\n\nThe following internet options are defined:\n\t0 - End of Option list. This option occupies only 1 octet; it has no length octet.\n\t1 - No Operation. This option occupies only 1 octet; it has no length octet.\n\t2 - Security. Used to carry Security, Compartmentation, User Group (TCC), and Handling Restriction Codes compatible with DOD requirements. [RFC1108]\n\t3 - Loose Source Routing. Used to route the internet datagram based on information supplied by the source.\n\t4 - Internet Timestamp.\n\t5 - Extended Security. [RFC1108]\n\t6 - Commercial Security.\n\t7 - Record Route. Used to trace the route an internet datagram takes.\n\t8 - Stream ID. Used to carry the stream identifier.\n\t9 - Strict Source Routing. Used to route the internet datagram based on information supplied by the source.\n\t10 - Experimental Measurement.\n\t11 - MTU Probe. [RFC1063] [RFC1191]\n\t12 - MTU Reply. [RFC1063] [RFC1191]\n\t13 - Experimental Flow Control.\n\t14 - Experimental Access Control. [RFC6814]\n\t15 - Encoding. [RFC6814]\n\t16 - IMI Traffic Descriptor.\n\t17 - Extended Internet Protocol. [RFC1385] [RFC6814]\n\t18 - Traceroute. [RFC1393] [RFC6814]\n\t19 - Address Extension. [RFC6814]\n\t20 - Router Alert. [RFC2113]\n\t21 - Selective Directed Broadcast. [RFC6814]\n\t23 - Dynamic Packet State. [RFC6814]\n\t24 - Upstream Multicast Pkt. [RFC6814]\n\t25 - Quick-Start. [RFC4782]\n\t30 - RFC3692-style Experiment [RFC4727]\n\n[RFC791]"
#define IPV4_OPTION_LENGTH "Option Length\n\nThe length of the option (including header and data).\n\n[RFC791]"
#define IPV4_OPTION_DATA "Option Data\n\nThe data carried by the option.\n\n[RFC791]"

/* IPV6 */
#define IPV6_VERSION "Version\n\n4-bit Internet Protocol version number = 6.\n\n[RFC2460]"
#define IPV6_TC "Traffic Class\n\nThe 8-bit Traffic Class field in the IPv6 header is available for use by originating nodes and/or forwarding routers to identify and distinguish between different classes or priorities of IPv6 packets. At the point in time at which this specification is being written, there are a number of experiments underway in the use of the IPv4 Type of Service and/or Precedence bits to provide various forms of 'differentiated service' for IP packets, other than through the use of explicit flow set-up. The Traffic Class field in the IPv6 header is intended to allow similar functionality to be supported in IPv6.\n\n[RFC2460]"
#define IPV6_FLOW "Flow Label\n\nThe 20-bit Flow Label field in the IPv6 header may be used by a source to label sequences of packets for which it requests special handling by the IPv6 routers, such as non-default quality of service or 'real-time' service. This aspect of IPv6 is, at the time of writing, still experimental and subject to change as the requirements for flow support in the Internet become clearer. Hosts or routers that do not support the functions of the Flow Label field are required to set the field to zero when originating a packet, pass the field on unchanged when forwarding a packet, and ignore the field when receiving a packet.\n\n[RFC2460]"
#define IPV6_PAYLEN "Payload Length\n\n16-bit unsigned integer. Length of the IPv6 payload, i.e., the rest of the packet following this IPv6 header, in octets. (Note that any extension headers present are considered part of the payload, i.e., included in the length count.)\n\n[RFC2460]"
#define IPV6_NEXT_HEADER "Next Header\n\n8-bit selector. Identifies the type of header immediately following the IPv6 header. Uses the same values as the IPv4 Protocol field [RFC-1700 et seq.].\n\n[RFC2460]"
#define IPV6_HOP_LIMIT "Hop Limit\n\n8-bit unsigned integer. Decremented by 1 by each node that forwards the packet. The packet is discarded if Hop Limit is decremented to zero.\n\n[RFC2460]"
#define IPV6_SOURCE "Source Address\n\n128-bit address of the originator of the packet.\n\n[RFC2460]"
#define IPV6_DESTINATION "Destination Address\n\n128-bit address of the intended recipient of the packet (possibly not the ultimate recipient, if a Routing header is present).\n\n[RFC2460]"
#define IPV6_HDR_EXT_LEN "Header Externsion Length\n\n8-bit unsigned integer. Length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.\n\n[RFC2460]"
#define IPV6_OPTION_TYPE "Option Type\n\n8-bit identifier of the type of option.\n\n[RFC2460]"
#define IPV6_OPTION_LENGTH "Option Length\n\n8-bit unsigned integer. Length of the Option Data field of this option, in octets.\n\n[RFC2460]"
#define IPV6_OPTION_DATA "Option Data\n\nVariable-length field. Option-Type-specific data.\n\n[RFC2460]"

/* ARP */
#define ARP_HTYPE "Hardware Type\n\nThis field specifies the hardware type.\n\n[RFC826]"
#define ARP_PTYPE "Protocol Type\n\nThis field specifies the protocol type.\n\n[RFC826]"
#define ARP_HLEN "Hardware Length\n\nThis field specifies the length of each hardware address in bytes.\n\n[RFC826]"
#define ARP_PLEN "Protocol Length\n\nThis field specifies the length of each protocol address in bytes.\n\n[RFC826]"
#define ARP_OPERATION "Operation\n\nThis field specifies the operation code. The following codes are possible:\n\t1 = ARP Request\n\t2 = ARP Reply\n\n[RFC826]"
#define ARP_HW_SENDER "Sender Hardware Address\n\nHardware address of sender of this packet. Length is specified in Hardware Length Field\n\n[RFC826]"
#define ARP_PROTO_SENDER "Sender Protocol Address\n\nProtocol address of sender of this packet. Length is specified in Protocol Length Field\n\n[RFC826]"
#define ARP_HW_TARGET "Target Hardware Address\n\nHardware address of target of this packet. Length is specified in Hardware Length Field\n\n[RFC826]"
#define ARP_PROTO_TARGET "Target Protocol Address\n\nProtocol address of target of this packet. Length is specified in Protocol Length Field\n\n[RFC826]"

/* ICMP */
#define ICMP_TYPE "Type\n\nThe first octet of the data portion of the datagram is a ICMP type field; the value of this field determines the format of the remaining data.\n\nThe following types are possible:\n\t0 = Echo Reply\n\t3 = Destination Unreachable\n\t4 = Source Quench\n\t5 = Redirect\n\t8 = Echo\n\t11 = Time Exceeded\n\t12 = Parameter Problem\n\t13 = Timestamp\n\t14 = Timestamp Reply\n\t15 = Information Request\n\t16 = Information Reply\n\n[RFC792]"
#define ICMP_CODE "Code\n\nThe sub code of the ICMP message. It depends on the ICMP type.\n\n[RFC792]"
#define ICMP_CHECKSUM "Checksum\n\nThe checksum is the 16-bit ones's complement of the one's complement sum of the ICMP message starting with the ICMP Type. For computing the checksum, the checksum field should be zero.\n\n[RFC792]"
#define ICMP_UNUSED "Unused\n\nAny field labeled 'unused' is reserved for later extensions and must be zero when sent, but receivers should not use these fields (except to include them in the checksum).\n\n[RFC792]"
#define ICMP_TIME_POINTER "Pointer\n\nIf code = 0, identifies the octet where an error was detected.\n\n[RFC792]"
#define ICMP_REDIRECT_GATEWAY "Gateway Internet Address\n\nAddress of the gateway to which traffic for the network specified in the internet destination network field of the original datagram's data should be sent.\n\n[RFC792]"
#define ICMP_ECHO_ID "Identifier\n\nIf code = 0, an identifier to aid in matching echos and replies, may be zero.\n\n[RFC792]"
#define ICMP_ECHO_SEQUENCE "Sequence Number\n\nIf code = 0, a sequence number to aid in matching echos and replies, may be zero.\n\n[RFC792]"
#define ICMP_DATA "Data\n\nFurther ICMP data. These fields depend on the ICMP type and sub code.\n\n[RFC792]"

/* ICMPV6 */
#define ICMPV6_TYPE "Type\n\nThe type field indicates the type of the message. Its value determines the format of the remaining data.\n\n[RFC4443]"
#define ICMPV6_CODE "Code\n\nThe code field depends on the message type. It is used to create an additional level of message granularity.\n\n[RFC4443]"
#define ICMPV6_CHECKSUM "Checksum\n\nThe checksum field is used to detect data corruption in the ICMPv6 message and parts of the IPv6 header.\n\n[RFC4443]"
#define ICMPV6_DATA "Data\n\nFurther ICMPv6 data. These fields depend on the ICMPv6 type and sub code.\n\n[RFC4443]"

/* LAYER 4 */

/* TCP */
#define TCP_SPORT "Source Port\n\nThe source port number.\n\n[RFC793]"
#define TCP_DPORT "Destination Port\n\nThe destination port number.\n\n[RFC793]"
#define TCP_SEQ_NUM "Sequence Number\n\nThe sequence number of the first data octet in this segment (except when SYN is present). If SYN is present the sequence number is the initial sequence number (ISN) and the first data octet is ISN+1.\n\n[RFC793]"
#define TCP_ACK_NUM "Acknowledgement Number\n\nIf the ACK control bit is set this field contains the value of the next sequence number the sender of the segment is expecting to receive. Once a connection is established this is always sent.\n\n[RFC793]"
#define TCP_DOFF "Data Offset\n\nThe number of 32 bit words in the TCP Header. This indicates where the data begins. The TCP header (even one including options) is an integral number of 32 bits long.\n\n[RFC793]"
#define TCP_FLAG_RES "Reserved\n\nReserved for future use. Must be zero.\n\n[RFC793]"
#define TCP_FLAG_NS "Nonce Sum (NS)\n\nThe ECN-nonce adds to this protocol, and enables the receiver to demonstrate to the sender that segments being acknowledged were received unmarked. A random one-bit value (a nonce) is encoded in the two ECT codepoints. The one-bit sum of these nonces is returned in a TCP header flag, the nonce sum (NS) bit. Packet marking erases the nonce value in the ECT codepoints because CE overwrites both ECN IP header bits. Since each nonce is required to calculate the sum, the correct nonce sum implies receipt of only unmarked packets. Not only are receivers prevented from concealing marked packets, middle-boxes along the network path cannot unmark a packet without successfully guessing the value of the original nonce.\n\n[RFC3540]"
#define TCP_FLAG_CWR "Congestion Window Reduce (CWR)\n\nFor TCP, ECN requires three new pieces of functionality:\n\t* negotiation between the endpoints during connection setup to determine if they are both ECN-capable;\n\t* an ECN-Echo (ECE) flag in the TCP header so that the data receiver can inform the data sender when a CE packet has been received;\n\t* and a Congestion Window Reduced (CWR) flag in the TCP header so that the data sender can inform the data receiver that the congestion window has been reduced.\n\n[RFC3168]"
#define TCP_FLAG_ECE "ECN-Echo (ECE)\n\nFor TCP, ECN requires three new pieces of functionality:\n\t* negotiation between the endpoints during connection setup to determine if they are both ECN-capable;\n\t* an ECN-Echo (ECE) flag in the TCP header so that the data receiver can inform the data sender when a CE packet has been received;\n\t* and a Congestion Window Reduced (CWR) flag in the TCP header so that the data sender can inform the data receiver that the congestion window has been reduced.\n\n[RFC3168]"
#define TCP_FLAG_URG "Urgent (URG)\n\nIndicates that the Urgent pointer field is significant[RFC793]"
#define TCP_FLAG_ACK "Acknowledgement (ACK)\n\nIndicates that the Acknowledgment field is significant. All packets after the initial SYN packet sent by the client should have this flag set.\n\n[RFC793]"
#define TCP_FLAG_PSH "Push (PSH)\n\nPush function. Asks to push the buffered data to the receiving application.\n\n[RFC793]"
#define TCP_FLAG_RST "Reset (RST)\n\nReset the connection.\n\n[RFC793]"
#define TCP_FLAG_SYN "Synchronize (SYN)\n\nSynchronize sequence numbers. Only the first packet sent from each end should have this flag set. Some other flags change meaning based on this flag, and some are only valid for when it is set, and others when it is clear.\n\n[RFC793]"
#define TCP_FLAG_FIN "Finish (FIN)\n\nNo more data from sender.\n\n[RFC793]"
#define TCP_WINDOW_SIZE "Window Size\n\nThe number of data octets beginning with the one indicated in the acknowledgment field which the sender of this segment is willing to accept.\n\n[RFC793]"
#define TCP_CHECKSUM "Checksum\n\nThe checksum field is the 16 bit one's complement of the one's complement sum of all 16 bit words in the header and text. If a segment contains an odd number of header and text octets to be checksummed, the last octet is padded on the right with zeros to form a 16 bit word for checksum purposes. The pad is not transmitted as part of the segment. While computing the checksum, the checksum field itself is replaced with zeros.\n\n[RFC793]"
#define TCP_URGENT_POINTER "Urgent Pointer\n\nThis field communicates the current value of the urgent pointer as a positive offset from the sequence number in this segment. The urgent pointer points to the sequence number of the octet following the urgent data. This field is only be interpreted in segments with the URG control bit set.\n\n[RFC793]"
#define TCP_OPTION_KIND "Option Kind\n\nThe kind of option.\n\n[RFC793]"
#define TCP_OPTION_LENGTH "Option Length\n\nThe option-length counts the two octets of option-kind and option-length as well as the option-data octets.\n\n[RFC793]"
#define TCP_OPTION_DATA "Option Data\n\nThe data of the option. It depends of the option kind.\n\n[RFC793]"

/* UDP */
#define UDP_SPORT "Source Port\n\nSource Port is an optional field, when meaningful, it indicates the port of the sending process, and may be assumed to be the port to which a reply should be addressed in the absence of any other information. If not used, a value of zero is inserted.\n\n[RFC768]"
#define UDP_DPORT "Destination Port\n\nDestination Port has a meaning within the context of a particular internet destination address.\n\n[RFC768]"
#define UDP_LENGTH "Length is the length in octets of this user datagram including this header and the data. (This means the minimum value of the length is eight.)\n\n[RFC768]"
#define UDP_CHECKSUM "Checksum\n\nChecksum is the 16-bit one's complement of the one's complement sum of a pseudo header of information from the IP header, the UDP header, and the data, padded with zero octets at the end (if necessary) to make a multiple of two octets.\n\n[RFC768]"

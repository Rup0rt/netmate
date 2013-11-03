/**************************************************************************************************/
/* netmate layer3 protocols */
/**************************************************************************************************/

char *ipprotocol(unsigned char id);
GtkGrid *ipv4_grid(struct iphdr *ipv4, u_char *options);				/* ipv4 (type 0x0800) */
GtkGrid *ipv6_grid(struct ip6_hdr *ipv6, u_char *options);				/* ipv6 (type 0x08dd) */
GtkGrid *arp_grid(struct arphdr *arp, u_char *options);					/* arp (type 0x0806) */
GtkGrid *icmp_grid(struct icmphdr *icmp, u_char *options, int left);	/* icmp */
GtkGrid *icmpv6_grid(struct icmp6_hdr *icmpv6, u_char *options);		/* icmp */

/**************************************************************************************************/

/* taken from http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers */
char *ipprotocol(unsigned char id) {
  switch (id) {
    case 0:
      return("HOPOPT");
    case 1:
      return("ICMP");
    case 2:
      return("IGMP");
    case 3:
      return("GGP");
    case 4:
      return("IPv4");
    case 5:
      return("ST");
    case 6:
      return("TCP");
    case 7:
      return("CBT");
    case 8:
      return("EGP");
    case 9:
      return("IGP");
    case 10:
      return("BBN-RCC-MON");
    case 11:
      return("NVP-II");
    case 12:
      return("PUP");
    case 13:
      return("ARGUS");
    case 14:
      return("EMCON");
    case 15:
      return("XNET");
    case 16:
      return("CHAOS");
    case 17:
      return("UDP");
    case 18:
      return("MUX");
    case 19:
      return("DCN-MEAS");
    case 20:
      return("HMP");
    case 21:
      return("PRM");
    case 22:
      return("XNS-IDP");
    case 23:
      return("TRUNK-1");
    case 24:
      return("TRUNK-2");
    case 25:
      return("LEAF-1");
    case 26:
      return("LEAF-2");
    case 27:
      return("RDP");
    case 28:
      return("IRTP");
    case 29:
      return("ISO-TP4");
    case 30:
      return("NETBLT");
    case 31:
      return("MFE-NSP");
    case 32:
      return("MERIT-INP");
    case 33:
      return("DCCP");
    case 34:
      return("3PC");
    case 35:
      return("IDPR");
    case 36:
      return("XTP");
    case 37:
      return("DDP");
    case 38:
      return("IDPR-CMTP");
    case 39:
      return("TP++");
    case 40:
      return("IL");
    case 41:
      return("IPv6");
    case 42:
      return("SDRP");
    case 43:
      return("IPv6-Route");
    case 44:
      return("IPv6-Frag");
    case 45:
      return("IDRP");
    case 46:
      return("RSVP");
    case 47:
      return("GRE");
    case 48:
      return("MHRP");
    case 49:
      return("BNA");
    case 50:
      return("ESP");
    case 51:
      return("AH");
    case 52:
      return("I-NLSP");
    case 53:
      return("SWIPE");
    case 54:
      return("NARP");
    case 55:
      return("MOBILE");
    case 56:
      return("TLSP");
    case 57:
      return("SKIP");
    case 58:
      return("IPv6-ICMP");
    case 59:
      return("IPv6-NoNxt");
    case 60:
      return("IPv6-Opts");
    case 61:
      return("Any host internal protocol");
    case 62:
      return("CFTP");
    case 63:
      return("Any local network");
    case 64:
      return("SAT-EXPAK");
    case 65:
      return("KRYPTOLAN");
    case 66:
      return("RVD");
    case 67:
      return("IPPC");
    case 68:
      return("Any distributed file system");
    case 69:
      return("SAT-MON");
    case 70:
      return("VISA");
    case 71:
      return("IPCV");
    case 72:
      return("CPNX");
    case 73:
      return("CPHB");
    case 74:
      return("WSN");
    case 75:
      return("PVP");
    case 76:
      return("BR-SAT-MON");
    case 77:
      return("SUN-ND");
    case 78:
      return("WB-MON");
    case 79:
      return("WB-EXPAK");
    case 80:
      return("ISO-IP");
    case 81:
      return("VMTP");
    case 82:
      return("SECURE-VMTP");
    case 83:
      return("VINES");
    case 84:
      return("TTP");
    case 85:
      return("NSFNET-IGP");
    case 86:
      return("DGP");
    case 87:
      return("TCF");
    case 88:
      return("EIGRP");
    case 89:
      return("OSPF");
    case 90:
      return("Sprite-RPC");
    case 91:
      return("LARP");
    case 92:
      return("MTP");
    case 93:
      return("AX.25");
    case 94:
      return("IPIP");
    case 95:
      return("MICP");
    case 96:
      return("SCC-SP");
    case 97:
      return("ETHERIP");
    case 98:
      return("ENCAP");
    case 99:
      return("Any private encryption scheme");
    case 100:
      return("GMTP");
    case 101:
      return("IFMP");
    case 102:
      return("PNNI");
    case 103:
      return("PIM");
    case 104:
      return("ARIS");
    case 105:
      return("SCPS");
    case 106:
      return("QNX");
    case 107:
      return("A/N");
    case 108:
      return("IPComp");
    case 109:
      return("SNP");
    case 110:
      return("Compaq-Peer");
    case 111:
      return("IPX-in-IP");
    case 112:
      return("VRRP");
    case 113:
      return("PGM");
    case 114:
      return("Any 0-hop protocol");
    case 115:
      return("L2TP");
    case 116:
      return("DDX");
    case 117:
      return("IATP");
    case 118:
      return("STP");
    case 119:
      return("SRP");
    case 120:
      return("UTI");
    case 121:
      return("SMP");
    case 122:
      return("SM");
    case 123:
      return("PTP");
    case 124:
      return("IS-IS over IPv4");
    case 125:
      return("FIRE");
    case 126:
      return("CRTP");
    case 127:
      return("CRUDP");
    case 128:
      return("SSCOPMCE");
    case 129:
      return("IPLT");
    case 130:
      return("SPS");
    case 131:
      return("PIPE");
    case 132:
      return("SCTP");
    case 133:
      return("FC");
    case 134:
      return("RSVP-E2E-IGNORE");
    case 135:
      return("Mobility Header");
    case 136:
      return("UDPLite");
    case 137:
      return("MPLS-in-IP");
    case 138:
      return("manet");
    case 139:
      return("HIP");
    case 140:
      return("Shim6");
    case 141:
      return("WESP");
    case 142:
      return("ROHC");
    case 253:
      return("experimentation and testing");
    case 254:
      return("experimentation and testing");
    case 255:
      return("Reserved");
  }
  return("UNKNOWN");
}

GtkGrid *ipv4_grid(struct iphdr *ipv4, u_char *options) {
  GtkGrid *grid;		/* the grid itself	 */
  char *label;			/* label of buttons to set */
  char ipv4_dscp;		/* ip dscp field */
  char ipv4_ecn;		/* ip ecn field */
  char *optdata;		/* option data */
  short ipv4_offset;	/* ip fragment offset */
  int x,y;				/* position pointer to next empty grid cell */
  int left;				/* bytes left for ipv4 options */
  int optlen;			/* length of options field */
  int opttype;			/* option type */
  int i;				/* loop counter for raw data representation */

  /* init new empty grid */
  grid = GTK_GRID(gtk_grid_new());

  /* set columns to be uniform sized (for better bit size representation) */
  gtk_grid_set_column_homogeneous(grid, TRUE);

  /* allocate memory for button label */
  label = malloc(100);

  /* build bit indication topic line (0 1 2 .. 31) */
  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  /* set cell pointer to next empty grid cell */
  x=0;
  y=1;

  /* read and set ip version field */
  sprintf(label, "Version: %u", ipv4->version);
  append_field(grid, &x, &y, 4, label, IPV4_VERSION);

  /* read and set ip header length (<< 2 to calculate real size) */
  sprintf(label, "IHL: %u (%u bytes)", ipv4->ihl, ipv4->ihl*4);
  append_field(grid, &x, &y, 4, label, IPV4_IHL);

  /* read and set ip dscp field */
  ipv4_dscp = ipv4->tos >> 2;
  sprintf(label, "DSCP: 0x%02x", ipv4_dscp);
  append_field(grid, &x, &y, 6, label, IPV4_DCSP);

  /* read and set ip ecn field */
  ipv4_ecn = ipv4->tos & 0x03;
  sprintf(label, "ECN:\n0x%02x", ipv4_ecn);
  append_field(grid, &x, &y, 2, label, IPV4_ECN);

  /* read and set total length of ip header */
  sprintf(label, "Total Length: %u", htons(ipv4->tot_len));
  append_field(grid, &x, &y, sizeof(ipv4->tot_len)*8, label, IPV4_TOTLEN);

  /* read and set identification field of ip packet */
  sprintf(label, "Identification: 0x%04x", htons(ipv4->id));
  append_field(grid, &x, &y, sizeof(ipv4->id)*8, label, IPV4_IDENTIFICATION);

  /* reserved flag */
  if (ipv4->frag_off & htons(IP_RF)) {
    append_field(grid, &x, &y, 1, "RF", IPV4_FLAG_RESERVED);
  } else {
    append_field(grid, &x, &y, 1, "rf", IPV4_FLAG_RESERVED);
  }

  /* dont fragment flag */
  if (ipv4->frag_off & htons(IP_DF)) {
    append_field(grid, &x, &y, 1, "DF", IPV4_FLAG_DF);
  } else {
    append_field(grid, &x, &y, 1, "df", IPV4_FLAG_DF);
  }

  /* more fragments flag */
  if (ipv4->frag_off & htons(IP_MF)) {
    append_field(grid, &x, &y, 1, "MF", IPV4_FLAG_MF);
  } else {
    append_field(grid, &x, &y, 1, "mf", IPV4_FLAG_MF);
  }

  /* read and set ip fragmentation offset (<< 3 to calculate real size); */
  ipv4_offset = (htons(ipv4->frag_off) & IP_OFFMASK);
  sprintf(label, "Fragment Offset: %u (%u bytes)", ipv4_offset, ipv4_offset << 3);
  append_field(grid, &x, &y, 13, label, IPV4_FRAGOFF);

  /* read and set time to live of ip packet */
  sprintf(label, "Time To Live: %u", ipv4->ttl);
  append_field(grid, &x, &y, sizeof(ipv4->ttl)*8, label, IPV4_TTL);

  /* read an d set upper layer protocol */
  sprintf(label, "Protocol: %u (%s)", ipv4->protocol, ipprotocol(ipv4->protocol));
  append_field(grid, &x, &y, sizeof(ipv4->protocol)*8, label, IPV4_PROTOCOL);

  /* read and set ip header checksum */
  sprintf(label, "Header checksum: 0x%04x", htons(ipv4->check));
  append_field(grid, &x, &y, sizeof(ipv4->check)*8, label, IPV4_CHECKSUM);

  /* read and set ip source address */
  sprintf(label, "Source IP Address: %u.%u.%u.%u", ipv4->saddr & 0xff, (ipv4->saddr >> 8) & 0xff, (ipv4->saddr >> 16) & 0xff, (ipv4->saddr >> 24) & 0xff);
  append_field(grid, &x, &y, sizeof(ipv4->saddr)*8, label, IPV4_SOURCE);

  /* read and set ip destination address */
  sprintf(label, "Destination IP Address: %u.%u.%u.%u", ipv4->daddr & 0xff, (ipv4->daddr >> 8) & 0xff, (ipv4->daddr >> 16) & 0xff, (ipv4->daddr >> 24) & 0xff);
  append_field(grid, &x, &y, sizeof(ipv4->daddr)*8, label, IPV4_DESTINATION);

  /* count bytes of option fields */
  left = (ipv4->ihl-0x05)*4;

  /* progress bytes until no option bytes left */
  while (left > 0) {
    /* get option type (first byte) */
    opttype = options[0];

    /* copy bit (bit 1) */
    if (opttype & IPOPT_COPY) {
      append_field(grid, &x, &y, 1, "C", IPV4_OPTION_FLAG_COPIED);
    } else {
      append_field(grid, &x, &y, 1, "c", IPV4_OPTION_FLAG_COPIED);
    }

    /* option class (bit 2 & 3) */
    sprintf(label, "Class: %u", opttype & IPOPT_CLASS_MASK);
    append_field(grid, &x, &y, 2, label, IPV4_OPTION_CLASS);

    /* option number (bit 4-8) */
    sprintf(label, "Number: %u", opttype & IPOPT_NUMBER_MASK);
    append_field(grid, &x, &y, 5, label, IPV4_OPTION_NUMBER);

    /* options length (INCLUDING type & length fields) */
    optlen = options[1];
    sprintf(label, "Length: %u", optlen);
    append_field(grid, &x, &y, 8, label, IPV4_OPTION_LENGTH);

    /* allocate memory for option data (*2 because of hex representation) */
    optdata = malloc(optlen*2);

    /* print bytes in hex format into array */
    for (i=0; i<optlen-2; ++i) sprintf(&optdata[i*2], "%02x", (unsigned int)options[i+2]);
    optdata[(optlen-2)*2] = 0x00;

    /* option data field */
    sprintf(label, "Opt. Data 0x%s", optdata);
    append_field(grid, &x, &y, (optlen-2)*8, label, IPV4_OPTION_DATA);

    /* free data */
    free(optdata);

    /* reduce length of field */
    left -= optlen;

    /* increase pointer to options header */
    options = options + optlen;
  }

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* pass grid back to tab builder function */
  return(grid);
}

GtkGrid *ipv6_grid(struct ip6_hdr *ipv6, u_char *options) {
  GtkGrid *grid;	/* the grid itself */
  char *label;		/* label of buttons to set */
  int x,y;			/* position pointer to next empty grid cell */
  char *optdata;
  int i;
  int optlen;
  int opttype;
  int hoplen;
  int left;
  int ipv6_version;
  int ipv6_tc;
  int ipv6_fl;
  int ipv6_nh;

  /* init new empty grid */
  grid = GTK_GRID(gtk_grid_new());

  /* set columns to be uniform sized (for better bit size representation) */
  gtk_grid_set_column_homogeneous(grid, TRUE);

  /* allocate memory for button label */
  label = malloc(100);

  /* build bit indication topic line (0 1 2 .. 31) */
  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  /* set cell pointer to next empty grid cell */
  x=0;
  y=1;

  /* read and set ip version field */
  ipv6_version = htonl(ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow) >> 28;
  sprintf(label, "Version: %u", ipv6_version);
  append_field(grid, &x, &y, 4, label, IPV6_VERSION);

  /* traffic class */
  ipv6_tc = htonl(ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow) >> 20 & 0x00ff;
  sprintf(label, "Traffic Class: 0x%02x", ipv6_tc);
  append_field(grid, &x, &y, 8, label, IPV6_TC);

  /* flow label */
  ipv6_fl = htonl(ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow) & 0x000fffff;
  sprintf(label, "Flow Label: 0x%06x", ipv6_fl);
  append_field(grid, &x, &y, 20, label, IPV6_FLOW);

  /* payload length */
  sprintf(label, "Payload Length: %u", htons(ipv6->ip6_ctlun.ip6_un1.ip6_un1_plen));
  append_field(grid, &x, &y, sizeof(ipv6->ip6_ctlun.ip6_un1.ip6_un1_plen)*8, label, IPV6_PAYLEN);

  /* next header */
  ipv6_nh = ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  sprintf(label, "Next Header: %u (%s)", ipv6_nh, ipprotocol(ipv6_nh));
  append_field(grid, &x, &y, sizeof(ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt)*8, label, IPV6_NEXT_HEADER);

  /* hop limit */
  sprintf(label, "Hop Limit: %u", ipv6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
  append_field(grid, &x, &y, sizeof(ipv6->ip6_ctlun.ip6_un1.ip6_un1_hlim)*8, label, IPV6_HOP_LIMIT);

  /* source address */
  sprintf(label, "Source Address: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", htons(ipv6->ip6_src.__in6_u.__u6_addr16[0]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[1]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[2]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[3]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[4]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[5]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[6]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[7]));
  append_field(grid, &x, &y, 128, label, IPV6_SOURCE);

  /* destination address */
  sprintf(label, "Destination Address: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", htons(ipv6->ip6_dst.__in6_u.__u6_addr16[0]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[1]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[2]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[3]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[4]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[5]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[6]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[7]));
  append_field(grid, &x, &y, 128, label, IPV6_DESTINATION);

  while (ipv6_nh == IPPROTO_HOPOPTS) {
    /* next header */
    ipv6_nh = options[0];
    sprintf(label, "Next Header: %u (%s)", ipv6_nh, ipprotocol(ipv6_nh));
    append_field(grid, &x, &y, sizeof(ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt)*8, label, IPV6_NEXT_HEADER);

    /* options length */
    hoplen = options[1];
    sprintf(label, "Length: %u (%u bytes)", hoplen, hoplen*8);
    append_field(grid, &x, &y, 8, label, IPV6_HDR_EXT_LEN);
    options += 2;

    left = hoplen*8 + 6;
    while (left > 0) {
      opttype = options[0];
      sprintf(label, "Type: %u", opttype);
      append_field(grid, &x, &y, 8, label, IPV6_OPTION_TYPE);

      optlen = options[1];
      sprintf(label, "Length: %u", optlen);
      append_field(grid, &x, &y, 8, label, IPV6_OPTION_LENGTH);

      if (optlen > 0) {
        optdata = malloc(optlen*2+1);

        for (i=0; i<optlen; ++i) sprintf(&optdata[i*2], "%02x", (unsigned int)options[i+2]);
        optdata[optlen*2] = 0x00;

        sprintf(label, "Data: 0x%s", optdata);
        append_field(grid, &x, &y, optlen*8, label, IPV6_OPTION_DATA);

        free(optdata);
      }

      options += 2 + optlen;
      left -= 2 + optlen;
    }

  }

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* pass grid back to tab builder function */
  return(grid);
}

GtkGrid *arp_grid(struct arphdr *arp, u_char *options) {
  GtkGrid *grid;	/* the grid itself */
  char *label;		/* label of buttons to set */
  int x,y;			/* position pointer to next empty grid cell */

  /* init new empty grid */
  grid = GTK_GRID(gtk_grid_new());

  /* set columns to be uniform sized (for better bit size representation) */
  gtk_grid_set_column_homogeneous(grid, TRUE);

  /* allocate memory for button label */
  label = malloc(100);

  /* build bit indication topic line (0 1 2 .. 31) */
  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  /* set cell pointer to next empty grid cell */
  x=0;
  y=1;

  /* hardware type */
  sprintf(label, "Hardware Type: %u (%s)", htons(arp->ar_hrd), hardwaretype(htons(arp->ar_hrd)));
  append_field(grid, &x, &y, sizeof(arp->ar_hrd)*8, label, ARP_HTYPE);

  /* protocol type */
  sprintf(label, "Protocol Type: 0x%04x (%s)", htons(arp->ar_pro), ethertype(htons(arp->ar_pro)));
  append_field(grid, &x, &y, sizeof(arp->ar_pro)*8, label, ARP_PTYPE);

  /* hardware length */
  sprintf(label, "Hardware Length: %u", arp->ar_hln);
  append_field(grid, &x, &y, sizeof(arp->ar_hln)*8, label, ARP_HLEN);

  /* protocol length */
  sprintf(label, "Protocol Length: %u", arp->ar_pln);
  append_field(grid, &x, &y, sizeof(arp->ar_pln)*8, label, ARP_PLEN);

  /* operation */
  sprintf(label, "Operation: %u", htons(arp->ar_op));
  append_field(grid, &x, &y, sizeof(arp->ar_op)*8, label, ARP_OPERATION);

  /* sender hardware address (SHA) */
  sprintf(label, "Sender Hardware Address: %02x:%02x:%02x:%02x:%02x:%02x", options[0], options[1], options[2], options[3], options[4], options[5]);
  append_field(grid, &x, &y, 48, label, ARP_HW_SENDER);
  options += 6;

  /* sender protocol address (SPA) */
  sprintf(label, "Sender Protocol Address: %u.%u.%u.%u", options[0], options[1], options[2], options[3]);
  append_field(grid, &x, &y, 32, label, ARP_PROTO_SENDER);
  options += 4;

  /* sender hardware address (THA) */
  sprintf(label, "Target Hardware Address: %02x:%02x:%02x:%02x:%02x:%02x", options[0], options[1], options[2], options[3], options[4], options[5]);
  append_field(grid, &x, &y, 48, label, ARP_HW_TARGET);
  options += 6;

  /* sender protocol address (TPA) */
  sprintf(label, "Target Protocol Address: %u.%u.%u.%u", options[0], options[1], options[2], options[3]);
  append_field(grid, &x, &y, 32, label, ARP_PROTO_TARGET);
  options += 4;

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* pass grid back to tab builder function */
  return(grid);
}

GtkGrid *icmp_grid(struct icmphdr *icmp, u_char *options, int left) {
  GtkGrid *grid;	/* the grid itself */
  char *label;		/* label of buttons to set */
  int x,y;			/* position pointer to next empty grid cell */
  int i;
  int optlen;
  char *optdata;

  /* init new empty grid */
  grid = GTK_GRID(gtk_grid_new());

  /* set columns to be uniform sized (for better bit size representation) */
  gtk_grid_set_column_homogeneous(grid, TRUE);

  /* allocate memory for button label */
  label = malloc(100);

  /* build bit indication topic line (0 1 2 .. 31) */
  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  /* set cell pointer to next empty grid cell */
  x=0;
  y=1;

  /* type */
  sprintf(label, "Type: %u", icmp->type);
  append_field(grid, &x, &y, sizeof(icmp->type)*8, label, ICMP_TYPE);

  /* code */
  sprintf(label, "Code: %u", icmp->code);
  append_field(grid, &x, &y, sizeof(icmp->code)*8, label, ICMP_CODE);

  /* checksum */
  sprintf(label, "Checksum: 0x%04x", htons(icmp->checksum));
  append_field(grid, &x, &y, sizeof(icmp->checksum)*8, label, ICMP_CHECKSUM);

  /* unused */
  sprintf(label, "Unused: 0x%08x", htonl(icmp->un.gateway));
  append_field(grid, &x, &y, sizeof(icmp->un)*8, label, ICMP_UNUSED);

  left -= 8;

  /* allocate memory for option data */
  optdata = malloc(10);

  /* progress bytes until no option bytes left */
  while (left > 0) {
    if (left >= 4) optlen = 4; else optlen = left;

    /* print bytes in hex format into array */
    for (i=0; i<optlen; ++i) sprintf(&optdata[i*2], "%02x", (unsigned int)options[i]);
    optdata[optlen*2] = 0x00;

    /* option data field */
    sprintf(label, "Data 0x%s", optdata);
    append_field(grid, &x, &y, optlen*8, label, ICMP_DATA);

    options += optlen;
    left -= optlen;
  }

  /* free data */
  free(optdata);

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* pass grid back to tab builder function */
  return(grid);
}

GtkGrid *icmpv6_grid(struct icmp6_hdr *icmpv6, u_char *options) {
  GtkGrid *grid;	/* the grid itself */
  char *label;		/* label of buttons to set */
  int x,y;			/* position pointer to next empty grid cell */

  /* init new empty grid */
  grid = GTK_GRID(gtk_grid_new());

  /* set columns to be uniform sized (for better bit size representation) */
  gtk_grid_set_column_homogeneous(grid, TRUE);

  /* allocate memory for button label */
  label = malloc(100);

  /* build bit indication topic line (0 1 2 .. 31) */
  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  /* set cell pointer to next empty grid cell */
  x=0;
  y=1;

  /* type */
  sprintf(label, "Type: %u", icmpv6->icmp6_type);
  append_field(grid, &x, &y, sizeof(icmpv6->icmp6_type)*8, label, ICMPV6_TYPE);

  /* code */
  sprintf(label, "Code: %u", icmpv6->icmp6_code);
  append_field(grid, &x, &y, sizeof(icmpv6->icmp6_code)*8, label, ICMPV6_CODE);

  /* checksum */
  sprintf(label, "Code: 0x%04x", htons(icmpv6->icmp6_cksum));
  append_field(grid, &x, &y, sizeof(icmpv6->icmp6_cksum)*8, label, ICMPV6_CHECKSUM);

  /* data */
  sprintf(label, "Data: 0x%08x", htonl(icmpv6->icmp6_dataun.icmp6_un_data32[0]));
  append_field(grid, &x, &y, 32, label, ICMPV6_DATA);

  /* TODO: support options */
  if (options != NULL) {}

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* pass grid back to tab builder function */
  return(grid);
}

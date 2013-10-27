/**************************************************************************************************/
/* netmate layer3 protocols */
/**************************************************************************************************/

GtkGrid *ipv4_grid(struct iphdr *ipv4, u_char *options);				/* ipv4 (type 0x0800) */
GtkGrid *ipv6_grid(struct ip6_hdr *ipv6, u_char *options);				/* ipv6 (type 0x08dd) */
GtkGrid *arp_grid(struct arphdr *arp, u_char *options);					/* arp (type 0x0806) */
GtkGrid *icmp_grid(struct icmphdr *icmp, u_char *options, int left);	/* icmp */
GtkGrid *icmpv6_grid(struct icmp6_hdr *icmpv6, u_char *options);		/* icmp */

/**************************************************************************************************/

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
  sprintf(label, "Protocol: %u", ipv4->protocol);
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
  sprintf(label, "Next Header: %u", ipv6_nh);
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
    sprintf(label, "Next Header: %u", ipv6_nh);
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
  sprintf(label, "Hardware Type: %u", htons(arp->ar_hrd));
  append_field(grid, &x, &y, sizeof(arp->ar_hrd)*8, label, NULL);

  /* protocol type */
  sprintf(label, "Protocol Type: 0x%04x", htons(arp->ar_pro));
  append_field(grid, &x, &y, sizeof(arp->ar_pro)*8, label, NULL);

  /* hardware length */
  sprintf(label, "Hardware Length: %u", arp->ar_hln);
  append_field(grid, &x, &y, sizeof(arp->ar_hln)*8, label, NULL);

  /* protocol length */
  sprintf(label, "Protocol Length: %u", arp->ar_pln);
  append_field(grid, &x, &y, sizeof(arp->ar_pln)*8, label, NULL);

  /* operation */
  sprintf(label, "Operation: %u", htons(arp->ar_op));
  append_field(grid, &x, &y, sizeof(arp->ar_op)*8, label, NULL);

  /* sender hardware address (SHA) */
  sprintf(label, "Sender Hardware Address: %02x:%02x:%02x:%02x:%02x:%02x", options[0], options[1], options[2], options[3], options[4], options[5]);
  append_field(grid, &x, &y, 48, label, NULL);
  options += 6;

  /* sender protocol address (SPA) */
  sprintf(label, "Sender Protocol Address: %u.%u.%u.%u", options[0], options[1], options[2], options[3]);
  append_field(grid, &x, &y, 32, label, NULL);
  options += 4;

  /* sender hardware address (THA) */
  sprintf(label, "Target Hardware Address: %02x:%02x:%02x:%02x:%02x:%02x", options[0], options[1], options[2], options[3], options[4], options[5]);
  append_field(grid, &x, &y, 48, label, NULL);
  options += 6;

  /* sender protocol address (TPA) */
  sprintf(label, "Target Protocol Address: %u.%u.%u.%u", options[0], options[1], options[2], options[3]);
  append_field(grid, &x, &y, 32, label, NULL);
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
  append_field(grid, &x, &y, sizeof(icmp->type)*8, label, NULL);

  /* code */
  sprintf(label, "Code: %u", icmp->code);
  append_field(grid, &x, &y, sizeof(icmp->code)*8, label, NULL);

  /* checksum */
  sprintf(label, "Checksum: 0x%04x", htons(icmp->checksum));
  append_field(grid, &x, &y, sizeof(icmp->checksum)*8, label, NULL);

  /* unused */
  sprintf(label, "Unused: 0x%08x", htonl(icmp->un.gateway));
  append_field(grid, &x, &y, sizeof(icmp->un)*8, label, NULL);

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
    append_field(grid, &x, &y, optlen*8, label, NULL);

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
  append_field(grid, &x, &y, sizeof(icmpv6->icmp6_type)*8, label, NULL);

  /* code */
  sprintf(label, "Code: %u", icmpv6->icmp6_code);
  append_field(grid, &x, &y, sizeof(icmpv6->icmp6_code)*8, label, NULL);

  /* checksum */
  sprintf(label, "Code: 0x%04x", htons(icmpv6->icmp6_cksum));
  append_field(grid, &x, &y, sizeof(icmpv6->icmp6_cksum)*8, label, NULL);

  /* data */
  sprintf(label, "Data: 0x%08x", htonl(icmpv6->icmp6_dataun.icmp6_un_data32[0]));
  append_field(grid, &x, &y, 32, label, NULL);

  /* TODO: support options */
  if (options != NULL) {}

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* pass grid back to tab builder function */
  return(grid);
}

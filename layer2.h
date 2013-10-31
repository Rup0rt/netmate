/**************************************************************************************************/
/* netmate layer2 protocols */
/**************************************************************************************************/

char *ethertype(unsigned short id);
GtkGrid *ethernet_grid(struct ether_header *eth);	/* ethernet */
GtkGrid *sll_grid(struct sll_header *sll);			/* ssl (linux cooked) */

/**************************************************************************************************/

char *ethertype(unsigned short id) {
  switch (id) {
    case 0x0800:
      return("Internet Protocol Version 4 (IPv4)");
    case 0x0806:
      return("Address Resolution Protocol (ARP)");
    case 0x0842:
      return("Wake-on-LAN");
    case 0x22F3:
      return("IETF TRILL Protocol");
    case 0x6003:
      return("DECnet Phase IV");
    case 0x8035:
      return("Reverse Address Resolution Protocol");
    case 0x809B:
      return("AppleTalk (Ethertalk)");
    case 0x80F3:
      return("AppleTalk Address Resolution Protocol (AARP)");
    case 0x8100:
      return("VLAN-tagged frame (IEEE 802.1Q)");
    case 0x8137:
      return("Internetwork Packet Exchange (IPX)");
    case 0x8138:
      return("Internetwork Packet Exchange (IPX)");
    case 0x8204:
      return("QNX Qnet");
    case 0x86DD:
      return("Internet Protocol Version 6 (IPv6)");
    case 0x8808:
      return("Ethernet flow control");
    case 0x8809:
      return("Slow Protocols (IEEE 802.3)");
    case 0x8819:
      return("CobraNet");
    case 0x8847:
      return("MPLS unicast");
    case 0x8848:
      return("MPLS multicast");
    case 0x8863:
      return("PPPoE Discovery Stage");
    case 0x8864:
      return("PPPoE Session Stage");
    case 0x8870:
      return("Jumbo Frames");
    case 0x887B:
      return("HomePlug 1.0 MME");
    case 0x888E:
      return("EAP over LAN (IEEE 802.1X)");
    case 0x8892:
      return("PROFINET Protocol");
    case 0x889A:
      return("HyperSCSI (SCSI over Ethernet)");
    case 0x88A2:
      return("ATA over Ethernet");
    case 0x88A4:
      return("EtherCAT Protocol");
    case 0x88A8:
      return("Provider Bridging (IEEE 802.1ad)");
    case 0x88AB:
      return("Ethernet Powerlink");
    case 0x88CC:
      return("Link Layer Discovery Protocol (LLDP)");
    case 0x88CD:
      return("SERCOS III");
    case 0x88E1:
      return("HomePlug AV MME");
    case 0x88E3:
      return("Media Redundancy Protocol (IEC62439-2)");
    case 0x88E5:
      return("MAC security (IEEE 802.1AE)");
    case 0x88F7:
      return("Precision Time Protocol (IEEE 1588)");
    case 0x8902:
      return("IEEE 802.1ag Connectivity Fault Management (CFM) Protocol");
    case 0x8906:
      return("Fibre Channel over Ethernet (FCoE)");
    case 0x8914:
      return("FCoE Initialization Protocol");
    case 0x8915:
      return("RDMA over Converged Ethernet (RoCE)");
    case 0x892F:
      return("High-availability Seamless Redundancy (HSR)");
    case 0x9000:
      return("Ethernet Configuration Testing Protocol");
    case 0x9100:
      return("Q-in-Q");
    case 0xCAFE:
      return("Veritas Low Latency Transport (LLT)");
  }
  return("UNKNOWN");
}

GtkGrid *sll_grid(struct sll_header *sll) {
  GtkGrid *grid;	/* the grid itself */
  int x, y;			/* position of next empty grid cell */
  char *label;		/* label of buttons to set */

  /* init a new empty grid */
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

  /* Packet Type */
  sprintf(label, "Packet Type: %u", htons(sll->sll_pkttype));
  append_field(grid, &x, &y, sizeof(sll->sll_pkttype)*8, label, SLL_PACKET_TYPE);

  /* ARP Header Type */
  sprintf(label, "ARPHRD_ Type: %u", htons(sll->sll_hatype));
  append_field(grid, &x, &y, sizeof(sll->sll_hatype)*8, label, SLL_ARPHRD_TYPE);

  /* Link-layer Address Length */
  sprintf(label, "Link-layer Address Length: %u", htons(sll->sll_halen));
  append_field(grid, &x, &y, sizeof(sll->sll_halen)*8, label, SLL_LLA_LENGTH);

  /* Link-layer Address */
  sprintf(label, "Link-layer Address: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2], sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5], sll->sll_addr[6], sll->sll_addr[7]);
  append_field(grid, &x, &y, sizeof(sll->sll_addr)*8, label, SLL_LLA);

  /* Upper Layer Protocol */
  sprintf(label, "Protocol Type: 0x%04x (%s)", htons(sll->sll_protocol), ethertype(htons(sll->sll_protocol)));
  append_field(grid, &x, &y, sizeof(sll->sll_protocol)*8, label, SLL_PROTOCOL);

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* return grid to tab builder */
  return(grid);
}

GtkGrid *ethernet_grid(struct ether_header *eth) {
  GtkGrid *grid;	/* the grid itself */
  int x, y;			/* position pointer to next empty grid cell */
  char *label;		/* label of buttons to set */

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

  /* destination mac */
  sprintf(label, "Destination: %02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
  append_field(grid, &x, &y, sizeof(eth->ether_dhost)*8, label, ETHERNET_DESTINATION);

  /* source mac */
  sprintf(label, "Source: %02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  append_field(grid, &x, &y, sizeof(eth->ether_shost)*8, label, ETHERNET_DESTINATION);

  /* upper layer protocol */
  sprintf(label, "Type: 0x%04x (%s)", htons(eth->ether_type), ethertype(htons(eth->ether_type)));
  append_field(grid, &x, &y, sizeof(eth->ether_type)*8, label, ETHERNET_TYPE);

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* return grid to tab builder */
  return(grid);
}

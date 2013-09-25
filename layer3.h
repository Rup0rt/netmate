///////////////////////////////////////////////////////////////////////////////////
// netmate layer3 protocols //
///////////////////////////////////////////////////////////////////////////////////

GtkGrid *ipv4_grid(struct iphdr *ipv4, u_char *options);	// ipv4 (type 0x0800)

///////////////////////////////////////////////////////////////////////////////////

GtkGrid *ipv4_grid(struct iphdr *ipv4, u_char *options) {
  GtkGrid *grid;	// the grid itself
  char *label;		// label of buttons to set
  char ipv4_dscp;	// ip dscp field
  char ipv4_ecn;	// ip ecn field
  char *optdata;	// option data
  short ipv4_offset;	// ip fragment offset
  int x,y;		// position pointer to next empty grid cell
  int left;		// bytes left for ipv4 options
  int optlen;		// length of options field
  int opttype;		// option type
  int i;		// loop counter for raw data representation

  // init new empty grid
  grid = GTK_GRID(gtk_grid_new());

  // set columns to be uniform sized (for better bit size representation)
  gtk_grid_set_column_homogeneous(grid, TRUE);

  // allocate memory for button label
  label = malloc(100);

  // build bit indication topic line (0 1 2 .. 31)
  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  // set cell pointer to next empty grid cell
  x=0;
  y=1;

  // read and set ip version field
  sprintf(label, "Version: %u", ipv4->version);
  append_field(grid, &x, &y, 4, label);

  // read and set ip header length (<< 2 to calculate real size)
  sprintf(label, "IHL: %u (%u bytes)", ipv4->ihl, ipv4->ihl*4);
  append_field(grid, &x, &y, 4, label);

  // read and set ip dscp field
  ipv4_dscp = ipv4->tos >> 2;
  sprintf(label, "DSCP: 0x%02x", ipv4_dscp);
  append_field(grid, &x, &y, 6, label);

  // read and set ip ecn field
  ipv4_ecn = ipv4->tos & 0x03;
  sprintf(label, "ECN:\n0x%02x", ipv4_ecn);
  append_field(grid, &x, &y, 2, label);

  // read and set total length of ip header
  sprintf(label, "Total Length: %u", htons(ipv4->tot_len));
  append_field(grid, &x, &y, sizeof(ipv4->tot_len)*8, label);

  // read and set identification field of ip packet
  sprintf(label, "Identification: 0x%04x", htons(ipv4->id));
  append_field(grid, &x, &y, sizeof(ipv4->id)*8, label);

  // reserved flag
  if (ipv4->frag_off & htons(IP_RF)) {
    append_field(grid, &x, &y, 1, "RF");
  } else {
    append_field(grid, &x, &y, 1, "rf");
  }

  // dont fragment flag
  if (ipv4->frag_off & htons(IP_DF)) {
    append_field(grid, &x, &y, 1, "DF");
  } else {
    append_field(grid, &x, &y, 1, "df");
  }

  // more fragments flag
  if (ipv4->frag_off & htons(IP_MF)) {
    append_field(grid, &x, &y, 1, "MF");
  } else {
    append_field(grid, &x, &y, 1, "mf");
  }

  // read and set ip fragmentation offset (<< 3 to calculate real size);
  ipv4_offset = (htons(ipv4->frag_off) & IP_OFFMASK);
  sprintf(label, "Fragment Offset: %u (%u bytes)", ipv4_offset, ipv4_offset << 3);
  append_field(grid, &x, &y, 13, label);

  // read and set time to live of ip packet
  sprintf(label, "Time To Live: %u", ipv4->ttl);
  append_field(grid, &x, &y, sizeof(ipv4->ttl)*8, label);

  // read an d set upper layer protocol
  sprintf(label, "Protocol: %u", ipv4->protocol);
  append_field(grid, &x, &y, sizeof(ipv4->protocol)*8, label);

  // read and set ip header checksum
  sprintf(label, "Header checksum: 0x%04x", htons(ipv4->check));
  append_field(grid, &x, &y, sizeof(ipv4->check)*8, label);

  // read and set ip source address
  sprintf(label, "Source IP Address: %u.%u.%u.%u", ipv4->saddr & 0xff, (ipv4->saddr >> 8) & 0xff, (ipv4->saddr >> 16) & 0xff, (ipv4->saddr >> 24) & 0xff);
  append_field(grid, &x, &y, sizeof(ipv4->saddr)*8, label);

  // read and set ip destination address
  sprintf(label, "Destination IP Address: %u.%u.%u.%u", ipv4->daddr & 0xff, (ipv4->daddr >> 8) & 0xff, (ipv4->daddr >> 16) & 0xff, (ipv4->daddr >> 24) & 0xff);
  append_field(grid, &x, &y, sizeof(ipv4->daddr)*8, label);

  // count bytes of option fields
  left = (ipv4->ihl-0x05)*4;

  // progress bytes until no option bytes left
  while (left > 0) {
    // get option type (first byte)
    opttype = options[0];

    // copy bit (bit 1)
    if (opttype & IPOPT_COPY) {
      append_field(grid, &x, &y, 1, "C");
    } else {
      append_field(grid, &x, &y, 1, "c");
    }

    // option class (bit 2 & 3)
    sprintf(label, "Class: %u", opttype & IPOPT_CLASS_MASK);
    append_field(grid, &x, &y, 2, label);

    // option number (bit 4-8)
    sprintf(label, "Number: %u", opttype & IPOPT_NUMBER_MASK);
    append_field(grid, &x, &y, 5, label);

    // options length (INCLUDING type & length fields)
    optlen = options[1];
    sprintf(label, "Length: %u", optlen);
    append_field(grid, &x, &y, 8, label);

    // allocate memory for option data (*2 because of hex representation)
    optdata = malloc(optlen*2);

    // print bytes in hex format into array
    for (i=0; i<optlen-2; ++i) sprintf(&optdata[i*2], "%02x", (unsigned int)options[i+2]);
    optdata[optlen] = 0x00;

    // option data field
    sprintf(label, "Opt. Data 0x%s", optdata);
    append_field(grid, &x, &y, (optlen-2)*8, label);

    // free data
    free(optdata);

    // reduce length of field
    left -= optlen;

    // increase pointer to options header
    options = options + optlen;
  }

  // free memory of label
  free(label);

  // show ethernet grid (tab)
  gtk_widget_show_all(GTK_WIDGET(grid));

  // pass grid back to tab builder function
  return(grid);
}

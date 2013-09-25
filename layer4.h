///////////////////////////////////////////////////////////////////////////////////
// netmate layer4 protocols //
///////////////////////////////////////////////////////////////////////////////////

GtkGrid *tcp_grid(struct tcphdr *tcp, u_char *options);
GtkGrid *udp_grid(struct udphdr *udp);

///////////////////////////////////////////////////////////////////////////////////

GtkGrid *tcp_grid(struct tcphdr *tcp, u_char *options) {
  GtkGrid *grid;	// the grid itself
  char *label;		// label of buttons to set
  char *optdata;	// option data
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

  // source port
  sprintf(label, "Source Port: %u", htons(tcp->source));
  append_field(grid, &x, &y, sizeof(tcp->source)*8, label);

  // destination port
  sprintf(label, "Destination Port: %u", htons(tcp->dest));
  append_field(grid, &x, &y, sizeof(tcp->dest)*8, label);

  // sequence number
  sprintf(label, "Sequence Number: %u", htonl(tcp->seq));
  append_field(grid, &x, &y, sizeof(tcp->seq)*8, label);

  // acknowledgement number
  sprintf(label, "Acknowledgement Number: %u", htonl(tcp->ack_seq));
  append_field(grid, &x, &y, sizeof(tcp->ack_seq)*8, label);

  // data offset
  sprintf(label, "Data Offset: %u (%u bytes)", tcp->doff, tcp->doff*4);
  append_field(grid, &x, &y, 4, label);

  // reserved (000)
  if (tcp->res1 & 0x08) {
    append_field(grid, &x, &y, 1, "R");
  } else {
    append_field(grid, &x, &y, 1, "r");
  }
  if (tcp->res1 & 0x04) {
    append_field(grid, &x, &y, 1, "R");
  } else {
    append_field(grid, &x, &y, 1, "r");
  }
  if (tcp->res1 & 0x02) {
    append_field(grid, &x, &y, 1, "R");
  } else {
    append_field(grid, &x, &y, 1, "r");
  }

  // NS
  if (tcp->res1 & 0x01) {
    append_field(grid, &x, &y, 1, "NS");
  } else {
    append_field(grid, &x, &y, 1, "ns");
  }

  // CWR
  if (tcp->res2 & 0x02) {
    append_field(grid, &x, &y, 1, "CWR");
  } else {
    append_field(grid, &x, &y, 1, "cwr");
  }

  // ECE
  if (tcp->res2 & 0x01) {
    append_field(grid, &x, &y, 1, "ECE");
  } else {
    append_field(grid, &x, &y, 1, "ece");
  }

  // URG
  if (tcp->urg) {
    append_field(grid, &x, &y, 1, "URG");
  } else {
    append_field(grid, &x, &y, 1, "urg");
  }

  // ACK
  if (tcp->ack) {
    append_field(grid, &x, &y, 1, "ACK");
  } else {
    append_field(grid, &x, &y, 1, "ack");
  }

  // PSH
  if (tcp->psh) {
    append_field(grid, &x, &y, 1, "PSH");
  } else {
    append_field(grid, &x, &y, 1, "psh");
  }

  // RST
  if (tcp->rst) {
    append_field(grid, &x, &y, 1, "RST");
  } else {
    append_field(grid, &x, &y, 1, "rst");
  }

  // SYN
  if (tcp->syn) {
    append_field(grid, &x, &y, 1, "SYN");
  } else {
    append_field(grid, &x, &y, 1, "syn");
  }

  // FIN
  if (tcp->fin) {
    append_field(grid, &x, &y, 1, "FIN");
  } else {
    append_field(grid, &x, &y, 1, "fin");
  }

  // window size
  sprintf(label, "Window Size: %u", htons(tcp->window));
  append_field(grid, &x, &y, sizeof(tcp->window)*8, label);

  // checksum
  sprintf(label, "Checksum: 0x%04x", htons(tcp->check));
  append_field(grid, &x, &y, sizeof(tcp->check)*8, label);

  // urgent pointer
  sprintf(label, "Urgent Pointer: %u", htons(tcp->urg_ptr));
  append_field(grid, &x, &y, sizeof(tcp->urg_ptr)*8, label);

  // count bytes of option fields
  left = (tcp->doff-0x05)*4;

  // progress bytes until no option bytes left
  while (left > 0) {
    // get option type (first byte)
    opttype = options[0];

    // TODO: switch-case check for option type, the current solution is "dirty"

    // option dependent output (some options dont have a kind field)
    if (opttype == 0x01) {
      // no operation option (pad option - NO kind field)
      sprintf(label, "Option Kind: 1 (NOP)");
      append_field(grid, &x, &y, 8, label);

      optlen = 1;
    } else {
      // options with kind and length field

      // option kind
      sprintf(label, "Option Kind: %u", opttype);
      append_field(grid, &x, &y, 8, label);

      // option length (INCLUDING type and kind field)
      optlen = options[1];
      sprintf(label, "Option Length: %u", optlen);
      append_field(grid, &x, &y, 8, label);

      // option has additional option data?
      if (optlen > 2) {

        // allocate memory for option data (*2 because of hex representation)
        optdata = malloc(optlen*2);

        // print bytes in hex format into array
        for (i=0; i<optlen-2; ++i) sprintf(&optdata[i*2], "%02x", (unsigned int)options[i+2]);
        optdata[(optlen-2)*2] = 0x00;

        // option data field
        sprintf(label, "Option Data: 0x%s", optdata);
        append_field(grid, &x, &y, (optlen-2)*8, label);

        // free data
        free(optdata);
      }
    }

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

GtkGrid *udp_grid(struct udphdr *udp) {
  GtkGrid *grid;	// the grid itself
  char *label;		// label of buttons to set
  int x,y;		// position pointer to next empty grid cell

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

  // source port
  sprintf(label, "Source Port: %u", htons(udp->source));
  append_field(grid, &x, &y, sizeof(udp->source)*8, label);

  // destination port
  sprintf(label, "Destination Port: %u", htons(udp->dest));
  append_field(grid, &x, &y, sizeof(udp->dest)*8, label);

  // length
  sprintf(label, "Length: %u", htons(udp->len));
  append_field(grid, &x, &y, sizeof(udp->len)*8, label);

  // checksum
  sprintf(label, "Checksum: 0x%02x", htons(udp->check));
  append_field(grid, &x, &y, sizeof(udp->check)*8, label);

  // free memory of label
  free(label);

  // show ethernet grid (tab)
  gtk_widget_show_all(GTK_WIDGET(grid));

  // pass grid back to tab builder function
  return(grid);
}

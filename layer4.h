///////////////////////////////////////////////////////////////////////////////////
// netmate layer4 protocols //
///////////////////////////////////////////////////////////////////////////////////

GtkGrid *tcp_grid(struct tcphdr *tcp, u_char *options) {
  GtkGrid *grid;
  int x,y;
  char *label;		// label of buttons to set

  grid = GTK_GRID(gtk_grid_new());

  gtk_grid_set_column_homogeneous(grid, TRUE);

  // allocate memory for button label
  label = malloc(100);

  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  x=0;
  y=1;

  sprintf(label, "Source Port: %u", htons(tcp->source));
  append_field(grid, &x, &y, sizeof(tcp->source)*8, label);

  sprintf(label, "Destination Port: %u", htons(tcp->dest));
  append_field(grid, &x, &y, sizeof(tcp->dest)*8, label);

  sprintf(label, "Sequence Number: %u", htonl(tcp->seq));
  append_field(grid, &x, &y, sizeof(tcp->seq)*8, label);

  sprintf(label, "Acknowledgement Number: %u", htonl(tcp->ack_seq));
  append_field(grid, &x, &y, sizeof(tcp->ack_seq)*8, label);

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

  sprintf(label, "Window Size: %u", htons(tcp->window));
  append_field(grid, &x, &y, sizeof(tcp->window)*8, label);

  sprintf(label, "Checksum: 0x%04x", htons(tcp->check));
  append_field(grid, &x, &y, sizeof(tcp->check)*8, label);

  sprintf(label, "Urgent Pointer: %u", htons(tcp->urg_ptr));
  append_field(grid, &x, &y, sizeof(tcp->urg_ptr)*8, label);

  int left = (tcp->doff-0x05)*4;
  int optlen;
  int opttype;
  int i;
  char *optdata;
  while (left > 0) {
    opttype = options[0];

    if (opttype == 0x01) {
      sprintf(label, "Option Kind: 1 (NOP)");
      append_field(grid, &x, &y, 8, label);

      optlen = 1;
    } else {

      sprintf(label, "Option Kind: %u", opttype);
      append_field(grid, &x, &y, 8, label);

      optlen = options[1];
      sprintf(label, "Option Length: %u", optlen);
      append_field(grid, &x, &y, 8, label);

      if (optlen > 2) {

        optdata = malloc(optlen*2);

        for (i=0; i<optlen-2; ++i)
          sprintf(&optdata[i*2], "%02x", (unsigned int)options[i+2]);

        optdata[optlen] = 0x00;
        sprintf(label, "Option Data: 0x%s", optdata);

        append_field(grid, &x, &y, (optlen-2)*8, label);
        free(optdata);
      }
    }

    left -= optlen;
    options = options + optlen;
  }

  // free memory of label
  free(label);

  // show ethernet grid (tab)
  gtk_widget_show_all(GTK_WIDGET(grid));

  return(grid);
}

///////////////////////////////////////////////////////////////////////////////////
// netmate layer2 protocols //
///////////////////////////////////////////////////////////////////////////////////

GtkGrid *ethernet_grid(struct ether_header *eth);	// ethernet
GtkGrid *sll_grid(struct sll_header *sll);		// ssl (linux cooked)

///////////////////////////////////////////////////////////////////////////////////

GtkGrid *sll_grid(struct sll_header *sll) {
  GtkGrid *grid;	// the grid itself
  int x, y;		// position of next empty grid cell
  char *label;		// label of buttons to set

  // init a new empty grid
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

  // Packet Type
  sprintf(label, "Packet Type: %u", htons(sll->sll_pkttype));
  append_field(grid, &x, &y, sizeof(sll->sll_pkttype)*8, label);

  // ARP Header Type
  sprintf(label, "ARPHDR_ Type: %u", htons(sll->sll_hatype));
  append_field(grid, &x, &y, sizeof(sll->sll_hatype)*8, label);

  // Link-layer Address Length
  sprintf(label, "Link-layer Address Length: %u", htons(sll->sll_halen));
  append_field(grid, &x, &y, sizeof(sll->sll_halen)*8, label);

  // Link-layer Address
  sprintf(label, "Link-layer Address: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2], sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5], sll->sll_addr[6], sll->sll_addr[7]);
  append_field(grid, &x, &y, sizeof(sll->sll_addr)*8, label);

  // Upper Layer Protocol
  sprintf(label, "Protocol Type: 0x%04x", htons(sll->sll_protocol));
  append_field(grid, &x, &y, sizeof(sll->sll_protocol)*8, label);

  // free memory of label
  free(label);

  // show ethernet grid (tab)
  gtk_widget_show_all(GTK_WIDGET(grid));

  // return grid to tab builder
  return(grid);
}

GtkGrid *ethernet_grid(struct ether_header *eth) {
  GtkGrid *grid;	// the grid itself
  int x, y;		// position pointer to next empty grid cell
  char *label;		// label of buttons to set

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

  // destination mac
  sprintf(label, "Destination: %02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
  append_field(grid, &x, &y, sizeof(eth->ether_dhost)*8, label);

  // source mac
  sprintf(label, "Source: %02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  append_field(grid, &x, &y, sizeof(eth->ether_shost)*8, label);

  // upper layer protocol
  sprintf(label, "Type: 0x%04x", htons(eth->ether_type));
  append_field(grid, &x, &y, sizeof(eth->ether_type)*8, label);

  // free memory of label
  free(label);

  // show ethernet grid (tab)
  gtk_widget_show_all(GTK_WIDGET(grid));

  // return grid to tab builder
  return(grid);
}

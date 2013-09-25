///////////////////////////////////////////////////////////////////////////////////
// netmate layer2 protocols //
///////////////////////////////////////////////////////////////////////////////////

GtkGrid *ethernet_grid(struct ether_header *eth);
GtkGrid *sll_grid(struct sll_header *sll);

///////////////////////////////////////////////////////////////////////////////////

GtkGrid *sll_grid(struct sll_header *sll) {
  GtkGrid *grid;
  int x, y;
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

  sprintf(label, "Packet Type: %u", htons(sll->sll_pkttype));
  append_field(grid, &x, &y, sizeof(sll->sll_pkttype)*8, label);

  sprintf(label, "ARPHDR_ Type: %u", htons(sll->sll_hatype));
  append_field(grid, &x, &y, sizeof(sll->sll_hatype)*8, label);

  sprintf(label, "Link-layer Address Length: %u", htons(sll->sll_halen));
  append_field(grid, &x, &y, sizeof(sll->sll_halen)*8, label);

  sprintf(label, "Link-layer Address: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2], sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5], sll->sll_addr[6], sll->sll_addr[7]);
  append_field(grid, &x, &y, sizeof(sll->sll_addr)*8, label);

  sprintf(label, "Protocol Type: 0x%04x", htons(sll->sll_protocol));
  append_field(grid, &x, &y, sizeof(sll->sll_protocol)*8, label);

  // free memory of label
  free(label);

  // show ethernet grid (tab)
  gtk_widget_show_all(GTK_WIDGET(grid));

  return(grid);
}

GtkGrid *ethernet_grid(struct ether_header *eth) {
  GtkGrid *grid;
  int x, y;
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

  return(grid);
}

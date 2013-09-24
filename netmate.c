#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <pcap/sll.h>
#include <gtk/gtk.h>

#ifndef WIN32
  #include <arpa/inet.h>
  #include <netinet/if_ether.h>
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
#endif

// THE VERSION OF NETMATE
#define VERSION "0.13"

// ADDITIONAL LINK TYPES
#define LINKTYPE_LINUX_SLL 113

void loadpcapfile(GtkWidget *widget, GtkListStore *packetliststore);
void append_field(GtkGrid *grid, int *x, int *y, int size, char *label);

char *filename = NULL;

// global grids (protocol container)
GtkNotebook *protocolheadernotebook;

////////////////////////////////////////////////////////////////////////////////////////////////////
// GTK INFORMATION WINDOWS //
////////////////////////////////////////////////////////////////////////////////////////////////////

// shows an error popup with given (char*) as message
void show_error(GtkWidget *widget, gpointer message) {
  GtkWidget *toplevel;	// the toplevel window
  GtkWidget *dialog;	// the dialog object

  // get toplevel from widget
  toplevel = gtk_widget_get_toplevel(widget);

  // show window only if toplevel
  if (gtk_widget_is_toplevel(toplevel)) {

    // create new dialog
    dialog = gtk_message_dialog_new(GTK_WINDOW(toplevel), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", (char*)message);

    // set title
    gtk_window_set_title(GTK_WINDOW(dialog), "Error");

    // run dialog
    gtk_dialog_run(GTK_DIALOG(dialog));

    // destroy dialog
    gtk_widget_destroy(dialog);
  }
}

// shows a warning popup with given (char*) as message
void show_warning(GtkWidget *widget, gpointer message) {
  GtkWidget *toplevel;	// the toplevel window
  GtkWidget *dialog;	// the dialog object

  // get toplevel from widget
  toplevel = gtk_widget_get_toplevel(widget);

  // show window only if toplevel
  if (gtk_widget_is_toplevel(toplevel)) {

    // create new dialog
    dialog = gtk_message_dialog_new(GTK_WINDOW(toplevel), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "%s", (char*)message);

    // set title
    gtk_window_set_title(GTK_WINDOW(dialog), "Warning");

    // run dialog
    gtk_dialog_run(GTK_DIALOG(dialog));

    // destroy dialog
    gtk_widget_destroy(dialog);
  }
}

// shows an information popup with given (char*) as message
void show_information(GtkWidget *widget, gpointer message) {
  GtkWidget *toplevel;	// the toplevel window
  GtkWidget *dialog;	// the dialog object

  // get toplevel from widget
  toplevel = gtk_widget_get_toplevel(widget);

  // show window only if toplevel
  if (gtk_widget_is_toplevel(toplevel)) {

    // create new dialog
    dialog = gtk_message_dialog_new(GTK_WINDOW(toplevel), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", (char*)message);

    // set title
    gtk_window_set_title(GTK_WINDOW(dialog), "Information");

    // run dialog
    gtk_dialog_run(GTK_DIALOG(dialog));

    // destroy dialog
    gtk_widget_destroy(dialog);
  }
}

// shows a questiong popup with given (char*) as message
gint show_question(GtkWidget *widget, gpointer message) {
  GtkWidget *toplevel;	// the toplevel window
  GtkWidget *dialog;	// the dialog object
  int ret = -1;		// return value (clicked button) GTK_RESPONSE_NO or GTK_RESPONSE_YES

  // get toplevel from widget
  toplevel = gtk_widget_get_toplevel(widget);

  // show window only if toplevel
  if (gtk_widget_is_toplevel(toplevel)) {
    // create new dialog
    dialog = gtk_message_dialog_new(GTK_WINDOW(toplevel), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s", (char*)message);

    // set title
    gtk_window_set_title(GTK_WINDOW(dialog), "Question");

    // run dialog and get click as int
    ret = gtk_dialog_run(GTK_DIALOG(dialog));

    // destroy dialog
    gtk_widget_destroy(dialog);
  }

  // return clicked button
  return(ret);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

GtkGrid *sll_grid(struct sll_header *sll) {
  GtkGrid *grid;
  int x;
  char *label;		// label of buttons to set

  grid = GTK_GRID(gtk_grid_new());

  gtk_grid_set_column_homogeneous(grid, TRUE);

  // allocate memory for button label
  label = malloc(100);

  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  sprintf(label, "Packet Type (0x%04x)", htons(sll->sll_pkttype));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 1, 16, 1);

  sprintf(label, "ARPHDR_ Type (0x%04x)", htons(sll->sll_hatype));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 1, 16, 1);

  sprintf(label, "Link-layer Address Length (0x%04x)", htons(sll->sll_halen));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 2, 16, 1);

  sprintf(label, "Link-layer Address (%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x)", sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2], sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5], sll->sll_addr[6], sll->sll_addr[7]);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 2, 16, 1);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 3, 32, 1);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 4, 16, 1);

  sprintf(label, "Protocol Type (0x%04x)", htons(sll->sll_protocol));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 4, 16, 1);

  // free memory of label
  free(label);

  // show ethernet grid (tab)
  gtk_widget_show_all(GTK_WIDGET(grid));

  return(grid);
}

GtkGrid *ethernet_grid(struct ether_header *eth) {
  GtkGrid *grid;
  int x;
  char *label;		// label of buttons to set

  grid = GTK_GRID(gtk_grid_new());

  gtk_grid_set_column_homogeneous(grid, TRUE);

  // allocate memory for button label
  label = malloc(100);

  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  // destination mac
  sprintf(label, "Destination (%02x:%02x:%02x:%02x:%02x:%02x)", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 1, 32, 1);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 2, 16, 1);

  // source mac
  sprintf(label, "Source (%02x:%02x:%02x:%02x:%02x:%02x)", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 2, 16, 1);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 3, 32, 1);

  // upper layer protocol
  sprintf(label, "Type\n(0x%04x)", htons(eth->ether_type));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 4, 2, 1);

  // free memory of label
  free(label);

  // show ethernet grid (tab)
  gtk_widget_show_all(GTK_WIDGET(grid));

  return(grid);
}

GtkGrid *ipv4_grid(struct iphdr *ipv4, u_char *options) {
  GtkGrid *grid;
  int x;
  char *label;		// label of buttons to set
  char ipv4_dscp;			// ip dscp field
  char ipv4_ecn;			// ip ecn field
  char ipv4_flags;			// ip header flags
  short ipv4_offset;			// ip fragment offset

  grid = GTK_GRID(gtk_grid_new());

  gtk_grid_set_column_homogeneous(grid, TRUE);

  // allocate memory for button label
  label = malloc(100);

  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  // read and set ip version field
  sprintf(label, "Version (%u)", ipv4->version);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 1, 4, 1);

  // read and set ip header length (<< 2 to calculate real size)
  sprintf(label, "IHL (0x%02x)", ipv4->ihl);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 4, 1, 4, 1);

  // read and set ip dscp field
  ipv4_dscp = ipv4->tos >> 2;
  sprintf(label, "DSCP (0x%02x)", ipv4_dscp);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 8, 1, 6, 1);

  // read and set ip ecn field
  ipv4_ecn = ipv4->tos & 0x03;
  sprintf(label, "ECN\n(0x%02x)", ipv4_ecn);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 14, 1, 2, 1);
//  sprintf(label, "<span size='7000'>ECN (0x%02x)</span>", ipv4_ecn);
//  GtkWidget *test = gtk_label_new(NULL);
//  gtk_label_set_markup(GTK_LABEL(test), label);
//  gtk_button_set_image(ipv4_ecnbutton, test);

  // read and set total length of ip header
  sprintf(label, "Total Length (%u)", htons(ipv4->tot_len));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 1, 16, 1);

  // read and set identification field of ip packet
  sprintf(label, "Identification (0x%04x)", htons(ipv4->id));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 2, 16, 1);

  // read and set ip header flags
  ipv4_flags = htons(ipv4->frag_off) >> 13;
  sprintf(label, "Flags (0x%02x)", ipv4_flags);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 2, 3, 1);

  // read and set ip fragmentation offset (<< 3 to calculate real size);
  ipv4_offset = (htons(ipv4->frag_off) & 0x1fff);
  sprintf(label, "Fragment Offset (0x%04x)", ipv4_offset);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 19, 2, 13, 1);

  // read and set time to live of ip packet
  sprintf(label, "Time To Live (%u)", ipv4->ttl);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 3, 8, 1);

  // read an d set upper layer protocol
  sprintf(label, "Protocol (%u)", ipv4->protocol);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 8, 3, 8, 1);

  // read and set ip header checksum
  sprintf(label, "Header checksum (0x%04x)", htons(ipv4->check));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 3, 16, 1);

  // read and set ip source address
  sprintf(label, "Source IP Address (0x%08x = %u.%u.%u.%u)", htonl(ipv4->saddr), ipv4->saddr & 0xff, (ipv4->saddr >> 8) & 0xff, (ipv4->saddr >> 16) & 0xff, (ipv4->saddr >> 24) & 0xff);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 4, 32, 1);

  // read and set ip destination address
  sprintf(label, "Destination IP Address (0x%08x = %u.%u.%u.%u)", htonl(ipv4->daddr), ipv4->daddr & 0xff, (ipv4->daddr >> 8) & 0xff, (ipv4->daddr >> 16) & 0xff, (ipv4->daddr >> 24) & 0xff);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 5, 32, 1);

  int y = 6;
  int left = (ipv4->ihl-0x05)*4;
  x = 0;
  int optlen;
  int opttype;
  char *optdata;
  while (left > 0) {
    opttype = options[0];

    sprintf(label, "Opt. Type (0x%02x)", opttype);
    append_field(grid, &x, &y, 8, label);

    optlen = options[1];
    sprintf(label, "Opt. Len (0x%02x)", optlen);
    append_field(grid, &x, &y, 8, label);

    optdata = malloc(optlen-2);
    memcpy(options+2, optdata, optlen-2);
    sprintf(label, "Opt. Data XXX");
    append_field(grid, &x, &y, (optlen-2)*8, label);
    free(optdata);

    left -= optlen;
    options = options + optlen;
  }

  // free memory of label
  free(label);

  // show ethernet grid (tab)
  gtk_widget_show_all(GTK_WIDGET(grid));

  return(grid);
}

void append_field(GtkGrid *grid, int *x, int *y, int size, char *label) {
  while (*x + size > 32) {
    gtk_grid_attach(grid, gtk_button_new_with_label(label), *x, *y, 32-*x, 1);
    size -= 32-*x;
    *x = 0;
    *y = *y + 1;
  }

  gtk_grid_attach(grid, gtk_button_new_with_label(label), *x, *y, size, 1);
  *x = *x + size;
  if (*x == 32) { *x = 0; *y = *y + 1; }
}

GtkGrid *tcp_grid(struct tcphdr *tcp, u_char *options) {
  GtkGrid *grid;
  int x;
  char *label;		// label of buttons to set

  grid = GTK_GRID(gtk_grid_new());

  gtk_grid_set_column_homogeneous(grid, TRUE);

  // allocate memory for button label
  label = malloc(100);

  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  sprintf(label, "Source Port (%u)", htons(tcp->source));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 1, 16, 1);

  sprintf(label, "Destination Port (%u)", htons(tcp->dest));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 1, 16, 1);

  sprintf(label, "Sequence Number (%u)", htonl(tcp->seq));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 2, 32, 1);

  sprintf(label, "Acknowledgement Number (%u)", htonl(tcp->ack_seq));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 3, 32, 1);

  sprintf(label, "Data Offset (0x%02x)", tcp->doff);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 4, 4, 1);

  sprintf(label, "Reserved (0x%02x)", tcp->res1 & 0x0e);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 4, 4, 3, 1);

  sprintf(label, "Flags (%u%u%u%u%u%u%u%u%ub)", tcp->res1 & 0x01, tcp->res2 & 0x02, tcp->res2 & 0x01, tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 7, 4, 9, 1);

  sprintf(label, "Window Size (%u)", htons(tcp->window));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 4, 16, 1);

  sprintf(label, "Checksum (0x%04x)", htons(tcp->check));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 0, 5, 16, 1);

  sprintf(label, "Urgent Pointer (0x%04x)", htons(tcp->urg_ptr));
  gtk_grid_attach(grid, gtk_button_new_with_label(label), 16, 5, 16, 1);

  int y = 6;
  int left = (tcp->doff-0x05)*4;
  x = 0;
  int optlen;
  int opttype;
  char *optdata;
  while (left > 0) {
    opttype = options[0];

    if (opttype == 0x01) {
      sprintf(label, "NOP");
      append_field(grid, &x, &y, 8, label);

      optlen = 1;
    } else {

      sprintf(label, "Opt. Type (0x%02x)", opttype);
      append_field(grid, &x, &y, 8, label);

      optlen = options[1];
      sprintf(label, "Opt. Len (0x%02x)", optlen);
      append_field(grid, &x, &y, 8, label);

      if (optlen > 2) {

        optdata = malloc(optlen-2);
        memcpy(options+2, optdata, optlen-2);
        sprintf(label, "Opt. Data XXX");
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

void display_packet(GtkWidget *widget, gpointer data) {
  GtkTreeSelection *selection;		// tree selection
  GtkTreeModel     *model;		// tree model
  GtkTreeIter       iter;		// tree iterator
  pcap_t *handler;			// pcap file handler
  char errbuf[PCAP_ERRBUF_SIZE];	// pcap error buffer
  struct pcap_pkthdr *header;		// the header from libpcap
  const u_char *packet;			// current packet pointer
  unsigned int packetnumber;		// currently secected packet number
  struct ether_header *eth;
  struct sll_header *sll;		// sll header (linux cooked)
  struct iphdr *ipv4;			// ipv4_header pointer
  struct tcphdr *tcp;
  int i = 1;				// loop counter to track packet
  unsigned short layer3 = 0;
  void *layer3ptr = NULL;

  if (filename == NULL) return;

  // open pcap to find packet
  handler = pcap_open_offline(filename, errbuf);
  if (handler == NULL) return;

  // get currently selected packet
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(widget));
  if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
    gtk_tree_model_get(model, &iter, 0, &packetnumber, -1);
  }

  // iterate through packets until selected packet is found
  // this might also be done by preloading of this technique is too slow
  while (i++ <= packetnumber) pcap_next_ex(handler, &header, &packet);

  // remember tab position and hide all tabs
  int pos;
  pos = gtk_notebook_get_current_page(protocolheadernotebook);

  // clear grids
  while (gtk_notebook_get_n_pages(protocolheadernotebook) > 0) {
    gtk_notebook_remove_page(protocolheadernotebook, 0);
  }

  switch (pcap_datalink(handler)) {

    case DLT_EN10MB:
      // set pointer to ethernet header
      eth = (struct ether_header*)(packet);

      // display ethernet tab
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(ethernet_grid(eth)), gtk_label_new("Ethernet"));

      layer3 = htons(eth->ether_type);
      layer3ptr = (void*)(packet + sizeof(struct ether_header));

      break;
    case LINKTYPE_LINUX_SLL:
      // LINUX COOKED
      sll = (struct sll_header*)(packet);

      // display sll tab
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(sll_grid(sll)), gtk_label_new("Linux Cooked"));

      layer3 = htons(sll->sll_protocol);
      layer3ptr = (void*)(packet + sizeof(struct sll_header));

      break;
    default:
      show_error(widget, "Unsupported link-layer. Please request author to add it!");
      printf("Layer type: %u\n", pcap_datalink(handler));
      return;
  }

  switch (layer3) {
    case ETHERTYPE_IP:
      // IPV4
      ipv4 = (struct iphdr*)layer3ptr;

      // display ipv4 tab
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(ipv4_grid(ipv4, ((u_char*)ipv4 + sizeof(struct iphdr)))), gtk_label_new("IPv4"));

      switch (ipv4->protocol) {
        case IPPROTO_TCP:
          tcp = (struct tcphdr*)(layer3ptr + sizeof(struct iphdr));

          gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(tcp_grid(tcp, ((u_char*)tcp + sizeof(struct tcphdr)))), gtk_label_new("TCP"));

          break;
      }

      break;
  }

  // switch to tab that was former selected
  if ((pos >= 0) && (pos < gtk_notebook_get_n_pages(protocolheadernotebook))) {
    gtk_notebook_set_current_page(protocolheadernotebook, pos);
  }

  // close pcap handler
  pcap_close(handler);
}

void openpcapfile(GtkWidget *widget, gpointer data) {
  GtkDialog *fileopendialog;

  fileopendialog = GTK_DIALOG(gtk_file_chooser_dialog_new ("Open File",
     				      GTK_WINDOW(gtk_widget_get_toplevel(widget)),
     				      GTK_FILE_CHOOSER_ACTION_OPEN,
     				      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
     				      GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
     				      NULL));
  gtk_window_resize(GTK_WINDOW(fileopendialog), 1000, 500);

  if (gtk_dialog_run (GTK_DIALOG (fileopendialog)) == GTK_RESPONSE_ACCEPT) {
    filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (fileopendialog));
    loadpcapfile(widget, GTK_LIST_STORE(data));
  }

  gtk_widget_destroy(GTK_WIDGET(fileopendialog));
}

void getinfo(pcap_t *handler, const u_char *packet, char **source, char **destination) {
  struct ether_header *eth;
  struct iphdr *ipv4;                   // ipv4_header pointer
  struct sll_header *sll;               // sll header (linux cooked)
  unsigned short layer3 = 0;
  void *layer3ptr = NULL;

  *source = malloc(100);
  *destination = malloc(100);
  memset(*source, 0, 100);
  memset(*destination, 0, 100);

  switch (pcap_datalink(handler)) {

    case DLT_EN10MB:
      // set pointer to ethernet header
      eth = (struct ether_header*)(packet);

      sprintf(*source, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
      sprintf(*destination, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

      layer3 = htons(eth->ether_type);
      layer3ptr = (void*)(packet + sizeof(struct ether_header));

      break;
    case LINKTYPE_LINUX_SLL:
      // LINUX COOKED
      sll = (struct sll_header*)(packet);

      // TODO: need to check sll->halen to get REAL size (6 chosen here)
      sprintf(*source, "%02x:%02x:%02x:%02x:%02x:%02x", sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2], sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
      // destination is unknown in SLL

      layer3 = htons(sll->sll_protocol);
      layer3ptr = (void*)(packet + sizeof(struct sll_header));

      break;
  }

  switch (layer3) {
    case ETHERTYPE_IP:
      // IPV4
      ipv4 = (struct iphdr*)layer3ptr;

      sprintf(*source, "%u.%u.%u.%u", ipv4->saddr & 0xff, (ipv4->saddr >> 8) & 0xff, (ipv4->saddr >> 16) & 0xff, (ipv4->saddr >> 24) & 0xff);
      sprintf(*destination, "%u.%u.%u.%u", ipv4->daddr & 0xff, (ipv4->daddr >> 8) & 0xff, (ipv4->daddr >> 16) & 0xff, (ipv4->daddr >> 24) & 0xff);

      break;
  }
}

void loadpcapfile(GtkWidget *widget, GtkListStore *packetliststore) {
  GtkTreeIter iter;             	// iterator for filling tree view
  char errbuf[PCAP_ERRBUF_SIZE];	// pcap error buffer
  unsigned int i;			// loop variable
  struct pcap_pkthdr *header;		// pointer to pcap header
  const u_char *packet;			// pcap packet pointer
  pcap_t *handler;			// pcap file handler

  // clear all items
  gtk_list_store_clear(packetliststore);

  // clear grids
  while (gtk_notebook_get_n_pages(protocolheadernotebook) > 0) {
    gtk_notebook_remove_page(protocolheadernotebook, 0);
  }

  // check for empty file pointer
  if (filename == NULL) return;

  // check if file exists
  if (access(filename, F_OK ) == -1 ) {
    show_error(widget, "File not found.");
    filename = NULL;
    return;
  }

  //open file and create pcap handler
  handler = pcap_open_offline(filename, errbuf);

  // check for proper pcap file
  if (handler == NULL ) {
    show_error(widget, "Invalid pcap format, try pcapfix :P");
    filename = NULL;
    return;
  }

  long begintime = -1;
  long beginutime;
  long realtime;
  long realutime;
  char *pcaptime = malloc(20);
  char *source;
  char *destination;

  // read packets from file and fill tree view
  i = 1;
  while (pcap_next_ex(handler, &header, &packet) >= 0) {
    if (begintime == -1) {
       begintime = (header->ts).tv_sec;
       beginutime = (header->ts).tv_usec;
    }

    realtime = (header->ts).tv_sec-begintime;
    realutime = (header->ts).tv_usec-beginutime;
    if (realutime < 0) {
      realtime--;
      realutime += 1000000;
    }

    sprintf(pcaptime, "%ld.%06ld", realtime, realutime);
    getinfo(handler, packet, &source, &destination);

    // insert new row into tree view
    gtk_list_store_insert_with_values(packetliststore, &iter, -1, 0,  i++, 1, pcaptime, 2, source, 3, destination, -1);
  }

  free(pcaptime);
  free(source);
  free(destination);

  // close pcap handler
  pcap_close(handler);
}

/// MAIN FUNCTION ///
int main (int argc, char *argv[]) {
  GtkBuilder *builder;			// the GUI builder object
  GtkWindow *mainwindow;		// main window object
  GtkListStore *packetliststore;	// list store for packets
  GtkTreeView *packettreeview;		// tree view for packets
  GtkImageMenuItem *openimagemenuitem;	// file open menu
  GtkImageMenuItem *quitimagemenuitem;	// quit menu
  char *title;				// title of the program (main window)

  // init GTK with console parameters (change to getopts later)
  gtk_init(NULL, NULL);

  // load UI descriptions from file
  builder = gtk_builder_new ();
  gtk_builder_add_from_file(builder, "netmate.ui", NULL);
  // for fileless compiling (gtk_builder_add_from_string)

  // init main window
  mainwindow = GTK_WINDOW(gtk_builder_get_object (builder, "mainwindow"));
  g_signal_connect(mainwindow, "destroy", G_CALLBACK(gtk_main_quit), NULL);

  // init packet list store (database)
  packetliststore = GTK_LIST_STORE(gtk_builder_get_object (builder, "packetliststore"));

  // init protocol header field(s)
  protocolheadernotebook = GTK_NOTEBOOK(gtk_builder_get_object (builder, "protocolheadernotebook"));

  // init open file menu
  openimagemenuitem = GTK_IMAGE_MENU_ITEM(gtk_builder_get_object (builder, "openimagemenuitem"));
  g_signal_connect(openimagemenuitem, "activate", G_CALLBACK(openpcapfile), packetliststore);

  // init quit menu
  quitimagemenuitem = GTK_IMAGE_MENU_ITEM(gtk_builder_get_object (builder, "quitimagemenuitem"));
  g_signal_connect(quitimagemenuitem, "activate", G_CALLBACK(gtk_main_quit), NULL);

  // init packet tree view (database representation)
  packettreeview = GTK_TREE_VIEW(gtk_builder_get_object (builder, "packettreeview"));
  g_signal_connect (packettreeview, "cursor-changed", G_CALLBACK(display_packet), NULL);

  // set title of main window
  title = malloc(100);
  sprintf(title, "NetMate v%s", VERSION);
  gtk_window_set_title(mainwindow, title);
  free(title);

  while (gtk_events_pending ()) gtk_main_iteration ();

  // try loading filename from parameters
  if (argv[1] != NULL) {
    filename = argv[1];
    loadpcapfile(GTK_WIDGET(mainwindow), packetliststore);
  }

  // ENTER MAIN LOOP
  gtk_main();

  // exit
  return(0);
}

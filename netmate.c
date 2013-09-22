#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <gtk/gtk.h>

#ifndef WIN32
  #include <arpa/inet.h>
  #include <netinet/if_ether.h>
  #include <netinet/ip.h>
#endif

// THE VERSION OF NETMATE
#define VERSION "0.06"

void loadpcapfile(GtkWidget *widget, GtkListStore *packetliststore);

char *filename = NULL;

// global ethernet buttons
GtkButton *eth_destmacbutton;
GtkButton *eth_sourcemacbutton;
GtkButton *eth_typebutton;

// global ipv4 buttons
GtkButton *ipv4_versionbutton;
GtkButton *ipv4_ihlbutton;
GtkButton *ipv4_dscpbutton;
GtkButton *ipv4_ecnbutton;
GtkButton *ipv4_totallengthbutton;
GtkButton *ipv4_identificationbutton;
GtkButton *ipv4_flagsbutton;
GtkButton *ipv4_fragmentoffsetbutton;
GtkButton *ipv4_timetolivebutton;
GtkButton *ipv4_protocolbutton;
GtkButton *ipv4_headerchecksumbutton;
GtkButton *ipv4_sourceipaddressbutton;
GtkButton *ipv4_destinationipaddressbutton;

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

void display_packet(GtkWidget *widget, gpointer data) {
  GtkTreeSelection *selection;		// tree selection
  GtkTreeModel     *model;		// tree model
  GtkTreeIter       iter;		// tree iterator
  pcap_t *handler;			// pcap file handler
  struct pcap_pkthdr *header;		// the header from libpcap
  const u_char *packet;			// current packet pointer
  unsigned int packetnumber;		// currently secected packet number
  char *label;				// label of buttons to set
  int i = 1;				// loop counter to track packet
  char errbuf[PCAP_ERRBUF_SIZE];	// pcap error buffer
  const struct ether_header *eth;
  const struct iphdr *ip;		// ipv4_header pointer

  // ipv4_header helper vars
  char ipv4_version;			// ip version
  char ipv4_headerlength;		// ip header length
  char ipv4_dscp;			// ip dscp field
  char ipv4_ecn;			// ip ecn field
  char ipv4_flags;			// ip header flags
  short ipv4_offset;			// ip fragment offset

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

  // allocate memory for button label
  label = malloc(100);

  // ETHERNET
  eth = (struct ether_header*)(packet);

  // destination mac
  sprintf(label, "Destination (%02x:%02x:%02x:%02x:%02x:%02x)", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
  gtk_button_set_label(eth_destmacbutton, label);

  // source mac
  sprintf(label, "Source (%02x:%02x:%02x:%02x:%02x:%02x)", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  gtk_button_set_label(eth_sourcemacbutton, label);

  // source mac
  sprintf(label, "Type (0x%04x)", htons(eth->ether_type));
  gtk_button_set_label(eth_typebutton, label);

  // IPV4
  ip = (struct iphdr*)(packet + sizeof(struct ether_header));

  // read and set ip version field
  ipv4_version = ip->version;
  sprintf(label, "Version (%u)", ipv4_version);
  gtk_button_set_label(ipv4_versionbutton, label);

  // read and set ip header length (<< 2 to calculate real size)
  ipv4_headerlength = ip->ihl;
  sprintf(label, "IHL (0x%02x)", ipv4_headerlength);
  gtk_button_set_label(ipv4_ihlbutton, label);

  // read and set ip dscp field
  ipv4_dscp = ip->tos >> 2;
  sprintf(label, "DSCP (0x%02x)", ipv4_dscp);
  gtk_button_set_label(ipv4_dscpbutton, label);

  // read and set ip ecn field
  ipv4_ecn = ip->tos & 0x03;
  sprintf(label, "ECN\n(0x%02x)", ipv4_ecn);
//  sprintf(label, "<span size='7000'>ECN (0x%02x)</span>", ipv4_ecn);
//  GtkWidget *test = gtk_label_new(NULL);
//  gtk_label_set_markup(GTK_LABEL(test), label);
  gtk_button_set_label(ipv4_ecnbutton, label);
//  gtk_button_set_image(ipv4_ecnbutton, test);

  // read and set total length of ip header
  sprintf(label, "Total Length (%u)", htons(ip->tot_len));
  gtk_button_set_label(ipv4_totallengthbutton, label);

  // read and set identification field of ip packet
  sprintf(label, "Identification (0x%04x)", htons(ip->id));
  gtk_button_set_label(ipv4_identificationbutton, label);

  // read and set ip header flags
  ipv4_flags = htons(ip->frag_off) >> 13;
  sprintf(label, "Flags (0x%02x)", ipv4_flags);
  gtk_button_set_label(ipv4_flagsbutton, label);

  // read and set ip fragmentation offset (<< 3 to calculate real size);
  ipv4_offset = (htons(ip->frag_off) & 0x1fff);
  sprintf(label, "Fragment Offset (0x%04x)", ipv4_offset);
  gtk_button_set_label(ipv4_fragmentoffsetbutton, label);

  // read and set time to live of ip packet
  sprintf(label, "Time To Live (%u)", ip->ttl);
  gtk_button_set_label(ipv4_timetolivebutton, label);

  // read an d set upper layer protocol
  sprintf(label, "Protocol (%u)", ip->protocol);
  gtk_button_set_label(ipv4_protocolbutton, label);

  // read and set ip header checksum
  sprintf(label, "Header checksum (0x%04x)", htons(ip->check));
  gtk_button_set_label(ipv4_headerchecksumbutton, label);

  // read and set ip source address
  sprintf(label, "Source IP Address (0x%08x = %u.%u.%u.%u)", htonl(ip->saddr), ip->saddr & 0xff, (ip->saddr >> 8) & 0xff, (ip->saddr >> 16) & 0xff, (ip->saddr >> 24) & 0xff);
  gtk_button_set_label(ipv4_sourceipaddressbutton, label);

  // read and set ip destination address
  sprintf(label, "Destination IP Address (0x%08x = %u.%u.%u.%u)", htonl(ip->daddr), ip->daddr & 0xff, (ip->daddr >> 8) & 0xff, (ip->daddr >> 16) & 0xff, (ip->daddr >> 24) & 0xff);
  gtk_button_set_label(ipv4_destinationipaddressbutton, label);

  // free memory of label
  free(label);

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

void loadpcapfile(GtkWidget *widget, GtkListStore *packetliststore) {
  GtkTreeIter iter;             	// iterator for filling tree view
  char errbuf[PCAP_ERRBUF_SIZE];	// pcap error buffer
  unsigned int i;			// loop variable
  struct pcap_pkthdr *header;		// pointer to pcap header
  const u_char *packet;			// pcap packet pointer
  pcap_t *handler;			// pcap file handler

  // clear all items
  gtk_list_store_clear(packetliststore);

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

  unsigned long begintime = -1;
  char *pcaptime = malloc(20);

  // read packets from file and fill tree view
  i = 1;
  while (pcap_next_ex(handler, &header, &packet) >= 0) {
    if (begintime == -1) begintime = (header->ts).tv_sec;

    sprintf(pcaptime, "%lu.%lu", (header->ts).tv_sec-begintime, (header->ts).tv_usec);

    // insert new row into tree view
    gtk_list_store_insert_with_values(packetliststore, &iter, -1, 0,  i++, 1, pcaptime, -1);
  }

  free(pcaptime);

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

  // init open file menu
  openimagemenuitem = GTK_IMAGE_MENU_ITEM(gtk_builder_get_object (builder, "openimagemenuitem"));
  g_signal_connect(openimagemenuitem, "activate", G_CALLBACK(openpcapfile), packetliststore);

  // init quit menu
  quitimagemenuitem = GTK_IMAGE_MENU_ITEM(gtk_builder_get_object (builder, "quitimagemenuitem"));
  g_signal_connect(quitimagemenuitem, "activate", G_CALLBACK(gtk_main_quit), NULL);

  // init packet tree view (database representation)
  packettreeview = GTK_TREE_VIEW(gtk_builder_get_object (builder, "packettreeview"));
  g_signal_connect (packettreeview, "cursor-changed", G_CALLBACK(display_packet), NULL);

  // init ethernet header buttons
  eth_destmacbutton = GTK_BUTTON(gtk_builder_get_object (builder, "eth_destmacbutton"));
  eth_sourcemacbutton = GTK_BUTTON(gtk_builder_get_object (builder, "eth_sourcemacbutton"));
  eth_typebutton = GTK_BUTTON(gtk_builder_get_object (builder, "eth_typebutton"));

  // init IP header buttons
  ipv4_versionbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_versionbutton"));
  ipv4_ihlbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_ihlbutton"));
  ipv4_dscpbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_dscpbutton"));
  ipv4_ecnbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_ecnbutton"));
  ipv4_totallengthbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_totallengthbutton"));
  ipv4_identificationbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_identificationbutton"));
  ipv4_flagsbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_flagsbutton"));
  ipv4_fragmentoffsetbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_fragmentoffsetbutton"));
  ipv4_timetolivebutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_timetolivebutton"));
  ipv4_protocolbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_protocolbutton"));
  ipv4_headerchecksumbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_headerchecksumbutton"));
  ipv4_sourceipaddressbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_sourceipaddressbutton"));
  ipv4_destinationipaddressbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ipv4_destinationipaddressbutton"));

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

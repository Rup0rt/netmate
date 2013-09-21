#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <gtk/gtk.h>

// THE VERSION OF NETMATE
#define VERSION "0.03"

// size of ethernet header (in pcap format - NOT ethernet frame!)
#define SIZE_ETHERNET 14

// global buttons for renaming
GtkButton *versionbutton;
GtkButton *ihlbutton;
GtkButton *dscpbutton;
GtkButton *ecnbutton;
GtkButton *totallengthbutton;
GtkButton *identificationbutton;
GtkButton *flagsbutton;
GtkButton *fragmentoffsetbutton;
GtkButton *timetolivebutton;
GtkButton *protocolbutton;
GtkButton *headerchecksumbutton;
GtkButton *sourceipaddressbutton;
GtkButton *destinationipaddressbutton;

// struct of ip header
struct ip_header {
  u_char ip_vhl;
  u_char ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
  u_char ip_ttl;
  u_char ip_p;
  u_short ip_sum;
  struct in_addr ip_src;
  struct in_addr ip_dst;
};

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
  char *fname = *(char**)data;		// read file name from caller signal
  const u_char *packet;			// current packet pointer
  unsigned int packetnumber;		// currently secected packet number
  char *label;				// label of buttons to set
  int i = 1;				// loop counter to track packet
  char errbuf[PCAP_ERRBUF_SIZE];	// pcap error buffer
  const struct ip_header *ip;		// ip_header pointer

  // ip_header helper vars
  char ip_version;			// ip version
  char ip_headerlength;			// ip header length
  char ip_dscp;				// ip dscp field
  char ip_ecn;				// ip ecn field
  char ip_flags;			// ip header flags
  short ip_offset;			// ip fragment offset

  // get currently selected packet
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(widget));
  if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
    gtk_tree_model_get(model, &iter, 0, &packetnumber, -1);
  }

  // open pcap to find packet
  handler = pcap_open_offline(fname, errbuf);

  // iterate through packets until selected packet is found
  // this might also be done by preloading of this technique is too slow
  while (i++ <= packetnumber) pcap_next_ex(handler, &header, &packet);

  // allocate memory for button label
  label = malloc(100);

  // pointer to ip header
  ip = (struct ip_header*)(packet + SIZE_ETHERNET);

  // read and set ip version field
  ip_version = ip->ip_vhl >> 4;
  sprintf(label, "Version (%u)", ip_version);
  gtk_button_set_label(versionbutton, label);

  // read and set ip header length
  ip_headerlength = ip->ip_vhl << 2;
  sprintf(label, "IHL (%u)", ip_headerlength);
  gtk_button_set_label(ihlbutton, label);

  // read and set ip dscp field
  ip_dscp = ip->ip_tos >> 2;
  sprintf(label, "DSCP (0x%02x)", ip_dscp);
  gtk_button_set_label(dscpbutton, label);

  // read and set ip ecn field
  ip_ecn = ip->ip_tos & 0x03;
  sprintf(label, "ECN (0x%02x)", ip_ecn);
  gtk_button_set_label(ecnbutton, label);

  // read and set total length of ip header
  sprintf(label, "Total Length (%u)", htons(ip->ip_len));
  gtk_button_set_label(totallengthbutton, label);

  // read and set identification field of ip packet
  sprintf(label, "Identification (0x%04x)", htons(ip->ip_id));
  gtk_button_set_label(identificationbutton, label);

  // read and set ip header flags
  ip_flags = htons(ip->ip_off) >> 13;
  sprintf(label, "Flags (0x%02x)", ip_flags);
  gtk_button_set_label(flagsbutton, label);

  // read and set ip fragmentation offset
  ip_offset = (htons(ip->ip_off) & 0x1fff) << 3;
  sprintf(label, "Fragment Offset (%u)", ip_offset);
  gtk_button_set_label(fragmentoffsetbutton, label);

  // read and set time to live of ip packet
  sprintf(label, "Time To Live (%u)", ip->ip_ttl);
  gtk_button_set_label(timetolivebutton, label);

  // read an d set upper layer protocol
  sprintf(label, "Protocol (%u)", ip->ip_p);
  gtk_button_set_label(protocolbutton, label);

  // read and set ip source address
  sprintf(label, "Source IP Address (0x%08x = %s)", (ip->ip_src).s_addr, inet_ntoa(ip->ip_src));
  gtk_button_set_label(sourceipaddressbutton, label);

  // read and set ip destination address
  sprintf(label, "Destination IP Address (0x%08x = %s)", (ip->ip_dst).s_addr, inet_ntoa(ip->ip_dst));
  gtk_button_set_label(destinationipaddressbutton, label);

  // read and set ip header checksum
  sprintf(label, "Header checksum (0x%04x)", htons(ip->ip_sum));
  gtk_button_set_label(headerchecksumbutton, label);

  // free memory of label
  free(label);

  // close pcap handler
  pcap_close(handler);
}

/// MAIN FUNCTION ///
int main (int argc, char *argv[]) {
  GtkBuilder *builder;			// the GUI builder object
  GtkWindow *mainwindow;		// main window object
  GtkListStore *packetliststore;	// list store for packets
  GtkTreeView *packettreeview;		// tree view for packets
  pcap_t *handler;			// pcap file handler
  GtkTreeIter iter;             	// iterator for filling tree view
  GtkImageMenuItem *quitimagemenuitem;	// quit menu
  char *title;				// title of the program (main window)
  char *fname;				// file name to read pcap files from
  char errbuf[PCAP_ERRBUF_SIZE];	// pcap error buffer
  struct pcap_pkthdr *header;		// pointer to pcap header
  const u_char *packet;			// pcap packet pointer
  unsigned int i;			// loop variable

  // init GTK with console parameters (change to getopts later)
  gtk_init(&argc, &argv);

  // load UI descriptions from file
  builder = gtk_builder_new ();
  gtk_builder_add_from_file (builder, "netmate.ui", NULL);
  // for fileless compiling (gtk_builder_add_from_string)

  // init main window
  mainwindow = GTK_WINDOW(gtk_builder_get_object (builder, "mainwindow"));
  g_signal_connect (mainwindow, "destroy", G_CALLBACK(gtk_main_quit), NULL);

  // init main window
  quitimagemenuitem = GTK_IMAGE_MENU_ITEM(gtk_builder_get_object (builder, "quitimagemenuitem"));
  g_signal_connect (quitimagemenuitem, "activate", G_CALLBACK(gtk_main_quit), NULL);

  // init packet list store (database)
  packetliststore = GTK_LIST_STORE(gtk_builder_get_object (builder, "packetliststore"));

  // init packet tree view (database representation)
  packettreeview = GTK_TREE_VIEW(gtk_builder_get_object (builder, "packettreeview"));
  g_signal_connect (packettreeview, "cursor-changed", G_CALLBACK(display_packet), &fname);

  // init IP header buttons
  versionbutton = GTK_BUTTON(gtk_builder_get_object (builder, "versionbutton"));
  ihlbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ihlbutton"));
  dscpbutton = GTK_BUTTON(gtk_builder_get_object (builder, "dscpbutton"));
  ecnbutton = GTK_BUTTON(gtk_builder_get_object (builder, "ecnbutton"));
  totallengthbutton = GTK_BUTTON(gtk_builder_get_object (builder, "totallengthbutton"));
  identificationbutton = GTK_BUTTON(gtk_builder_get_object (builder, "identificationbutton"));
  flagsbutton = GTK_BUTTON(gtk_builder_get_object (builder, "flagsbutton"));
  fragmentoffsetbutton = GTK_BUTTON(gtk_builder_get_object (builder, "fragmentoffsetbutton"));
  timetolivebutton = GTK_BUTTON(gtk_builder_get_object (builder, "timetolivebutton"));
  protocolbutton = GTK_BUTTON(gtk_builder_get_object (builder, "protocolbutton"));
  headerchecksumbutton = GTK_BUTTON(gtk_builder_get_object (builder, "headerchecksumbutton"));
  sourceipaddressbutton = GTK_BUTTON(gtk_builder_get_object (builder, "sourceipaddressbutton"));
  destinationipaddressbutton = GTK_BUTTON(gtk_builder_get_object (builder, "destinationipaddressbutton"));

  // set title of main window
  title = malloc(100);
  sprintf(title, "NetMate v%s", VERSION);
  gtk_window_set_title(mainwindow, title);
  free(title);

  // read file from argv
  fname = argv[1];

  // check for given parameter
  if (argv[1] == NULL) {
    show_error(GTK_WIDGET(mainwindow), "No filename given.");
    return(0);
  }

  //open file and create pcap handler
  handler = pcap_open_offline(fname, errbuf);

  // read packets from file and fill tree view
  i = 1;
  while (pcap_next_ex(handler, &header, &packet) >= 0) {
    // insert new row into tree view
    gtk_list_store_insert_with_values(packetliststore, &iter, -1, 0,  i++, -1);
  }

  // close pcap handler
  pcap_close(handler);

  // ENTER MAIN LOOP
  gtk_main();

  // exit
  return 0;
}

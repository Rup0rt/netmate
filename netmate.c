#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <gtk/gtk.h>

// THE VERSION OF NETMATE
#define VERSION "0.01"

#define SIZE_ETHERNET 14

pcap_t *handler;
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

struct sniff_ip {
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
   //The header that pcap gives us
  struct pcap_pkthdr *header;

  //The actual packet
  const u_char *packet;

  const struct sniff_ip *ip;
  char ip_version;
  char ip_headerlength;
  char ip_dscp;
  char ip_ecn;
  char ip_flags;
  short ip_offset;

  char *label;

  if (pcap_next_ex(handler, &header, &packet) >= 0) {
    label = malloc(100);

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    ip_version = ip->ip_vhl >> 4;
    sprintf(label, "Version (%u)", ip_version);
    gtk_button_set_label(versionbutton, label);

    ip_headerlength = ip->ip_vhl << 2;
    sprintf(label, "IHL (%u)", ip_headerlength);
    gtk_button_set_label(ihlbutton, label);

    ip_dscp = ip->ip_tos >> 2;
    sprintf(label, "DSCP (0x%02x)", ip_dscp);
    gtk_button_set_label(dscpbutton, label);

    ip_ecn = ip->ip_tos & 0x03;
    sprintf(label, "ECN (0x%02x)", ip_ecn);
    gtk_button_set_label(ecnbutton, label);

    sprintf(label, "Total Length (%u)", htons(ip->ip_len));
    gtk_button_set_label(totallengthbutton, label);

    sprintf(label, "Identification (0x%04x)", htons(ip->ip_id));
    gtk_button_set_label(identificationbutton, label);

    ip_flags = htons(ip->ip_off) >> 13;
    sprintf(label, "Flags (0x%02x)", ip_flags);
    gtk_button_set_label(flagsbutton, label);

    ip_offset = (htons(ip->ip_off) & 0x1fff) << 3;
    sprintf(label, "Fragment Offset (%u)", ip_offset);
    gtk_button_set_label(fragmentoffsetbutton, label);

    sprintf(label, "Time To Live (%u)", ip->ip_ttl);
    gtk_button_set_label(timetolivebutton, label);

    sprintf(label, "Protocol (%u)", ip->ip_p);
    gtk_button_set_label(protocolbutton, label);

    sprintf(label, "Source IP Address (0x%08x = %s)", (ip->ip_src).s_addr, inet_ntoa(ip->ip_src));
    gtk_button_set_label(sourceipaddressbutton, label);

    sprintf(label, "Destination IP Address (0x%08x = %s)", (ip->ip_dst).s_addr, inet_ntoa(ip->ip_dst));
    gtk_button_set_label(destinationipaddressbutton, label);

    sprintf(label, "Header checksum (0x%04x)", htons(ip->ip_sum));
    gtk_button_set_label(headerchecksumbutton, label);

    free(label);

  } else {
    show_information(widget, "No more packet in file...");
  }
}

/// MAIN FUNCTION ///
int main (int argc, char *argv[]) {
  GtkBuilder *builder;			// the GUI builder object
  GtkWindow *mainwindow;		// main window object
  GtkButton *readpacketbutton;

  char *title;

  // init GTK with console parameters (change to getopts later)
  gtk_init(&argc, &argv);

  // load UI descriptions from file
  builder = gtk_builder_new ();
  gtk_builder_add_from_file (builder, "netmate.ui", NULL);
  // for fileless compiling (gtk_builder_add_from_string)

  // read objects needed to be passed as signal parameters
  mainwindow = GTK_WINDOW(gtk_builder_get_object (builder, "mainwindow"));
  readpacketbutton = GTK_BUTTON(gtk_builder_get_object (builder, "readpacketbutton"));

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

  // MAIN WINDOW
  // set title of main window
  title = malloc(100);
  sprintf(title, "NetMate v%s", VERSION);
  gtk_window_set_title(mainwindow, title);
  free(title);

  // connect close signal
  g_signal_connect (mainwindow, "destroy", G_CALLBACK(gtk_main_quit), NULL);
  g_signal_connect (readpacketbutton, "clicked", G_CALLBACK(display_packet), NULL);

  if (argv[1] == NULL) {
    show_error(GTK_WIDGET(mainwindow), "No filename given.");
    return(0);
  }

  //error buffer
  char errbuff[PCAP_ERRBUF_SIZE];

  //open file and create pcap handler
  handler = pcap_open_offline(argv[1], errbuff);

  // ENTER MAIN LOOP
  gtk_main();

  return 0;
}

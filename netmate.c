/*******************************************************************************
 *
 * Copyright (c) 2013 Robert Krause (ruport@f00l.de)
 *
 * This file is part of Netmate.
 *
 * Netmate is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * Netmate is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Netmate. If not, see http://www.gnu.org/licenses/.
 *
 ******************************************************************************/

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
  #include <net/if_arp.h>
  #include <netinet/ip.h>
  #include <netinet/ip6.h>
  #include <netinet/ip_icmp.h>
  #include <netinet/icmp6.h>
  #include <netinet/tcp.h>
  #include <netinet/udp.h>
#else
  #include "win32.h"
#endif

/* THE VERSION OF NETMATE */
#define VERSION "0.2.1"

/* ADDITIONAL LINK TYPES */
#define LINKTYPE_LINUX_SLL 113

/******************************************************************************/

void loadpcapfile(GtkWidget *widget, GtkListStore *packetliststore);
void append_field(GtkGrid *grid, int *x, int *y, int size, char *label, char *tooltip);
void display_packet(GtkWidget *widget);
void openpcapfile(GtkWidget *widget, gpointer data);
void getinfo(pcap_t *handler, const u_char *packet, char **protocol, char **flags, char **source, char **sport, char **destination, char **dport);

#include "tooltips.h"
#include "layer2.h"
#include "layer3.h"
#include "layer4.h"

/******************************************************************************/

char *filename = NULL;

/* global grids (protocol container) */
GtkNotebook *protocolheadernotebook;

/******************************************************************************/
/* GTK INFORMATION WINDOWS */
/******************************************************************************/

/* shows an error popup with given (char*) as message */
void show_error(GtkWidget *widget, gpointer message) {
  GtkWidget *toplevel;	/* the toplevel window */
  GtkWidget *dialog;	/* the dialog object */

  /* get toplevel from widget */
  toplevel = gtk_widget_get_toplevel(widget);

  /* show window only if toplevel */
  if (gtk_widget_is_toplevel(toplevel)) {

    /* create new dialog */
    dialog = gtk_message_dialog_new(GTK_WINDOW(toplevel), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", (char*)message);

    /* set title */
    gtk_window_set_title(GTK_WINDOW(dialog), "Error");

    /* run dialog */
    gtk_dialog_run(GTK_DIALOG(dialog));

    /* destroy dialog */
    gtk_widget_destroy(dialog);
  }
}

/* shows a warning popup with given (char*) as message */
void show_warning(GtkWidget *widget, gpointer message) {
  GtkWidget *toplevel;	/* the toplevel window */
  GtkWidget *dialog;	/* the dialog object */

  /* get toplevel from widget */
  toplevel = gtk_widget_get_toplevel(widget);

  /* show window only if toplevel */
  if (gtk_widget_is_toplevel(toplevel)) {

    /* create new dialog */
    dialog = gtk_message_dialog_new(GTK_WINDOW(toplevel), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, "%s", (char*)message);

    /* set title */
    gtk_window_set_title(GTK_WINDOW(dialog), "Warning");

    /* run dialog */
    gtk_dialog_run(GTK_DIALOG(dialog));

    /* destroy dialog */
    gtk_widget_destroy(dialog);
  }
}

/* shows an information popup with given (char*) as message */
void show_information(GtkWidget *widget, gpointer message) {
  GtkWidget *toplevel;	/* the toplevel window */
  GtkWidget *dialog;	/* the dialog object */

  /* get toplevel from widget */
  toplevel = gtk_widget_get_toplevel(widget);

  /* show window only if toplevel */
  if (gtk_widget_is_toplevel(toplevel)) {

    /* create new dialog */
    dialog = gtk_message_dialog_new(GTK_WINDOW(toplevel), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", (char*)message);

    /* set title */
    gtk_window_set_title(GTK_WINDOW(dialog), "Information");

    /* run dialog */
    gtk_dialog_run(GTK_DIALOG(dialog));

    /* destroy dialog */
    gtk_widget_destroy(dialog);
  }
}

/* shows a questiong popup with given (char*) as message */
gint show_question(GtkWidget *widget, gpointer message) {
  GtkWidget *toplevel;	/* the toplevel window */
  GtkWidget *dialog;	/* the dialog object */
  int ret = -1;		/* return value (clicked button) GTK_RESPONSE_NO or GTK_RESPONSE_YES */

  /* get toplevel from widget */
  toplevel = gtk_widget_get_toplevel(widget);

  /* show window only if toplevel */
  if (gtk_widget_is_toplevel(toplevel)) {
    /* create new dialog */
    dialog = gtk_message_dialog_new(GTK_WINDOW(toplevel), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s", (char*)message);

    /* set title */
    gtk_window_set_title(GTK_WINDOW(dialog), "Question");

    /* run dialog and get click as int */
    ret = gtk_dialog_run(GTK_DIALOG(dialog));

    /* destroy dialog */
    gtk_widget_destroy(dialog);
  }

  /* return clicked button */
  return(ret);
}

/******************************************************************************/

void append_field(GtkGrid *grid, int *x, int *y, int size, char *label, char *tooltip) {
  GtkButton *button;
  while (*x + size > 32) {
    button = GTK_BUTTON(gtk_button_new_with_label(label));
    if (tooltip != NULL) gtk_widget_set_tooltip_text(GTK_WIDGET(button), tooltip);
    gtk_grid_attach(grid, GTK_WIDGET(button), *x, *y, 32-*x, 1);
    size -= 32-*x;
    *x = 0;
    *y = *y + 1;
  }

  button = GTK_BUTTON(gtk_button_new_with_label(label));
  if (tooltip != NULL) gtk_widget_set_tooltip_text(GTK_WIDGET(button), tooltip);
  gtk_grid_attach(grid, GTK_WIDGET(button), *x, *y, size, 1);
  *x = *x + size;
  if (*x == 32) { *x = 0; *y = *y + 1; }
}

GtkGrid *not_supported_grid(char *protocol) {
  GtkGrid *grid;	/* the grid itself */
  char *label;		/* label of buttons to set */

  /* init a new empty grid */
  grid = GTK_GRID(gtk_grid_new());

  /* set columns to be uniform sized (for better bit size representation) */
  gtk_grid_set_column_homogeneous(grid, TRUE);

  /* allocate memory for button label */
  label = malloc(255);

  /* Upper Layer Protocol */
  sprintf(label, "\n%s is not supported yet.\n\nPlease send an email to Ruport@web.de if you want it to be supported in future releases.", protocol);
  gtk_grid_attach(grid, gtk_label_new(label), 0, 0, 32, 5);

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* return grid to tab builder */
  return(grid);
}

void display_packet(GtkWidget *widget) {
  GtkTreeSelection *selection;		/* tree selection */
  GtkTreeModel     *model;		/* tree model */
  GtkTreeIter       iter;		/* tree iterator */
  pcap_t *handler;			/* pcap file handler */
  char errbuf[PCAP_ERRBUF_SIZE];	/* pcap error buffer */
  struct pcap_pkthdr *header;		/* the header from libpcap */
  const u_char *packet;			/* current packet pointer */
  unsigned int packetnumber;		/* currently secected packet number */
  struct ether_header *eth = NULL;
  struct sll_header *sll = NULL;	/* sll header (linux cooked) */
  struct arphdr *arp = NULL;
  struct iphdr *ipv4 = NULL;		/* ipv4_header pointer */
  struct ip6_hdr *ipv6 = NULL;
  struct icmphdr *icmp = NULL;
  struct icmp6_hdr *icmpv6 = NULL;
  struct tcphdr *tcp = NULL;
  struct udphdr *udp = NULL;
  unsigned int i = 1;			/* loop counter to track packet */
  unsigned short nextproto = 0;
  char *nextptr = NULL;
  int pos;

  if (filename == NULL) return;

  /* open pcap to find packet */
  handler = pcap_open_offline(filename, errbuf);
  if (handler == NULL) return;

  /* get currently selected packet */
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(widget));
  if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
    gtk_tree_model_get(model, &iter, 0, &packetnumber, -1);
  }

  /* iterate through packets until selected packet is found
     this might also be done by preloading of this technique is too slow */
  while (i++ <= packetnumber) pcap_next_ex(handler, &header, &packet);

  /* remember tab position and hide all tabs */
  pos = gtk_notebook_get_current_page(protocolheadernotebook);

  /* clear grids */
  while (gtk_notebook_get_n_pages(protocolheadernotebook) > 0) {
    gtk_notebook_remove_page(protocolheadernotebook, 0);
  }

  switch (pcap_datalink(handler)) {

    case DLT_EN10MB:
      /* set pointer to ethernet header */
      eth = (struct ether_header*)(packet);

      /* display ethernet tab */
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(ethernet_grid(eth)), gtk_label_new(hardwaretype(pcap_datalink(handler))));

      nextproto = htons(eth->ether_type);
      nextptr = (void*)(packet + sizeof(struct ether_header));

      break;
    case LINKTYPE_LINUX_SLL:
      /* LINUX COOKED */
      sll = (struct sll_header*)(packet);

      /* display sll tab */
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(sll_grid(sll)), gtk_label_new(hardwaretype(pcap_datalink(handler))));

      nextproto = htons(sll->sll_protocol);
      nextptr = (void*)(packet + sizeof(struct sll_header));

      break;
    default:
      /* display not supported tab */
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(not_supported_grid(hardwaretype(pcap_datalink(handler)))), gtk_label_new(hardwaretype(pcap_datalink(handler))));

      return;
  }

  switch (nextproto) {
    case ETHERTYPE_ARP:
      /* ARP */
      arp = (struct arphdr*)nextptr;
      nextptr += sizeof(struct arphdr);

      /* display arp tab */
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(arp_grid(arp, ((u_char*)nextptr))), gtk_label_new(ethertype(nextproto)));
      nextproto = 0xffff;

      break;
    case ETHERTYPE_IP:
      /* IPV4 */
      ipv4 = (struct iphdr*)nextptr;
      nextptr += sizeof(struct iphdr);

      /* display ipv4 tab */
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(ipv4_grid(ipv4, ((u_char*)nextptr))), gtk_label_new(ethertype(nextproto)));

      nextproto = ipv4->protocol;

      break;
    case ETHERTYPE_IPV6:
      /* IPV6 */
      ipv6 = (struct ip6_hdr*)nextptr;
      nextptr += sizeof(struct ip6_hdr);

      /* display ipv4 tab */
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(ipv6_grid(ipv6, ((u_char*)nextptr))), gtk_label_new(ethertype(nextproto)));

      nextproto = ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

      while (nextproto == IPPROTO_HOPOPTS) {
        /* next header */
        nextproto = ((u_char*)nextptr)[0];

        nextptr += (((u_char*)nextptr)[1]+1) * 8;
      }

      break;
    default:
      /* display not supported tab */
      gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(not_supported_grid(ethertype(nextproto))), gtk_label_new(ethertype(nextproto)));

      nextproto = 0xffff;

      break;
  }

  if (nextproto != 0xffff) {
    switch (nextproto) {
      case IPPROTO_ICMP:
        icmp = (struct icmphdr*)nextptr;
        nextptr += sizeof(struct icmphdr);

        gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(icmp_grid(icmp, ((u_char*)nextptr), htons(ipv4->tot_len)-(ipv4->ihl*4))), gtk_label_new(ipprotocol(nextproto)));

        break;
      case IPPROTO_ICMPV6:
        icmpv6 = (struct icmp6_hdr*)nextptr;

        /* skip 4 bytes of unused / reserved fields of header struct and pass to next protocol pointer */
        nextptr += sizeof(struct icmp6_hdr)-4;

        gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(icmpv6_grid(icmpv6, ((u_char*)nextptr), htons(ipv6->ip6_ctlun.ip6_un1.ip6_un1_plen))), gtk_label_new(ipprotocol(nextproto)));

        break;
      case IPPROTO_TCP:
        tcp = (struct tcphdr*)nextptr;
        nextptr += sizeof(struct tcphdr);

        gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(tcp_grid(tcp, ((u_char*)nextptr))), gtk_label_new(ipprotocol(nextproto)));

        break;
      case IPPROTO_UDP:
        udp = (struct udphdr*)nextptr;

        gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(udp_grid(udp)), gtk_label_new(ipprotocol(nextproto)));

        break;
      default:

        /* display not supported tab */
        gtk_notebook_append_page(protocolheadernotebook, GTK_WIDGET(not_supported_grid(ipprotocol(nextproto))), gtk_label_new(ipprotocol(nextproto)));

        nextproto = 0xffff;

        break;
    }
  }

  /* switch to tab that was former selected */
  if ((pos >= 0) && (pos < gtk_notebook_get_n_pages(protocolheadernotebook))) {
    gtk_notebook_set_current_page(protocolheadernotebook, pos);
  }

  /* close pcap handler */
  pcap_close(handler);
}

void openpcapfile(GtkWidget *widget, gpointer data) {
  GtkDialog *fileopendialog;

  fileopendialog = GTK_DIALOG(gtk_file_chooser_dialog_new ("Open File",
     				      GTK_WINDOW(gtk_widget_get_toplevel(widget)),
     				      GTK_FILE_CHOOSER_ACTION_OPEN,
     				      "_Cancel", GTK_RESPONSE_CANCEL,
     				      "_Open", GTK_RESPONSE_ACCEPT,
     				      NULL));
  gtk_window_resize(GTK_WINDOW(fileopendialog), 1000, 500);


  if (gtk_dialog_run (GTK_DIALOG (fileopendialog)) == GTK_RESPONSE_ACCEPT) {
    filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (fileopendialog));
    loadpcapfile(widget, GTK_LIST_STORE(data));
  }

  gtk_widget_destroy(GTK_WIDGET(fileopendialog));
}

void getinfo(pcap_t *handler, const u_char *packet, char **protocol, char **flags, char **source, char **sport, char **destination, char **dport) {
  struct ether_header *eth;
  struct iphdr *ipv4;                   /* ipv4_header pointer */
  struct tcphdr *tcp;
  struct udphdr *udp;
  struct ip6_hdr *ipv6;
  struct sll_header *sll;               /* sll header (linux cooked) */
  unsigned short nextproto;
  char *nextptr = NULL;

  *protocol = malloc(100);
  *source = malloc(100);
  *sport = malloc(100);
  *destination = malloc(100);
  *dport = malloc(100);
  *flags = malloc(100);
  memset(*protocol, 0, 100);
  memset(*source, 0, 100);
  memset(*sport, 0, 100);
  memset(*destination, 0, 100);
  memset(*dport, 0, 100);
  memset(*flags, 0, 100);

  sprintf(*protocol, "%s", hardwaretype(pcap_datalink(handler)));

  switch (pcap_datalink(handler)) {

    case DLT_EN10MB:
      /* set pointer to ethernet header */
      eth = (struct ether_header*)(packet);

      sprintf(*source, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
      sprintf(*destination, "%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

      nextproto = htons(eth->ether_type);
      nextptr = (void*)(packet + sizeof(struct ether_header));

      break;
    case LINKTYPE_LINUX_SLL:
      /* LINUX COOKED */
      sll = (struct sll_header*)(packet);

      /* TODO: need to check sll->halen to get REAL size (6 chosen here) */
      sprintf(*source, "%02x:%02x:%02x:%02x:%02x:%02x", sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2], sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
      /* destination is unknown in SLL */

      nextproto = htons(sll->sll_protocol);
      nextptr = (void*)(packet + sizeof(struct sll_header));

      break;
    default:
      nextproto = 0xffff;
      break;
  }

  if (nextproto != 0xffff) {

    sprintf(*protocol, "%s", ethertype(nextproto));

    switch (nextproto) {

      case ETHERTYPE_ARP:
        /* ARP */
  /*      arp = (struct arphdr*)nextptr;*/
        nextproto = 0xffff;

        break;

      case ETHERTYPE_IP:
        /* IPV4 */
        ipv4 = (struct iphdr*)nextptr;
        nextptr += sizeof(struct iphdr);
        nextproto = ipv4->protocol;

        sprintf(*source, "%u.%u.%u.%u", ipv4->saddr & 0xff, (ipv4->saddr >> 8) & 0xff, (ipv4->saddr >> 16) & 0xff, (ipv4->saddr >> 24) & 0xff);
        sprintf(*destination, "%u.%u.%u.%u", ipv4->daddr & 0xff, (ipv4->daddr >> 8) & 0xff, (ipv4->daddr >> 16) & 0xff, (ipv4->daddr >> 24) & 0xff);

        /* reserved flag */
        if (ipv4->frag_off & htons(IP_RF)) strcat(*flags, "RF ");

        /* dont fragment flag */
        if (ipv4->frag_off & htons(IP_DF)) strcat(*flags, "DF ");

        /* more fragments flag */
        if (ipv4->frag_off & htons(IP_MF)) strcat(*flags, "MF ");

        break;
      case ETHERTYPE_IPV6:
        ipv6 = (struct ip6_hdr*)nextptr;
        nextptr += sizeof(struct ip6_hdr);

        sprintf(*source, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", htons(ipv6->ip6_src.__in6_u.__u6_addr16[0]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[1]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[2]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[3]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[4]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[5]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[6]), htons(ipv6->ip6_src.__in6_u.__u6_addr16[7]));
        sprintf(*destination, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", htons(ipv6->ip6_dst.__in6_u.__u6_addr16[0]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[1]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[2]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[3]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[4]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[5]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[6]), htons(ipv6->ip6_dst.__in6_u.__u6_addr16[7]));

        nextproto = ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        while (nextproto == IPPROTO_HOPOPTS) {
          /* next header */
          nextproto = ((u_char*)nextptr)[0];

          nextptr += (((u_char*)nextptr)[1]+1) * 8;
        }
        break;
      default:
        nextproto = 0xffff;
        break;
    }
  }

  if (nextproto != 0xffff) {

    sprintf(*protocol, "%s", ipprotocol(nextproto));

    switch (nextproto) {
      case IPPROTO_ICMP:
/*      icmp = (struct icmphdr*)nextptr;*/

        break;
      case IPPROTO_ICMPV6:
/*        icmpv6 = (struct icmp6_hdr*)nextptr;*/

        break;
      case IPPROTO_TCP:
        tcp = (struct tcphdr*)nextptr;

        sprintf(*sport, "%u", htons(tcp->source));
        sprintf(*dport, "%u", htons(tcp->dest));

        /* NS */
        if (tcp->res1 & 0x01) strcat(*flags, "NS ");

        /* CWR */
        if (tcp->res2 & 0x02) strcat(*flags, "CWR ");

        /* ECE */
        if (tcp->res2 & 0x01) strcat(*flags, "ECE ");

        /* URG */
        if (tcp->urg) strcat(*flags, "URG ");

        /* ACK */
        if (tcp->ack) strcat(*flags, "ACK ");

        /* PSH */
        if (tcp->psh) strcat(*flags, "PSH ");

        /* RST */
        if (tcp->rst) strcat(*flags, "RST ");

        /* SYN */
        if (tcp->syn) strcat(*flags, "SYN ");

        /* FIN */
        if (tcp->fin) strcat(*flags, "FIN ");

        break;
      case IPPROTO_UDP:
        udp = (struct udphdr*)nextptr;

        sprintf(*sport, "%u", htons(udp->source));
        sprintf(*dport, "%u", htons(udp->dest));

        break;
      default:
        nextproto = 0xffff;
        break;
    }
  }
}

void loadpcapfile(GtkWidget *widget, GtkListStore *packetliststore) {
  GtkTreeIter iter;             	/* iterator for filling tree view */
  char errbuf[PCAP_ERRBUF_SIZE];	/* pcap error buffer */
  unsigned int i;			/* loop variable */
  struct pcap_pkthdr *header;		/* pointer to pcap header */
  const u_char *packet;			/* pcap packet pointer */
  pcap_t *handler;			/* pcap file handler */
  long begintime = -1;
  long beginutime;
  long realtime;
  long realutime;
  char *pcaptime = malloc(20);
  char *protocol;
  char *source;
  char *sport;
  char *destination;
  char *dport;
  char *flags;

  /* clear all items */
  gtk_list_store_clear(packetliststore);

  /* clear grids */
  while (gtk_notebook_get_n_pages(protocolheadernotebook) > 0) {
    gtk_notebook_remove_page(protocolheadernotebook, 0);
  }

  /* check for empty file pointer */
  if (filename == NULL) return;

  /* check if file exists */
  if (access(filename, F_OK ) == -1 ) {
    show_error(widget, "File not found.");
    filename = NULL;
    return;
  }

  /* open file and create pcap handler */
  handler = pcap_open_offline(filename, errbuf);

  /* check for proper pcap file */
  if (handler == NULL ) {
    show_error(widget, "Invalid pcap format, try pcapfix :)");
    filename = NULL;
    return;
  }

  /* read packets from file and fill tree view */
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
    getinfo(handler, packet, &protocol, &flags, &source, &sport, &destination, &dport);

    /* insert new row into tree view */
    gtk_list_store_insert_with_values(packetliststore, &iter, -1, 0,  i++, 1, pcaptime, 2, protocol, 3, flags, 4, source, 5, sport, 6, destination, 7, dport, -1);
  }

  free(pcaptime);
  free(source);
  free(destination);

  /* close pcap handler */
  pcap_close(handler);
}

/* MAIN FUNCTION */
int main (int argc, char *argv[]) {
  GtkWindow *mainwindow;		/* main window object */
  GtkBox *mainbox;
  GtkMenuBar *topmenubar;
  GtkScrolledWindow *packetscrolledwindow;
  GtkMenuItem *filemenuitem, *helpmenuitem, *aboutmenuitem;
  GtkMenu *filemenu, *helpmenu;
  GtkTreeViewColumn *packetnumbertreeviewcolumn, *timetreeviewcolumn, *protocoltreeviewcolumn, *sourcetreeviewcolumn, *destinationtreeviewcolumn, *sporttreeviewcolumn, *dporttreeviewcolumn, *flagstreeviewcolumn;
  GtkCellRendererText *packetnumbercellrenderertext, *timecellrenderertext, *protocolcellrenderertext, *sourcecellrenderertext, *destinationcellrenderertext, *sportcellrenderertext, *dportcellrenderertext, *flagscellrenderertext;
  GtkListStore *packetliststore;	/* list store for packets */
  GtkTreeView *packettreeview;		/* tree view for packets */
  GtkImageMenuItem *openimagemenuitem;	/* file open menu */
  GtkImageMenuItem *quitimagemenuitem;	/* quit menu */
  char *title;				/* title of the program (main window) */

  /* init GTK with console parameters (change to getopts later) */
  gtk_init(NULL, NULL);

  /* init packet list store (database) */
  packetliststore = GTK_LIST_STORE(gtk_list_store_new (8, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING));

  /* init main window */
  mainwindow = GTK_WINDOW(gtk_window_new(GTK_WINDOW_TOPLEVEL));
  gtk_window_set_position(mainwindow, GTK_WIN_POS_CENTER_ALWAYS);
  g_signal_connect(mainwindow, "destroy", G_CALLBACK(gtk_main_quit), NULL);

  mainbox = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 0));
  gtk_container_add(GTK_CONTAINER(mainwindow), GTK_WIDGET(mainbox));

  topmenubar = GTK_MENU_BAR(gtk_menu_bar_new());
  filemenuitem = (GtkMenuItem*)gtk_menu_item_new_with_label("File");

  filemenu = GTK_MENU(gtk_menu_new());

  /* init open file menu */
  openimagemenuitem = (GtkImageMenuItem*)gtk_menu_item_new_with_label("Open");
  g_signal_connect(openimagemenuitem, "activate", G_CALLBACK(openpcapfile), packetliststore);

  gtk_container_add(GTK_CONTAINER(filemenu), GTK_WIDGET(openimagemenuitem));

  gtk_container_add(GTK_CONTAINER(filemenu), gtk_separator_menu_item_new());

  /* init quit menu */
  quitimagemenuitem = (GtkImageMenuItem*)gtk_menu_item_new_with_label("Quit");
  g_signal_connect(quitimagemenuitem, "activate", G_CALLBACK(gtk_main_quit), NULL);

  gtk_container_add(GTK_CONTAINER(filemenu), GTK_WIDGET(quitimagemenuitem));

  gtk_menu_item_set_submenu(filemenuitem, GTK_WIDGET(filemenu));

  gtk_container_add(GTK_CONTAINER(topmenubar), GTK_WIDGET(filemenuitem));

  helpmenuitem = GTK_MENU_ITEM(gtk_menu_item_new_with_label("Help"));
  helpmenu = GTK_MENU(gtk_menu_new());

  gtk_menu_item_set_submenu(helpmenuitem, GTK_WIDGET(helpmenu));

  aboutmenuitem = GTK_MENU_ITEM(gtk_menu_item_new_with_label("About"));

  g_signal_connect(aboutmenuitem, "activate", G_CALLBACK(show_information), "Copyright (c) 2013-2016 Robert Krause (ruport@f00l.de)\n\nNetmate is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.\n\nNetmate is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.\n\nPlease report any bugs and feature requests to ruport@f00l.de\n\nFor more information visit http://f00l.de/netmate/");

  gtk_container_add(GTK_CONTAINER(helpmenu), GTK_WIDGET(aboutmenuitem));

  gtk_container_add(GTK_CONTAINER(topmenubar), GTK_WIDGET(helpmenuitem));

  gtk_box_pack_start(mainbox, GTK_WIDGET(topmenubar), FALSE, TRUE, 0);

	packetscrolledwindow = GTK_SCROLLED_WINDOW(gtk_scrolled_window_new(NULL, NULL));
  gtk_widget_set_size_request(GTK_WIDGET(packetscrolledwindow), 800, 400);

  packettreeview = GTK_TREE_VIEW(gtk_tree_view_new_with_model(GTK_TREE_MODEL(packetliststore)));
  g_signal_connect (packettreeview, "cursor-changed", G_CALLBACK(display_packet), NULL);

  packetnumbercellrenderertext = GTK_CELL_RENDERER_TEXT(gtk_cell_renderer_text_new());
  packetnumbertreeviewcolumn = gtk_tree_view_column_new_with_attributes("No.", GTK_CELL_RENDERER(packetnumbercellrenderertext), "text", 0, NULL);
  gtk_tree_view_column_set_resizable(packetnumbertreeviewcolumn, TRUE);
  gtk_tree_view_append_column(packettreeview, packetnumbertreeviewcolumn);

  timecellrenderertext = GTK_CELL_RENDERER_TEXT(gtk_cell_renderer_text_new());
  timetreeviewcolumn = gtk_tree_view_column_new_with_attributes("Time", GTK_CELL_RENDERER(timecellrenderertext), "text", 1, NULL);
  gtk_tree_view_column_set_resizable(timetreeviewcolumn, TRUE);
  gtk_tree_view_append_column(packettreeview, timetreeviewcolumn);

  protocolcellrenderertext = GTK_CELL_RENDERER_TEXT(gtk_cell_renderer_text_new());
  protocoltreeviewcolumn = gtk_tree_view_column_new_with_attributes("Protocol", GTK_CELL_RENDERER(protocolcellrenderertext), "text", 2, NULL);
  gtk_tree_view_column_set_resizable(protocoltreeviewcolumn, TRUE);
  gtk_tree_view_append_column(packettreeview, protocoltreeviewcolumn);

  flagscellrenderertext = GTK_CELL_RENDERER_TEXT(gtk_cell_renderer_text_new());
  flagstreeviewcolumn = gtk_tree_view_column_new_with_attributes("Flags", GTK_CELL_RENDERER(flagscellrenderertext), "text", 3, NULL);
  gtk_tree_view_column_set_resizable(flagstreeviewcolumn, TRUE);
  gtk_tree_view_append_column(packettreeview, flagstreeviewcolumn);

  sourcecellrenderertext = GTK_CELL_RENDERER_TEXT(gtk_cell_renderer_text_new());
  sourcetreeviewcolumn = gtk_tree_view_column_new_with_attributes("Source", GTK_CELL_RENDERER(sourcecellrenderertext), "text", 4, NULL);
  gtk_tree_view_column_set_resizable(sourcetreeviewcolumn, TRUE);
  gtk_tree_view_append_column(packettreeview, sourcetreeviewcolumn);

  sportcellrenderertext = GTK_CELL_RENDERER_TEXT(gtk_cell_renderer_text_new());
  sporttreeviewcolumn = gtk_tree_view_column_new_with_attributes("S.port", GTK_CELL_RENDERER(sportcellrenderertext), "text", 5, NULL);
  gtk_tree_view_column_set_resizable(sporttreeviewcolumn, TRUE);
  gtk_tree_view_append_column(packettreeview, sporttreeviewcolumn);

  destinationcellrenderertext = GTK_CELL_RENDERER_TEXT(gtk_cell_renderer_text_new());
  destinationtreeviewcolumn = gtk_tree_view_column_new_with_attributes("Destination", GTK_CELL_RENDERER(destinationcellrenderertext), "text", 6, NULL);
  gtk_tree_view_column_set_resizable(destinationtreeviewcolumn, TRUE);
  gtk_tree_view_append_column(packettreeview, destinationtreeviewcolumn);

  dportcellrenderertext = GTK_CELL_RENDERER_TEXT(gtk_cell_renderer_text_new());
  dporttreeviewcolumn = gtk_tree_view_column_new_with_attributes("D.port", GTK_CELL_RENDERER(dportcellrenderertext), "text", 7, NULL);
  gtk_tree_view_column_set_resizable(dporttreeviewcolumn, TRUE);
  gtk_tree_view_append_column(packettreeview, dporttreeviewcolumn);

  gtk_container_add(GTK_CONTAINER(packetscrolledwindow), GTK_WIDGET(packettreeview));
  gtk_box_pack_start(mainbox, GTK_WIDGET(packetscrolledwindow), FALSE, TRUE, 0);

  /* init protocol header field */
  protocolheadernotebook = GTK_NOTEBOOK(gtk_notebook_new());
  gtk_box_pack_start(mainbox, GTK_WIDGET(protocolheadernotebook), FALSE, TRUE, 0);

  gtk_widget_set_visible(GTK_WIDGET(mainwindow), TRUE);
  gtk_widget_show_all(GTK_WIDGET(mainwindow));

  /* set title of main window */
  title = malloc(100);
  sprintf(title, "NetMate v%s", VERSION);
  gtk_window_set_title(mainwindow, title);
  free(title);

  while (gtk_events_pending ()) gtk_main_iteration ();

  /* try loading filename from parameters */
  if (argc >= 1) {
    filename = argv[1];
    loadpcapfile(GTK_WIDGET(mainwindow), packetliststore);
  }

  /* ENTER MAIN LOOP */
  gtk_main();

  /* exit */
  return(0);
}

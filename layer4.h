/*******************************************************************************
 *
 * Copyright (c) 2013-2016 Robert Krause (ruport@f00l.de)
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

/******************************************************************************/
/* netmate layer4 protocols */
/******************************************************************************/

char *tcp_optkind(unsigned char id);
GtkGrid *tcp_grid(struct tcphdr *tcp, u_char *options);
GtkGrid *udp_grid(struct udphdr *udp);

/******************************************************************************/

char *tcp_optkind(unsigned char id) {
  switch (id) {
    case 0:
      return("End of Options");
    case 1:
      return("No Operation");
    case 2:
      return("Maximum segment size");
    case 3:
      return("Window scale");
    case 4:
      return("SACK permitted");
    case 5:
      return("Selective ACKnowledgement");
    case 8:
      return("Timestamp");
    case 14:
      return("TCP Alternate Checksum Request");
    case 15:
      return("TCP Alternate Checksum Data");
  }
  return("UNKNOWN");
}

GtkGrid *tcp_grid(struct tcphdr *tcp, u_char *options) {
  GtkGrid *grid;	/* the grid itself */
  char *label;		/* label of buttons to set */
  char *optdata;	/* option data */
  int x,y;			/* position pointer to next empty grid cell */
  int left;			/* bytes left for ipv4 options */
  int optlen;		/* length of options field */
  int optkind;		/* option kind */
  int i;			/* loop counter for raw data representation */

  /* init new empty grid */
  grid = GTK_GRID(gtk_grid_new());

  /* set columns to be uniform sized (for better bit size representation) */
  gtk_grid_set_column_homogeneous(grid, TRUE);

  /* allocate memory for button label */
  label = malloc(100);

  /* build bit indication topic line (0 1 2 .. 31) */
  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  /* set cell pointer to next empty grid cell */
  x=0;
  y=1;

  /* source port */
  sprintf(label, "Source Port: %u", htons(tcp->source));
  append_field(grid, &x, &y, sizeof(tcp->source)*8, label, TCP_SPORT);

  /* destination port */
  sprintf(label, "Destination Port: %u", htons(tcp->dest));
  append_field(grid, &x, &y, sizeof(tcp->dest)*8, label, TCP_DPORT);

  /* sequence number */
  sprintf(label, "Sequence Number: %u", htonl(tcp->seq));
  append_field(grid, &x, &y, sizeof(tcp->seq)*8, label, TCP_SEQ_NUM);

  /* acknowledgement number */
  sprintf(label, "Acknowledgement Number: %u", htonl(tcp->ack_seq));
  append_field(grid, &x, &y, sizeof(tcp->ack_seq)*8, label, TCP_ACK_NUM);

  /* data offset */
  sprintf(label, "Data Offset: %u (%u bytes)", tcp->doff, tcp->doff*4);
  append_field(grid, &x, &y, 4, label, TCP_DOFF);

  /* reserved (000) */
  if (tcp->res1 & 0x08) {
    append_field(grid, &x, &y, 1, "R", TCP_FLAG_RES);
  } else {
    append_field(grid, &x, &y, 1, "r", TCP_FLAG_RES);
  }
  if (tcp->res1 & 0x04) {
    append_field(grid, &x, &y, 1, "R", TCP_FLAG_RES);
  } else {
    append_field(grid, &x, &y, 1, "r", TCP_FLAG_RES);
  }
  if (tcp->res1 & 0x02) {
    append_field(grid, &x, &y, 1, "R", TCP_FLAG_RES);
  } else {
    append_field(grid, &x, &y, 1, "r", TCP_FLAG_RES);
  }

  /* NS */
  if (tcp->res1 & 0x01) {
    append_field(grid, &x, &y, 1, "NS", TCP_FLAG_NS);
  } else {
    append_field(grid, &x, &y, 1, "ns", TCP_FLAG_NS);
  }

  /* CWR */
  if (tcp->res2 & 0x02) {
    append_field(grid, &x, &y, 1, "CWR", TCP_FLAG_CWR);
  } else {
    append_field(grid, &x, &y, 1, "cwr", TCP_FLAG_CWR);
  }

  /* ECE */
  if (tcp->res2 & 0x01) {
    append_field(grid, &x, &y, 1, "ECE", TCP_FLAG_ECE);
  } else {
    append_field(grid, &x, &y, 1, "ece", TCP_FLAG_ECE);
  }

  /* URG */
  if (tcp->urg) {
    append_field(grid, &x, &y, 1, "URG", TCP_FLAG_URG);
  } else {
    append_field(grid, &x, &y, 1, "urg", TCP_FLAG_URG);
  }

  /* ACK */
  if (tcp->ack) {
    append_field(grid, &x, &y, 1, "ACK", TCP_FLAG_ACK);
  } else {
    append_field(grid, &x, &y, 1, "ack", TCP_FLAG_ACK);
  }

  /* PSH */
  if (tcp->psh) {
    append_field(grid, &x, &y, 1, "PSH", TCP_FLAG_PSH);
  } else {
    append_field(grid, &x, &y, 1, "psh", TCP_FLAG_PSH);
  }

  /* RST */
  if (tcp->rst) {
    append_field(grid, &x, &y, 1, "RST", TCP_FLAG_RST);
  } else {
    append_field(grid, &x, &y, 1, "rst", TCP_FLAG_RST);
  }

  /* SYN */
  if (tcp->syn) {
    append_field(grid, &x, &y, 1, "SYN", TCP_FLAG_SYN);
  } else {
    append_field(grid, &x, &y, 1, "syn", TCP_FLAG_SYN);
  }

  /* FIN */
  if (tcp->fin) {
    append_field(grid, &x, &y, 1, "FIN", TCP_FLAG_FIN);
  } else {
    append_field(grid, &x, &y, 1, "fin", TCP_FLAG_FIN);
  }

  /* window size */
  sprintf(label, "Window Size: %u", htons(tcp->window));
  append_field(grid, &x, &y, sizeof(tcp->window)*8, label, TCP_WINDOW_SIZE);

  /* checksum */
  sprintf(label, "Checksum: 0x%04x", htons(tcp->check));
  append_field(grid, &x, &y, sizeof(tcp->check)*8, label, TCP_CHECKSUM);

  /* urgent pointer */
  sprintf(label, "Urgent Pointer: %u", htons(tcp->urg_ptr));
  append_field(grid, &x, &y, sizeof(tcp->urg_ptr)*8, label, TCP_URGENT_POINTER);

  /* count bytes of option fields */
  left = (tcp->doff-0x05)*4;

  /* progress bytes until no option bytes left */
  while (left > 0) {
    /* get option type (first byte) */
    optkind = options[0];

    /* option kind */
    sprintf(label, "Option Kind: %u (%s)", optkind, tcp_optkind(optkind));
    append_field(grid, &x, &y, 8, label, TCP_OPTION_KIND);

    /* option dependent output (some options dont have a length field) */
    if ((optkind == 0x00) || (optkind == 0x01)) { /* EOO or NOP */
      /* option length is only 1 byte */
      optlen = 1;
    } else {
      /* options with variable length */

      /* option length (INCLUDING kind and length field) */
      optlen = options[1];
      sprintf(label, "Option Length: %u", optlen);
      append_field(grid, &x, &y, 8, label, TCP_OPTION_LENGTH);

      /* option has additional option data? */
      if (optlen > 2) {

        /* allocate memory for option data (*2 because of hex representation) */
        optdata = malloc(optlen*2);

        /* print bytes in hex format into array */
        for (i=0; i<optlen-2; ++i) sprintf(&optdata[i*2], "%02x", (unsigned int)options[i+2]);
        optdata[(optlen-2)*2] = 0x00;

        /* option data field */
        sprintf(label, "Option Data: 0x%s", optdata);
        append_field(grid, &x, &y, (optlen-2)*8, label, TCP_OPTION_DATA);

        /* free data */
        free(optdata);
      }
    }

    /* reduce length of field */
    left -= optlen;

    /* increase pointer to options header */
    options = options + optlen;
  }

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* pass grid back to tab builder function */
  return(grid);
}

GtkGrid *udp_grid(struct udphdr *udp) {
  GtkGrid *grid;	/* the grid itself */
  char *label;		/* label of buttons to set */
  int x,y;			/* position pointer to next empty grid cell */

  /* init new empty grid */
  grid = GTK_GRID(gtk_grid_new());

  /* set columns to be uniform sized (for better bit size representation) */
  gtk_grid_set_column_homogeneous(grid, TRUE);

  /* allocate memory for button label */
  label = malloc(100);

  /* build bit indication topic line (0 1 2 .. 31) */
  for (x=0; x<32; x++) {
    sprintf(label, "%u", x);
    gtk_grid_attach(grid, gtk_label_new(label), x, 0, 1, 1);
  }

  /* set cell pointer to next empty grid cell */
  x=0;
  y=1;

  /* source port */
  sprintf(label, "Source Port: %u", htons(udp->source));
  append_field(grid, &x, &y, sizeof(udp->source)*8, label, UDP_SPORT);

  /* destination port */
  sprintf(label, "Destination Port: %u", htons(udp->dest));
  append_field(grid, &x, &y, sizeof(udp->dest)*8, label, UDP_DPORT);

  /* length */
  sprintf(label, "Length: %u", htons(udp->len));
  append_field(grid, &x, &y, sizeof(udp->len)*8, label, UDP_LENGTH);

  /* checksum */
  sprintf(label, "Checksum: 0x%02x", htons(udp->check));
  append_field(grid, &x, &y, sizeof(udp->check)*8, label, UDP_CHECKSUM);

  /* free memory of label */
  free(label);

  /* show ethernet grid (tab) */
  gtk_widget_show_all(GTK_WIDGET(grid));

  /* pass grid back to tab builder function */
  return(grid);
}



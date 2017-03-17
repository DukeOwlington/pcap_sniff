#define _GNU_SOURCE

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type; /* IP? ARP? RARP? etc */
};

void GotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void PrintMac(char *prt_str, u_char *host) {
  printf(prt_str,
    (unsigned)host[0],
    (unsigned)host[1],
    (unsigned)host[2],
    (unsigned)host[3],
    (unsigned)host[4],
    (unsigned)host[5]);

}

void PrintPayload(const u_char *payload, int len);

void PrintHALine(const u_char *payload, int len, int offset);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void PrintHALine(const u_char *payload, int len, int offset) {

  int i;
  int gap;
  const u_char *ch;

  /* offset */
  printf("%05d   ", offset);

  /* hex */
  ch = payload;
  for (i = 0; i < len; i++) {
    printf("%02x ", *ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7)
      printf(" ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8)
    printf(" ");

  /* fill hex gap with spaces if not full line */
  if (len < 16) {
    gap = 16 - len;
    for (i = 0; i < gap; i++) {
      printf("   ");
    }
  }
  printf("   ");

  /* ascii (if printable) */
  ch = payload;
  for (i = 0; i < len; i++) {
    if (isprint(*ch))
      printf("%c", *ch);
    else
      printf(".");
    ch++;
  }

  printf("\n");

  return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void PrintPayload(const u_char *payload, int len) {

  int len_rem = len;
  int line_width = 16; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  const u_char *ch = payload;

  if (len <= 0)
    return;

  /* data fits on one line */
  if (len <= line_width) {
    PrintHALine(ch, len, offset);
    return;
  }

  /* data spans multiple lines */
  for (;;) {
    /* compute current line length */
    line_len = line_width % len_rem;
    /* print line */
    PrintHALine(ch, line_len, offset);
    /* compute total remaining */
    len_rem = len_rem - line_len;
    /* shift pointer to remaining bytes to print */
    ch = ch + line_len;
    /* add offset */
    offset = offset + line_width;
    /* check if we have line width chars or less */
    if (len_rem <= line_width) {
      /* print last line and get out */
      PrintHALine(ch, len_rem, offset);
      break;
    }
  }

  return;
}

/*
 * dissect/print packet
 */
void GotPacket(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

  static int count = 1; /* packet counter */

  /* declare pointers to packet headers */
  struct ethernet *ether; /* The ethernet header [1] */
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct in_addr src, dest;
  const u_char *payload; /* Packet payload */

  int size_ip;
  int size_tcp;
  int size_payload;

  printf("\nPacket number %d:\n", count);
  count++;

  /* define ethernet header */
  ether = (struct ethernet*) (packet);

  /* define/compute ip header offset */
  ip = (struct iphdr*) (packet + SIZE_ETHERNET);
  size_ip = ip->ihl * 4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }

  src.s_addr = ip->saddr;
  dest.s_addr = ip->daddr;
  /* print source and destination IP addresses */
  printf("   From: %s\n", inet_ntoa(src));
  printf("   To: %s\n", inet_ntoa(dest));

  PrintMac("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ether->ether_dhost);
  PrintMac("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ether->ether_shost);

  /* determine protocol */
  switch (ip->protocol) {
    case IPPROTO_TCP:
      printf("   Protocol: TCP\n");
      break;
    case IPPROTO_UDP:
      printf("   Protocol: UDP\n");
      return;
    case IPPROTO_ICMP:
      printf("   Protocol: ICMP\n");
      return;
    case IPPROTO_IP:
      printf("   Protocol: IP\n");
      return;
    default:
      printf("   Protocol: unknown\n");
      return;
  }

  /*
   * this packet is TCP.
   * define/compute tcp header offset */
  tcp = (struct tcphdr*) (packet + SIZE_ETHERNET + size_ip);
  size_tcp = tcp->doff * 4;
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }

  printf("   Src port: %d\n", ntohs(tcp->source));
  printf("   Dst port: %d\n", ntohs(tcp->dest));

  /* define/compute tcp payload (segment) offset */
  payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

  /* compute tcp payload (segment) size */
  size_payload = ntohs(ip->tot_len) - (size_ip + size_tcp);

  /*
   * Print payload data; it might be binary, so don't just
   * treat it as a string.
   */
  if (size_payload > 0) {
    printf("   Payload (%d bytes):\n", size_payload);
    PrintPayload(payload, size_payload);
  }

  return;
}

int main(int argc, char **argv) {

  char *dev = NULL; /* capture device name */
  char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */

  pcap_t *handle; /* packet capture handle */

  char filter_exp[] = "ip"; /* filter expression [3] */
  struct bpf_program fp; /* compiled filter program (expression) */
  bpf_u_int32 mask; /* subnet mask */
  bpf_u_int32 net; /* ip */
  int num_packets = 0; /* number of packets to capture */


    /* find a capture device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      exit(EXIT_FAILURE);
    }

  /* get network number and mask associated with capture device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

  /* print capture info */
  printf("Device: %s\n", dev);
  printf("Number of packets: %d\n", num_packets);
  printf("Filter expression: %s\n", filter_exp);

  /* open capture device */
  handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  /* make sure we're capturing on an Ethernet device [2] */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }

  /* compile the filter expression */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* now we can set our callback function */
  pcap_loop(handle, num_packets, GotPacket, NULL);

  /* cleanup */
  pcap_freecode(&fp);
  pcap_close(handle);

  printf("\nCapture complete.\n");

  return 0;
}

#include "pcap_sniff.h"

/*
 * dissect/print packet
 */
void GotPacket(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

  static int count = 1; /* packet counter */
  unsigned short recv_check, calc_check; /* checksum variables */

  /* declare pointers to packet headers */
  struct ethernet *ether; /* The ethernet header [1] */
  struct iphdr *ip;
  struct in_addr src, dest;
  const u_char *payload; /* Packet payload */

  unsigned int size_ip;
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


  /* calculate ip header checksum */
  recv_check = ip->check;
  ip->check = 0;
  calc_check = CalcIPChecksum((unsigned short*)ip, ip->ihl<<2);

  /* print channel and network layer information */
  PrintMac("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ether->ether_dhost);
  PrintMac("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ether->ether_shost);
  printf("   Received IP header checksum: %d\n", recv_check);
  printf("   Calculated IP header checksum: %d\n", calc_check);


  /* determine protocol */
  switch (ip->protocol) {
    case IPPROTO_TCP:
      printf("   Protocol: TCP\n");
      HandleTCPHeader(ip, size_ip, packet);
      break;
    case IPPROTO_UDP:
      printf("   Protocol: UDP\n");
      HandleUDPHeader(ip, size_ip, packet);
      break;
    case IPPROTO_ICMP:
      printf("   Protocol: ICMP\n");
      HandleICMPHeader(ip, size_ip, packet);
      break;
    case IPPROTO_IP:
      printf("   Protocol: IP\n");
      break;
    default:
      printf("   Protocol: unknown\n");
      break;
  }

  payload = (u_char *) (packet);
  size_payload = ntohs(ip->tot_len);
  /*
   * Print payload data; it might be binary, so don't just
   * treat it as a string.
   */
  if (size_payload > 0) {
    printf("   Payload (%d bytes):\n", size_payload);
    PrintPayload(payload, size_payload);
  }
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

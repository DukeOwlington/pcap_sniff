#include "pcap_sniff.h"

void HandleTCPHeader(struct iphdr *ip, unsigned int size_ip, const u_char *packet) {
  unsigned int size_tcp;
  unsigned short recv_check, calc_check; /* checksum variables */
  struct tcphdr *tcp;
  /*
   * define/compute tcp header offset
   */
  tcp = (struct tcphdr*) (packet + SIZE_ETHERNET + size_ip);
  size_tcp = tcp->doff * 4;
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }

  recv_check = tcp->check;
  calc_check = CalcTCPChecksum(ip, (unsigned short *) tcp);

  printf("   Src port: %d\n", ntohs(tcp->source));
  printf("   Dst port: %d\n", ntohs(tcp->dest));
  printf("   Received checksum: %d\n", recv_check);
  printf("   Calculated checksum: %d\n", calc_check);
}

void HandleUDPHeader(struct iphdr *ip, unsigned int size_ip, const u_char *packet) {
  unsigned int size_udp;
  unsigned short recv_check, calc_check; /* checksum variables */
  struct udphdr *udp;

  /*
   * define/compute udp header offset
   */
  udp = (struct udphdr*) (packet + SIZE_ETHERNET + size_ip);
  size_udp = udp->len * 4;
  if (size_udp < 20) {
    printf("   * Invalid UDP header length: %u bytes\n", size_udp);
    return;
  }
  recv_check = udp->check;
  calc_check = CalcUDPChecksum(ip, (unsigned short *) udp);

  printf("   Src port: %d\n", ntohs(udp->source));
  printf("   Dst port: %d\n", ntohs(udp->dest));
  printf("   Received checksum: %d\n", recv_check);
  printf("   Calculated checksum: %d\n", calc_check);
}

void HandleICMPHeader(struct iphdr *ip, unsigned int size_ip, const u_char *packet) {
  unsigned short recv_check, calc_check; /* checksum variables */
  struct icmphdr *icmp;

  /*
   * define ICMP header offset
   */
  icmp = (struct icmphdr*) (packet + SIZE_ETHERNET + size_ip);

  recv_check = icmp->checksum;
  calc_check = CalcICMPChecksum((unsigned short *)icmp, sizeof(struct icmphdr) + ntohs(ip->tot_len));

  printf("   Received checksum: %d\n", recv_check);
  printf("   Calculated checksum: %d\n", calc_check);
}

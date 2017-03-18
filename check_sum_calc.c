#include "pcap_sniff.h"

/*
 * calculate ip checksum (first 20 bytes)
 */
unsigned short CalcIPChecksum(unsigned short *addr, unsigned int count) {
  unsigned long sum = 0;

  while (count > 1) {
    sum += *addr++;
    count -= 2;
  }

  /* if any bytes left, pad the bytes and add */

  if(count > 0) {
    sum += ((*addr) & htons(0xFF00));
  }

  /* fold sum to 16 bits: add carrier to result */
  while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }

  /* one's complement */
  sum = ~sum;
  return ((unsigned short)sum);
}

/* set tcp checksum: given IP header and tcp segment */

unsigned short CalcTCPChecksum(struct iphdr *ip, unsigned short *ip_payload) {
    unsigned long sum = 0;
    unsigned short tcpLen = ntohs(ip->tot_len) - (ip->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ip_payload);
    /* the source ip */
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += (ip->saddr) & 0xFFFF;
    /* the dest ip */
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += (ip->daddr) & 0xFFFF;
    /* protocol and reserved: 6 */
    sum += htons(IPPROTO_TCP);
    /* the length */
    sum += htons(tcpLen);
    /* add the IP payload */
    /* initialize checksum to 0 */
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ip_payload++;
        tcpLen -= 2;
    }
    /* if any bytes left, pad the bytes and add */
    if(tcpLen > 0) {
        sum += ((*ip_payload) & htons(0xFF00));

    }
    /* fold 32-bit sum to 16 bits: add carrier to result */
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    /* set computation result */
    tcphdrp->check = (unsigned short)sum;
    return (unsigned short)sum;
}

/* set udp checksum: given IP header and UDP datagram */

unsigned short CalcUDPChecksum(struct iphdr *ip, unsigned short *ip_payload) {
    unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(ip_payload);
    unsigned short udpLen = htons(udphdrp->len);

    /* the source ip */
    sum += (ip->saddr>>16)&0xFFFF;
    sum += (ip->saddr)&0xFFFF;
    /* the dest ip */
    sum += (ip->daddr>>16)&0xFFFF;
    sum += (ip->daddr)&0xFFFF;
    /* protocol and reserved: 17 */
    sum += htons(IPPROTO_UDP);
    /* the length */
    sum += udphdrp->len;

    /* initialize checksum to 0 */
    udphdrp->check = 0;
    while (udpLen > 1) {
        sum += * ip_payload++;
        udpLen -= 2;
    }

    /* if any bytes left, pad the bytes and add */
    if(udpLen > 0) {
        sum += ((*ip_payload)&htons(0xFF00));
    }

    /* fold sum to 16 bits: add carrier to result */
    while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    /* set computation result */
    return ((unsigned short)sum == 0x0000) ? 0xFFFF : (unsigned short)sum;
}

/*
    Function calculate checksum
*/
unsigned short CalcICMPChecksum(unsigned short *ptr, int nbytes) {
    unsigned long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}

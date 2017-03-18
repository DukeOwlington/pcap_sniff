#include "pcap_sniff.h"

/*
 * print MAC address
 */
void PrintMac(char *prt_str, u_char *host) {
  printf(prt_str,
    (unsigned)host[0],
    (unsigned)host[1],
    (unsigned)host[2],
    (unsigned)host[3],
    (unsigned)host[4],
    (unsigned)host[5]);

}

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

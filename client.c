/*
 * WARNING: This code is fucking bloated and has been written to be so;
 * please do not intend to run this code more than 5 minutes for testing.
 *
 * wildcat - 2011
 */
/* gcc -o client client.c -lpcap */
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <fcntl.h>
#include <net/if.h>
#include <limits.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#define NPEER 2
#define RHOST1 "88.198.146.22"
#define RHOST2 "88.198.146.22"

#define RPORT1 31337
#define RPORT2 31338

#define LPORT1 31339
#define LPORT2 31340

#define LTAP "tap0"

typedef unsigned int uint16;
int rsock[NPEER];
int lsock[NPEER];
struct sockaddr_in raddr[NPEER];

int s_idx(void) {
  static int i = 0;
  if (i++ % NPEER) { 
    return 0; 
  } else { 
    return 1; 
  }
}

void clean_exit(void) {
  fprintf(stderr, "[!] Forced shutdown\n");
  shutdown(rsock[0], SHUT_RDWR);
  shutdown(rsock[1], SHUT_RDWR);
  close(rsock[0]);
  close(rsock[1]);
  exit(1); 
}

void p_recv(u_char * useless, const struct pcap_pkthdr *pkthdr, const u_char * packet)
{
    if (!packet)
	return;

    fflush(stdout);
    unsigned int len = pkthdr->len;
    int idx = s_idx();
    fprintf(stdout, "[<-] len=%d -> %d\n", pkthdr->len, idx);
    
    int n =
	sendto(rsock[idx], &len, sizeof(len), 0, (struct sockaddr *) &raddr[idx],
	       sizeof(raddr[idx]));
    if (n < 0) {
      clean_exit();
    }
    n = sendto(rsock[idx], packet, len, 0,
	       (struct sockaddr *) &raddr[idx], sizeof(raddr[idx]));
    if (n < 0) {
      clean_exit();
    }
    printf("[-] Wrote %d on socket %d\n", n, idx);
    fflush(stdout);
    return;
}



int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc_desc;

    pc_desc = pcap_open_live(LTAP, BUFSIZ, 0, -1, errbuf);
    if (pc_desc == NULL) {
	printf("pcap_open_live(): %s\n", errbuf);
	exit(1);
    }

    int tap_fd = open("/dev/net/tun", O_RDWR | O_SYNC);
    if (tap_fd < 0) {
	fprintf(stderr, "[!] Cannot open /dev/net/tun\n");
	return 42;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, LTAP, strlen(LTAP));
    if (ioctl(tap_fd, TUNSETIFF, (void *) &ifr) < 0) {
	fprintf(stderr, "[!] Unable to setup tap device %s", LTAP);
	close(tap_fd);
	return 42;
    }


    /* prepare the DGRAM sockets */
    rsock[0] = socket(AF_INET, SOCK_DGRAM, 0);
    rsock[1] = socket(AF_INET, SOCK_DGRAM, 0);
    lsock[0] = socket(AF_INET, SOCK_DGRAM, 0);
    lsock[1] = socket(AF_INET, SOCK_DGRAM, 0);
    if (rsock[0] < 0 || rsock[1] < 0 || lsock[0] < 0 || lsock[1] < 0) {
	fprintf(stderr, "Error, socket() failed: %s\n", strerror(errno));
	return 1;
    }

    memset(&raddr[0], 0, sizeof(raddr[0]));
    raddr[0].sin_family = AF_INET;
    inet_pton(AF_INET, RHOST1, &(raddr[0].sin_addr.s_addr));
    raddr[0].sin_port = htons(RPORT1);

    memset(&raddr[1], 0, sizeof(raddr[1]));
    raddr[1].sin_family = AF_INET;
    inet_pton(AF_INET, RHOST2, &(raddr[1].sin_addr.s_addr));
    raddr[1].sin_port = htons(RPORT2);

    int pid = fork();
    if (pid == 0) {
      pcap_loop(pc_desc, 0, p_recv, NULL);
      fprintf(stdout, "\nDone processing packets... wheew!\n");
      shutdown(rsock[0], SHUT_RDWR);
      shutdown(rsock[1], SHUT_RDWR);
      close(rsock[0]);
      close(rsock[1]);
    }

    /* bind local server port */
    struct sockaddr_in cliAddr, servAddr;
    int rc,len;

    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(LPORT1);
    rc = bind(lsock[0], (struct sockaddr *) &servAddr, sizeof(servAddr));
    servAddr.sin_port = htons(LPORT2);
    rc = bind(lsock[1], (struct sockaddr *) &servAddr, sizeof(servAddr));
    if (rc < 0) {
        printf("[!] Cannot bind port number %d or %d \n", LPORT1, LPORT2);
        exit(1);
    }

    printf("[-] Waiting for data on port UDP %u\n", LPORT1);
    printf("[-] Waiting for data on port UDP %u\n", LPORT2);
    fd_set s_set;
    struct timeval t_out, *to;
    int biggest = 0;
    if (lsock[0] > lsock[1]) {
      biggest = lsock[0];
    } else {
      biggest = lsock[1];
    }
    int i,idx,cliLen,n;
    u_char *packet;
    /* server infinite loop */
    while (1) {

        memset(&len, 0x0, sizeof(len));

        /* receive message length */
        FD_ZERO(&s_set);
        FD_SET(lsock[0], &s_set);
        FD_SET(lsock[1], &s_set);
        t_out.tv_sec  = 0;
        t_out.tv_usec = 500;
        to = &t_out;
        if ( (i = select (biggest + 1, &s_set, NULL, NULL, &t_out)) > 0) {
          if (FD_ISSET(lsock[0], &s_set)) {
             idx = 0;
          } else if (FD_ISSET(lsock[1], &s_set)) {
             idx = 1;
          } else {
            printf("[!] POUAH!\n");
            break;
          }
          cliLen = sizeof(cliAddr);
          n = recvfrom(lsock[idx], &len, sizeof(len), 0, (struct sockaddr *) &cliAddr, &cliLen);
          if (n < 0) {
              printf("[!] Cannot receive data \n");
              continue;
          }
          packet = (u_char *) malloc(len + 1);
//          memset(packet, 0, len);
          n = recvfrom(lsock[idx], packet, len, 0,
                     (struct sockaddr *) &cliAddr, &cliLen);

          if (n < 0) {
              printf("[!] Cannot receive data 2\n");
              continue;
          }

          if ((n = write(tap_fd, packet, len)) < 0) {
          //if (pcap_inject(pc_desc, packet, len) == -1) {

              printf("[!] Cannot inject data\n");
              continue;
          }


          printf("[-] Wrote %d bytes on tap sock\n",n);
          printf("[-] From %s:%u (%d)\n",
               inet_ntoa(cliAddr.sin_addr),
               ntohs(cliAddr.sin_port), len);

          free(packet);
        }
      }

}


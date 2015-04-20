/*
 * WARNING: This code is fucking bloated and has been written to be so;
 * please do not intend to run this code more than 5 minutes for testing.
 *
 * wildcat - 2011
 */
/* gcc -o server server.c -lpcap */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>


#define LTAP "tap42"
#define PORT1 31338
#define PORT2 31337
#define NPEER 2

int rsock[NPEER];

int main(int argc, char *argv[])
{

    int sd, rc, n, cliLen;
    struct sockaddr_in cliAddr, servAddr;
    u_char *packet;
    unsigned int len;

    int fd = open("/dev/net/tun", O_RDWR | O_SYNC);
    if (fd < 0) {
	fprintf(stderr, "[!] Cannot open /dev/net/tun\n");
	return 42;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP;
    strncpy(ifr.ifr_name, LTAP, strlen(LTAP));
    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
	fprintf(stderr, "[!] Unable to setup tap device %s\n", LTAP);
	close(fd);
	return 42;
    }

    rsock[0] = socket(AF_INET, SOCK_DGRAM, 0);
    rsock[1] = socket(AF_INET, SOCK_DGRAM, 0);
    if (rsock[0] < 0||rsock[1] < 0) {
	printf("[!] Cannot open socket \n");
	exit(1);
    }

    /* bind local server port */
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(PORT1);
    rc = bind(rsock[0], (struct sockaddr *) &servAddr, sizeof(servAddr));
    servAddr.sin_port = htons(PORT2);
    rc = bind(rsock[1], (struct sockaddr *) &servAddr, sizeof(servAddr));
    if (rc < 0) {
	printf("[!] Cannot bind port number %d or %d \n", PORT1, PORT2);
	exit(1);
    }

    printf("[-] Waiting for data on port UDP %u\n", PORT1);
    printf("[-] Waiting for data on port UDP %u\n", PORT2);

    fd_set s_set;
    struct timeval t_out, *to;	
    int biggest = 0;
    if (rsock[0] > rsock[1]) {
      biggest = rsock[0];
    } else {
      biggest = rsock[1];
    }

    int i,idx;
    /* server infinite loop */
    while (1) {

	memset(&len, 0x0, sizeof(len));

	/* receive message length */
	FD_ZERO(&s_set);
	FD_SET(rsock[0], &s_set);
	FD_SET(rsock[1], &s_set);
	t_out.tv_sec  = 0;
	t_out.tv_usec = 500;
	to = &t_out;
        if ( (i = select (biggest + 1, &s_set, NULL, NULL, &t_out)) > 0) {
	  if (FD_ISSET(rsock[0], &s_set)) {
	     idx = 0;
	  } else if (FD_ISSET(rsock[1], &s_set)) {
	     idx = 1;
	  } else {
	    printf("[!] POUAH!\n");
	    break;
	  }
          cliLen = sizeof(cliAddr);
          n = recvfrom(sd, &len, sizeof(len), 0, (struct sockaddr *) &cliAddr, &cliLen);
          if (n < 0) {
              printf("[!] Cannot receive data \n");
              continue;
          }
#ifdef REMOTE_LE
  	  len = ntohl(len);
#endif
	  packet = (u_char *) malloc(len + 1);
	  n = recvfrom(sd, packet, len, 0,
		     (struct sockaddr *) &cliAddr, &cliLen);

	  if (n < 0) {
	      printf("[!] Cannot receive data \n");
	      continue;
  	  }

	  write(fd, packet, len);

	  printf("[-] From %s:%u (%d)\n",
	       inet_ntoa(cliAddr.sin_addr),
	       ntohs(cliAddr.sin_port), len);

	  free(packet);
	}
    }
    return 0;
}



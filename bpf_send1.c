#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PUT 0
#define GET 1
#define DEL 2

int main(int argc, char ** argv)
{
  int sd;
  struct sockaddr_in addr;
  struct packet_data {
    int type;
    char buf[2048];
  };

  struct packet_data pkt;
  
  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    return -1;
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(22222);
  addr.sin_addr.s_addr = inet_addr("192.168.182.138");

  while (1) {
    char * buf2;
    printf("type>>");
    scanf("%d", &pkt.type);
    printf(">>");
    scanf("%s", &pkt.buf);

    if (sendto(sd, htons(&pkt), sizeof(struct packet_data), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
      perror("send");
      return -1;
    }
    if (strcmp("exit", pkt.buf) == 0) {
      break;
    }
  }

  close(sd);

  return 0;
}

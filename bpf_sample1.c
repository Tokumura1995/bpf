#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include "libbpf.h"

int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size, unsigned int value_size, unsigned int max_entries);

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}


int main(){
   int sd;
   struct sockaddr_in addr;

   socklen_t sin_size;
   struct sockaddr_in from_addr;
   
   char buf[2048];
   
   int map_fd, prog_fd;
   int key, value;

   if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
     perror("socket");
     return -1;
   }
   addr.sin_family = AF_INET;
   addr.sin_port = htons(22222);
   addr.sin_addr.s_addr = INADDR_ANY;
   
   if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
     perror("bind");
     return -1;
   }
   
   if ((map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 256)) < 0) {
     perror("bpf_create_map");
     return -1;
   }
  
   struct sock_filter code[] = {
     BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, -1),
     BPF_ALU64_IMM(BPF_MOV, BPF_REG_1, -1),
     BPF_ALU64_IMM(BPF_MOV, BPF_REG_2, 3),
     BPF_ALU64_REG(BPF_MUL, BPF_REG_1, BPF_REG_2),
     BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0xfffffffd, 1),
     BPF_EXIT_INSN(),
     BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 1),
     BPF_EXIT_INSN(),
   };
    
   struct sock_fprog bpf = {
     .len = sizeof(code)/sizeof(code[0]),
     .filter = code,
   };

   setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
   
   while(1){
     ssize_t len = recv(sd, buf, sizeof(buf), 0);
     // printf("%s\n", buf);
     struct ethhdr* ethhdr = (struct ethhdr*)buf;
     //int proto = ntohs(ethhdr->h_proto);
     if(len <= 0) break;
     printf("%3ld \n", len);
   }
   return 0;
}

int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size, unsigned int value_size, unsigned int max_entries)
{
  union bpf_attr attr;
  memset(&attr, '\0', sizeof(attr));
 
  attr.map_type    = map_type;
  attr.key_size    = key_size;
  attr.value_size  = value_size;
  attr.max_entries = max_entries;
  

  return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

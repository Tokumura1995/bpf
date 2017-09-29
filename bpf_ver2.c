#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "libbpf.h"

#define LOG_BUF_SIZE 1024
char bpf_log_buf[LOG_BUF_SIZE];

int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size, unsigned int value_size, unsigned int max_entries);
int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns, int prog_len, const char *license);
int bpf_lookup_elem(int fd, const void *key, void *value);
int bpf_update_elem(int fd, const void *key, const void *value, uint64_t flags);
int bpf_get_next_key(int fd, void *key, void *next_key);

int cache_checker(void *key);

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}


int main(int argc, char ** argv)
{
  int sd;
  struct sockaddr_in addr;

  socklen_t sin_size;
  struct sockaddr_in from_addr;

  char buf[2048];
  int buf2;

  int map_fd, prog_fd;
  int key;
  char value[4];

  if ((map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 256)) < 0) {
    perror("bpf_create_map");
    return -1;
  }

  
  struct bpf_insn prog[] = {
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
    BPF_LD_ABS(BPF_W, 76),
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, cache_checker),
    BPF_EXIT_INSN(),
  };
    

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
  
  while (strcmp(buf, "start") != 0) {
    if(recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&from_addr, &sin_size) < 0) {
      perror("recvfrom");
      return -1;
    }
    printf("buf = %s\n", buf);
  }
  
  if ((prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog), "GPL")) < 0) {
    printf("bpf_prog_load() err=%d\n%s", errno, bpf_log_buf);
    return -1;	
  } 

  if (setsockopt(sd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
    perror("setsockeopt");
    return -1;
  }

  printf("success\n");
  
  
  while (1) {
    int key1 = 0;
    char  value1[4];
    
    assert(bpf_lookup_elem(map_fd, &key1, value1) == 0);
    //printf("bpf_lookup_elem() err=%d\n%s", errno, bpf_log_buf);
    //return -1;	
    //}

    sleep(3);
    printf("aiueo\n");
    printf("value = %s\n", value1);
    sleep(1);
  }

  close(sd);
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

int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns, int prog_len, const char *license)
{
  union bpf_attr attr;
  memset(&attr, '\0', sizeof(attr));
  
  attr.prog_type = type;
  attr.insns     = ptr_to_u64((void *)insns);
  attr.insn_cnt  = prog_len / sizeof(struct bpf_insn);
  attr.license   = ptr_to_u64((void *)license);
  attr.log_buf   = ptr_to_u64(bpf_log_buf);
  attr.log_size  = LOG_BUF_SIZE;
  attr.log_level = 1;
  attr.kern_version = 4;

  bpf_log_buf[0] = 0;
  
  return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_lookup_elem(int fd, const void *key, void *value)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key    = ptr_to_u64(key),
    .value  = ptr_to_u64(value),
  };
  
  return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, const void *key, const void *value, uint64_t flags)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key    = ptr_to_u64(key),
    .value  = ptr_to_u64(value),
    .flags  = flags,
  };
  
  return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_get_next_key(int fd, void *key, void *next_key)
{
  union bpf_attr attr = {
    .map_fd = fd,
    .key = ptr_to_u64(key),
    .next_key = ptr_to_u64(next_key),
  };

  return sys_bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}
 
int cache_checker(void *key)
{
  printf("%s\n", (char *)key);
  return 0;
}

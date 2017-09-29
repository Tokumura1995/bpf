#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if.h>
#include <assert.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include "libbpf.h"

#define LOG_BUF_SIZE 1024
char bpf_log_buf[LOG_BUF_SIZE];

int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size, unsigned int value_size, unsigned int max_entries);
int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns, int prog_len, const char *license);
int bpf_lookup_elem(int fd, const void *key, void *value);
int open_raw_sock(const char *name);


static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int test_sock(void)
{
    int sock = -1, map_fd, prog_fd, i, key;
    long long value = 0, tcp_cnt, udp_cnt, icmp_cnt;

    map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),256);
    if (map_fd < 0) {
        printf("failed to create map '%s'\n", strerror(errno));
        goto cleanup;
    }

    struct bpf_insn prog[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_LD_ABS(BPF_B, ETH_HLEN + offsetof(struct iphdr, protocol)),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), 
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), 
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
        BPF_MOV64_IMM(BPF_REG_1, 1), 
        BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0), 
        BPF_MOV64_IMM(BPF_REG_0, 0), 
        BPF_EXIT_INSN(),
    };

    prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, prog, sizeof(prog), "GPL");
    if (prog_fd < 0) {
        printf("failed to load prog '%s'\n", strerror(errno));
        goto cleanup;
    }

    sock = open_raw_sock("lo");

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        printf("setsockopt %s\n", strerror(errno));
        goto cleanup;
    }

    for (i = 0; i < 100; i++) {
        key = IPPROTO_TCP;
        assert(bpf_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

        key = IPPROTO_UDP;
        assert(bpf_lookup_elem(map_fd, &key, &udp_cnt) == 0);

        key = IPPROTO_ICMP;
        assert(bpf_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

        printf("TCP %lld UDP %lld ICMP %lld packets\n",
               tcp_cnt, udp_cnt, icmp_cnt);
        sleep(1);
    }

cleanup:

    return 0;
}

int main(void)
{
    FILE *f;

    f = popen("ping -c5 localhost", "r");
    (void)f;

    return test_sock();
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

int open_raw_sock(const char *name)
{
  struct sockaddr_ll sll;
  int sock;
  
  sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (sock < 0) {
    printf("cannot create raw socket\n");
    return -1;
  }
  
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = if_nametoindex(name);
  sll.sll_protocol = htons(ETH_P_ALL);
  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    printf("bind to %s: %s\n", name, strerror(errno));
    close(sock);
    return -1;
  }
  
  return sock;
}

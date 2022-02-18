//
// Created by niujinlin on 2022/2/17.
//
#include "xdp-proxy.skel.h"
// #include "vmlinux.h"
#include "sys/resource.h"
#include "errno.h"
#include "string.h"
#include "net/if.h"
#include "uapi//linux/if_link.h"

int main(int argc, char **argv) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    int err = setrlimit(RLIMIT_MEMLOCK, &rlim_new);

    struct xdp_proxy_bpf *obj = xdp_proxy_bpf__open();

    err = xdp_proxy_bpf__load(obj);
    if (err) {
        printf("error load bpf object: (%d) %s\n", errno, strerror(errno));
    }

    unsigned int ifindex = if_nametoindex("eth0");
    int prog_id = bpf_program__fd(obj->progs.xdp_proxy);
    err = bpf_set_link_xdp_fd(ifindex, prog_id, XDP_FLAGS_UPDATE_IF_NOEXIST|XDP_FLAGS_SKB_MODE);
    if (err) {
        printf("error attach bpf program on eth0: (%d) %s\n", errno, strerror(errno));
    }
}
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_BPF_OBJ "./tc_router_kern.o"
#define MAX_ROUTES 1024
#define TC_HANDLE 0x1
#define TC_PRIO 1
#define TC_RETRY 16

struct route_entry {
    __u32 ifindex;
    __u8  dst_mac[ETH_ALEN];
    __u8  src_mac[ETH_ALEN];
};

struct route_arg {
    char src_ip[32];
    char nh_ip[32];
    char dev[IF_NAMESIZE];
    __u32 src_ip_be;
    __u32 nh_ip_be;
    int ifindex;
    __u8 src_mac[ETH_ALEN];
};

static void die(const char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

static int get_if_mac(const char *ifname, __u8 mac[ETH_ALEN])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
    return 0;
}

static int get_if_ipv4(const char *ifname, struct in_addr *addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    *addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    close(fd);
    return 0;
}

static int send_arp_request(const char *ifname, int ifindex, __u8 src_mac[ETH_ALEN],
                            struct in_addr src_ip, struct in_addr dst_ip)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0)
        return -1;

    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_ifindex = ifindex,
        .sll_halen = ETH_ALEN,
    };
    memset(sll.sll_addr, 0xff, ETH_ALEN);

    struct {
        struct ethhdr eth;
        struct arphdr arp;
        __u8 sha[ETH_ALEN];
        __u8 spa[4];
        __u8 tha[ETH_ALEN];
        __u8 tpa[4];
    } __attribute__((packed)) pkt;

    memset(&pkt, 0, sizeof(pkt));
    memset(pkt.eth.h_dest, 0xff, ETH_ALEN);
    memcpy(pkt.eth.h_source, src_mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_ARP);

    pkt.arp.ar_hrd = htons(ARPHRD_ETHER);
    pkt.arp.ar_pro = htons(ETH_P_IP);
    pkt.arp.ar_hln = ETH_ALEN;
    pkt.arp.ar_pln = 4;
    pkt.arp.ar_op = htons(ARPOP_REQUEST);

    memcpy(pkt.sha, src_mac, ETH_ALEN);
    memcpy(pkt.spa, &src_ip.s_addr, 4);
    memset(pkt.tha, 0x00, ETH_ALEN);
    memcpy(pkt.tpa, &dst_ip.s_addr, 4);

    int ret = sendto(fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sll, sizeof(sll));
    close(fd);
    return ret < 0 ? -1 : 0;
}

static int lookup_neigh_mac_nl(const char *ip, int ifindex, __u8 mac[ETH_ALEN])
{
    struct in_addr dst;
    if (inet_pton(AF_INET, ip, &dst) != 1)
        return -1;

    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
        return -1;

    char buf[256];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    struct ndmsg *ndm = (struct ndmsg *)(buf + sizeof(*nlh));

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ndm));
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = 0;

    ndm->ndm_family = AF_INET;
    ndm->ndm_ifindex = ifindex;
    ndm->ndm_state = 0;

    struct rtattr *rta = (struct rtattr *)(buf + nlh->nlmsg_len);
    rta->rta_type = NDA_DST;
    rta->rta_len = RTA_LENGTH(sizeof(dst));
    memcpy(RTA_DATA(rta), &dst, sizeof(dst));
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_LENGTH(sizeof(dst));

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    if (sendto(fd, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    char resp[4096];
    int len = recv(fd, resp, sizeof(resp), 0);
    if (len < 0) {
        close(fd);
        return -1;
    }

    for (struct nlmsghdr *h = (struct nlmsghdr *)resp; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
        if (h->nlmsg_type == NLMSG_ERROR) {
            close(fd);
            return -1;
        }
        if (h->nlmsg_type != RTM_NEWNEIGH)
            continue;

        struct ndmsg *m = NLMSG_DATA(h);
        int attrlen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*m));
        for (struct rtattr *a = RTM_RTA(m); RTA_OK(a, attrlen); a = RTA_NEXT(a, attrlen)) {
            if (a->rta_type == NDA_LLADDR) {
                int alen = RTA_PAYLOAD(a);
                if (alen >= ETH_ALEN) {
                    memcpy(mac, RTA_DATA(a), ETH_ALEN);
                    close(fd);
                    return 0;
                }
            }
        }
    }

    close(fd);
    return -1;
}

static int parse_route(const char *arg, struct route_arg *out)
{
    char buf[128];
    memset(out, 0, sizeof(*out));
    strncpy(buf, arg, sizeof(buf) - 1);

    char *s = strtok(buf, "@");
    char *n = strtok(NULL, "@");
    char *d = strtok(NULL, "@");

    if (!s || !n || !d)
        return -1;

    strncpy(out->src_ip, s, sizeof(out->src_ip) - 1);
    strncpy(out->nh_ip, n, sizeof(out->nh_ip) - 1);
    strncpy(out->dev, d, sizeof(out->dev) - 1);
    return 0;
}

static int attach_one(int ifindex, int prog_fd, enum bpf_tc_attach_point ap,
                      __u32 *handle, __u32 *prio)
{
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = ap,
    };

    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .prog_fd = prog_fd,
    };

    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST)
        return err;

    for (int i = 0; i < TC_RETRY; i++) {
        opts.handle = *handle + i;
        opts.priority = *prio + i;
        opts.flags = 0;

        err = bpf_tc_attach(&hook, &opts);
        if (err == -EEXIST || err == -EBUSY) {
            opts.flags = BPF_TC_F_REPLACE;
            err = bpf_tc_attach(&hook, &opts);
        }
        if (!err) {
            *handle = opts.handle;
            *prio = opts.priority;
            return 0;
        }
        if (err != -EEXIST && err != -EBUSY)
            return err;
    }

    return -EBUSY;
}

static int detach_one(int ifindex, enum bpf_tc_attach_point ap, __u32 handle, __u32 prio)
{
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = ap,
    };

    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .handle = handle,
        .priority = prio,
    };

    int err = bpf_tc_detach(&hook, &opts);
    if (err && err != -ENOENT)
        return err;

    err = bpf_tc_hook_destroy(&hook);
    if (err && err != -ENOENT)
        return err;

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --devs veth0,veth1 --route SRC@NH@DEV [--route ...] [--obj PATH] [--attach-point ingress|egress] [--attach-devs DEVLIST] [--handle N] [--prio N]\n"
        "  %s --detach --devs veth0,veth1 [--attach-point ingress|egress] [--attach-devs DEVLIST] [--handle N] [--prio N]\n"
        "  %s --watch [--attach-point ingress|egress] [--attach-devs DEVLIST] --devs veth0,veth1 --route SRC@NH@DEV [--route ...] [--handle N] [--prio N]\n\n"
        "Route format: SRC@NH@DEV\n"
        "Example: 10.10.1.1@10.10.1.254@veth0\n",
        prog, prog, prog);
}

int main(int argc, char **argv)
{
    const char *obj_path = DEFAULT_BPF_OBJ;
    const char *devs = NULL;
    const char *attach_devs = NULL;
    struct route_arg routes[MAX_ROUTES];
    int route_cnt = 0;
    bool do_detach = false;
    bool do_watch = false;
    enum bpf_tc_attach_point attach_point = BPF_TC_EGRESS;
    __u32 handle = TC_HANDLE;
    __u32 prio = TC_PRIO;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--obj") == 0 && i + 1 < argc) {
            obj_path = argv[++i];
        } else if (strcmp(argv[i], "--devs") == 0 && i + 1 < argc) {
            devs = argv[++i];
        } else if (strcmp(argv[i], "--attach-devs") == 0 && i + 1 < argc) {
            attach_devs = argv[++i];
        } else if (strcmp(argv[i], "--handle") == 0 && i + 1 < argc) {
            handle = (__u32)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--prio") == 0 && i + 1 < argc) {
            prio = (__u32)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--route") == 0 && i + 1 < argc) {
            if (route_cnt >= MAX_ROUTES) {
                fprintf(stderr, "too many routes\n");
                return 1;
            }
            if (parse_route(argv[++i], &routes[route_cnt]) != 0) {
                fprintf(stderr, "invalid route: %s\n", argv[i]);
                return 1;
            }
            route_cnt++;
        } else if (strcmp(argv[i], "--detach") == 0) {
            do_detach = true;
        } else if (strcmp(argv[i], "--watch") == 0) {
            do_watch = true;
        } else if (strcmp(argv[i], "--attach-point") == 0 && i + 1 < argc) {
            const char *ap = argv[++i];
            if (strcmp(ap, "ingress") == 0)
                attach_point = BPF_TC_INGRESS;
            else if (strcmp(ap, "egress") == 0)
                attach_point = BPF_TC_EGRESS;
            else {
                fprintf(stderr, "invalid attach point: %s\n", ap);
                return 1;
            }
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!devs) {
        usage(argv[0]);
        return 1;
    }
    if (!attach_devs)
        attach_devs = devs;

    char *devs_buf = strdup(devs);
    if (!devs_buf)
        die("strdup");
    char *attach_buf = strdup(attach_devs);
    if (!attach_buf)
        die("strdup");

    if (do_detach) {
        char *tok = strtok(attach_buf, ",");
        while (tok) {
            int ifindex = if_nametoindex(tok);
            if (!ifindex) {
                fprintf(stderr, "unknown dev: %s\n", tok);
                free(devs_buf);
                free(attach_buf);
                return 1;
            }
            int err = detach_one(ifindex, attach_point, handle, prio);
            if (err) {
                fprintf(stderr, "detach %s failed: %s\n", tok, strerror(-err));
                free(devs_buf);
                free(attach_buf);
                return 1;
            }
            tok = strtok(NULL, ",");
        }
        free(devs_buf);
        free(attach_buf);
        return 0;
    }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj)
        die("bpf_object__open_file");

    if (bpf_object__load(obj))
        die("bpf_object__load");

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tc_router");
    if (!prog) {
        fprintf(stderr, "program tc_router not found\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
        die("bpf_program__fd");

    char *tok = strtok(attach_buf, ",");
    while (tok) {
        int ifindex = if_nametoindex(tok);
        if (!ifindex) {
            fprintf(stderr, "unknown dev: %s\n", tok);
            free(devs_buf);
            free(attach_buf);
            return 1;
        }
        __u32 use_handle = handle;
        __u32 use_prio = prio;
        int err = attach_one(ifindex, prog_fd, attach_point, &use_handle, &use_prio);
        if (err) {
            fprintf(stderr, "attach %s failed: %s\n", tok, strerror(-err));
            free(devs_buf);
            free(attach_buf);
            return 1;
        }
        fprintf(stderr, "attached %s handle %u prio %u\n", tok, use_handle, use_prio);
        tok = strtok(NULL, ",");
    }
    free(devs_buf);
    free(attach_buf);

    int map_fd = bpf_object__find_map_fd_by_name(obj, "route_map");
    if (map_fd < 0)
        die("find route_map");

    for (int i = 0; i < route_cnt; i++) {
        struct in_addr src, nh;
        if (inet_pton(AF_INET, routes[i].src_ip, &src) != 1) {
            fprintf(stderr, "bad src ip: %s\n", routes[i].src_ip);
            return 1;
        }
        if (inet_pton(AF_INET, routes[i].nh_ip, &nh) != 1) {
            fprintf(stderr, "bad next-hop ip: %s\n", routes[i].nh_ip);
            return 1;
        }

        int ifindex = if_nametoindex(routes[i].dev);
        if (!ifindex) {
            fprintf(stderr, "unknown dev: %s\n", routes[i].dev);
            return 1;
        }
        routes[i].ifindex = ifindex;
        routes[i].src_ip_be = src.s_addr;
        routes[i].nh_ip_be = nh.s_addr;

        struct route_entry entry;
        memset(&entry, 0, sizeof(entry));
        entry.ifindex = ifindex;

        if (get_if_mac(routes[i].dev, entry.src_mac) != 0) {
            fprintf(stderr, "failed to get src mac for %s\n", routes[i].dev);
            return 1;
        }
        memcpy(routes[i].src_mac, entry.src_mac, ETH_ALEN);

        if (lookup_neigh_mac_nl(routes[i].nh_ip, ifindex, entry.dst_mac) != 0) {
            /* Try to trigger ARP, then continue if watch mode is enabled */
            (void)send_arp_request(routes[i].dev, ifindex, entry.src_mac, src, nh);
            if (!do_watch) {
                fprintf(stderr,
                    "no neighbor entry for %s on %s. "
                    "Populate neighbor cache first (ip neigh).\n",
                    routes[i].nh_ip, routes[i].dev);
                return 1;
            }
            fprintf(stderr,
                "neighbor missing for %s on %s, waiting for ARP...\n",
                routes[i].nh_ip, routes[i].dev);
            continue;
        }

        if (bpf_map_update_elem(map_fd, &routes[i].src_ip_be, &entry, BPF_ANY) != 0)
            die("bpf_map_update_elem");
    }

    if (do_watch) {
        int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (nl < 0)
            die("netlink socket");

        struct sockaddr_nl sa = {
            .nl_family = AF_NETLINK,
            .nl_groups = RTMGRP_NEIGH,
        };
        if (bind(nl, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            die("netlink bind");

        for (;;) {
            char buf[8192];
            int len = recv(nl, buf, sizeof(buf), 0);
            if (len < 0) {
                if (errno == EINTR)
                    continue;
                die("netlink recv");
            }

            for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, len);
                 h = NLMSG_NEXT(h, len)) {
                if (h->nlmsg_type != RTM_NEWNEIGH && h->nlmsg_type != RTM_DELNEIGH)
                    continue;

                struct ndmsg *m = NLMSG_DATA(h);
                if (m->ndm_family != AF_INET)
                    continue;

                __u32 dst = 0;
                __u8 lladdr[ETH_ALEN];
                bool have_lladdr = false;

                int attrlen = h->nlmsg_len - NLMSG_LENGTH(sizeof(*m));
                for (struct rtattr *a = RTM_RTA(m); RTA_OK(a, attrlen); a = RTA_NEXT(a, attrlen)) {
                    if (a->rta_type == NDA_DST) {
                        memcpy(&dst, RTA_DATA(a), sizeof(dst));
                    } else if (a->rta_type == NDA_LLADDR) {
                        int alen = RTA_PAYLOAD(a);
                        if (alen >= ETH_ALEN) {
                            memcpy(lladdr, RTA_DATA(a), ETH_ALEN);
                            have_lladdr = true;
                        }
                    }
                }

                if (!dst)
                    continue;

                for (int i = 0; i < route_cnt; i++) {
                    if (routes[i].ifindex != m->ndm_ifindex)
                        continue;
                    if (routes[i].nh_ip_be != dst)
                        continue;

                    if (h->nlmsg_type == RTM_NEWNEIGH && have_lladdr) {
                        struct route_entry entry;
                        memset(&entry, 0, sizeof(entry));
                        entry.ifindex = routes[i].ifindex;
                        memcpy(entry.src_mac, routes[i].src_mac, ETH_ALEN);
                        memcpy(entry.dst_mac, lladdr, ETH_ALEN);

                        if (bpf_map_update_elem(map_fd, &routes[i].src_ip_be, &entry, BPF_ANY) != 0)
                            fprintf(stderr, "map update failed for %s\n", routes[i].src_ip);
                    } else if (h->nlmsg_type == RTM_DELNEIGH) {
                        fprintf(stderr, "neighbor removed for %s on %s\n", routes[i].nh_ip, routes[i].dev);
                    }
                }
            }
        }
    }

    return 0;
}

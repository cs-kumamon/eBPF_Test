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
#include <ctype.h>
#include <strings.h>
#include <limits.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_BPF_OBJ "./tc_router_kern.o"
#define MAX_ROUTES 1024
#define TC_HANDLE 0x1
#define TC_PRIO 1
#define TC_RETRY 16
#define ARP_RETRY_MS 1000
#define PING_RETRY_MS 2000

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
    struct in_addr arp_src_ip;
    int arp_src_set;
    int neigh_ready;
    __u64 last_arp_ms;
    __u64 last_ping_ms;
};

struct config {
    char obj_path[PATH_MAX];
    char attach_ingress[512];
    char attach_egress[512];
    int watch;
    int auto_detach;
    int ping_on_miss;
    int mode_detach;
    __u32 handle;
    __u32 prio;
    int route_cnt;
    struct route_arg routes[MAX_ROUTES];
};

static struct config g_cfg;
static volatile sig_atomic_t g_stop = 0;
static int g_auto_detach = 0;

static void die(const char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

static int detach_list(const char *list, enum bpf_tc_attach_point ap, __u32 handle, __u32 prio);

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void cleanup_detach(void)
{
    if (!g_auto_detach)
        return;
    (void)detach_list(g_cfg.attach_ingress, BPF_TC_INGRESS, g_cfg.handle, g_cfg.prio);
    (void)detach_list(g_cfg.attach_egress, BPF_TC_EGRESS, g_cfg.handle, g_cfg.prio);
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '\0')
        return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

static int parse_bool(const char *s)
{
    if (!s)
        return 0;
    if (strcasecmp(s, "1") == 0 || strcasecmp(s, "true") == 0 || strcasecmp(s, "yes") == 0)
        return 1;
    return 0;
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

static __u64 now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

static int run_ping(const char *dev, const char *dst)
{
    pid_t pid = fork();
    if (pid == 0) {
        execlp("ping", "ping", "-I", dev, "-c", "1", "-W", "1", dst, (char *)NULL);
        _exit(127);
    }
    if (pid < 0)
        return -1;
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
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

static int parse_route_value(const char *arg, struct route_arg *out)
{
    char buf[128];
    memset(out, 0, sizeof(*out));
    strncpy(buf, arg, sizeof(buf) - 1);

    const char *delim = strchr(buf, '@') ? "@" : ",";
    char *s = strtok(buf, delim);
    char *n = strtok(NULL, delim);
    char *d = strtok(NULL, delim);

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
    struct bpf_tc_hook hook;
    struct bpf_tc_opts opts;
    memset(&hook, 0, sizeof(hook));
    memset(&opts, 0, sizeof(opts));
    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = ap;
    opts.sz = sizeof(opts);
    opts.prog_fd = prog_fd;

    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST)
        return err;

    for (int i = 0; i < TC_RETRY; i++) {
        opts.handle = *handle + i;
        opts.priority = *prio + i;
        opts.flags = 0;

        err = bpf_tc_attach(&hook, &opts);
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
    struct bpf_tc_hook hook;
    struct bpf_tc_opts opts;
    memset(&hook, 0, sizeof(hook));
    memset(&opts, 0, sizeof(opts));
    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = ap;
    opts.sz = sizeof(opts);
    opts.handle = handle;
    opts.priority = prio;

    int err = bpf_tc_detach(&hook, &opts);
    if (err && err != -ENOENT)
        return err;

    err = bpf_tc_hook_destroy(&hook);
    if (err && err != -ENOENT)
        return err;

    return 0;
}

static int attach_list(const char *list, int prog_fd, enum bpf_tc_attach_point ap,
                       __u32 handle, __u32 prio)
{
    if (!list || list[0] == '\0')
        return 0;

    char *buf = strdup(list);
    if (!buf)
        return -1;

    char *tok = strtok(buf, ",");
    while (tok) {
        int ifindex = if_nametoindex(tok);
        if (!ifindex) {
            fprintf(stderr, "unknown dev: %s\n", tok);
            free(buf);
            return -1;
        }
        __u32 use_handle = handle;
        __u32 use_prio = prio;
        int err = attach_one(ifindex, prog_fd, ap, &use_handle, &use_prio);
        if (err) {
            fprintf(stderr, "attach %s failed: %s\n", tok, strerror(-err));
            free(buf);
            return err;
        }
        fprintf(stderr, "attached %s handle %u prio %u\n", tok, use_handle, use_prio);
        tok = strtok(NULL, ",");
    }

    free(buf);
    return 0;
}

static int detach_list(const char *list, enum bpf_tc_attach_point ap, __u32 handle, __u32 prio)
{
    if (!list || list[0] == '\0')
        return 0;

    char *buf = strdup(list);
    if (!buf)
        return -1;

    char *tok = strtok(buf, ",");
    while (tok) {
        int ifindex = if_nametoindex(tok);
        if (!ifindex) {
            fprintf(stderr, "unknown dev: %s\n", tok);
            free(buf);
            return -1;
        }
        int err = detach_one(ifindex, ap, handle, prio);
        if (err) {
            fprintf(stderr, "detach %s failed: %s\n", tok, strerror(-err));
            free(buf);
            return err;
        }
        tok = strtok(NULL, ",");
    }

    free(buf);
    return 0;
}

static int load_config(const char *path, struct config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->obj_path, DEFAULT_BPF_OBJ, sizeof(cfg->obj_path) - 1);
    cfg->watch = 0;
    cfg->auto_detach = 0;
    cfg->ping_on_miss = 0;
    cfg->mode_detach = 0;
    cfg->handle = TC_HANDLE;
    cfg->prio = TC_PRIO;
    int auto_detach_set = 0;

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        char *hash = strchr(p, '#');
        if (hash)
            *hash = '\0';
        char *semi = strchr(p, ';');
        if (semi)
            *semi = '\0';

        p = trim(p);
        if (*p == '\0')
            continue;

        char *eq = strchr(p, '=');
        if (!eq)
            continue;

        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);

        if (strcasecmp(key, "obj") == 0) {
            strncpy(cfg->obj_path, val, sizeof(cfg->obj_path) - 1);
        } else if (strcasecmp(key, "watch") == 0) {
            cfg->watch = parse_bool(val);
            if (!auto_detach_set)
                cfg->auto_detach = cfg->watch ? 1 : 0;
            if (cfg->watch)
                cfg->ping_on_miss = 1;
        } else if (strcasecmp(key, "mode") == 0) {
            if (strcasecmp(val, "detach") == 0)
                cfg->mode_detach = 1;
        } else if (strcasecmp(key, "auto_detach") == 0) {
            cfg->auto_detach = parse_bool(val);
            auto_detach_set = 1;
        } else if (strcasecmp(key, "ping_on_miss") == 0) {
            cfg->ping_on_miss = parse_bool(val);
        } else if (strcasecmp(key, "handle") == 0) {
            cfg->handle = (__u32)strtoul(val, NULL, 0);
        } else if (strcasecmp(key, "prio") == 0) {
            cfg->prio = (__u32)strtoul(val, NULL, 0);
        } else if (strcasecmp(key, "attach_ingress_devs") == 0) {
            strncpy(cfg->attach_ingress, val, sizeof(cfg->attach_ingress) - 1);
        } else if (strcasecmp(key, "attach_egress_devs") == 0) {
            strncpy(cfg->attach_egress, val, sizeof(cfg->attach_egress) - 1);
        } else if (strcasecmp(key, "attach_devs") == 0) {
            strncpy(cfg->attach_egress, val, sizeof(cfg->attach_egress) - 1);
        } else if (strcasecmp(key, "route") == 0) {
            if (cfg->route_cnt >= MAX_ROUTES) {
                fclose(f);
                errno = E2BIG;
                return -1;
            }
            if (parse_route_value(val, &cfg->routes[cfg->route_cnt]) != 0) {
                fclose(f);
                errno = EINVAL;
                return -1;
            }
            cfg->route_cnt++;
        }
    }

    fclose(f);
    if (!auto_detach_set)
        cfg->auto_detach = cfg->watch ? 1 : 0;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --config PATH\n\n"
        "Config example:\n"
        "  obj=./tc_router_kern.o\n"
        "  watch=1\n"
        "  auto_detach=1\n"
        "  ping_on_miss=1\n"
        "  mode=attach\n"
        "  handle=1\n"
        "  prio=1\n"
        "  attach_ingress_devs=veth0,veth1\n"
        "  attach_egress_devs=enp0s3\n"
        "  route=10.10.1.1,10.10.1.254,veth0\n"
        "  route=10.10.2.1,10.10.2.254,veth1\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *cfg_path = "./tc_router.conf";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            cfg_path = argv[++i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    struct config cfg;
    if (load_config(cfg_path, &cfg) != 0) {
        fprintf(stderr, "failed to load config: %s\n", cfg_path);
        return 1;
    }

    if (cfg.mode_detach) {
        g_auto_detach = 0;
        if (detach_list(cfg.attach_ingress, BPF_TC_INGRESS, cfg.handle, cfg.prio) != 0)
            return 1;
        if (detach_list(cfg.attach_egress, BPF_TC_EGRESS, cfg.handle, cfg.prio) != 0)
            return 1;
        return 0;
    }

    if (cfg.route_cnt == 0) {
        fprintf(stderr, "no routes configured\n");
        return 1;
    }

    g_cfg = cfg;
    g_auto_detach = cfg.auto_detach ? 1 : 0;
    if (g_auto_detach)
        atexit(cleanup_detach);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    struct bpf_object *obj = bpf_object__open_file(cfg.obj_path, NULL);
    if (!obj)
        die("bpf_object__open_file");

    if (bpf_object__load(obj))
        die("bpf_object__load");

    struct bpf_program *prog_ing = bpf_object__find_program_by_name(obj, "tc_router_ingress");
    struct bpf_program *prog_egr = bpf_object__find_program_by_name(obj, "tc_router_egress");
    if (!prog_ing || !prog_egr) {
        fprintf(stderr, "programs tc_router_ingress/egress not found\n");
        return 1;
    }

    int prog_ing_fd = bpf_program__fd(prog_ing);
    int prog_egr_fd = bpf_program__fd(prog_egr);
    if (prog_ing_fd < 0 || prog_egr_fd < 0)
        die("bpf_program__fd");

    if (attach_list(cfg.attach_ingress, prog_ing_fd, BPF_TC_INGRESS, cfg.handle, cfg.prio) != 0)
        return 1;
    if (attach_list(cfg.attach_egress, prog_egr_fd, BPF_TC_EGRESS, cfg.handle, cfg.prio) != 0)
        return 1;

    int map_fd = bpf_object__find_map_fd_by_name(obj, "route_map");
    if (map_fd < 0)
        die("find route_map");

    for (int i = 0; i < cfg.route_cnt; i++) {
        struct in_addr src, nh;
        if (inet_pton(AF_INET, cfg.routes[i].src_ip, &src) != 1) {
            fprintf(stderr, "bad src ip: %s\n", cfg.routes[i].src_ip);
            return 1;
        }
        if (inet_pton(AF_INET, cfg.routes[i].nh_ip, &nh) != 1) {
            fprintf(stderr, "bad next-hop ip: %s\n", cfg.routes[i].nh_ip);
            return 1;
        }

        int ifindex = if_nametoindex(cfg.routes[i].dev);
        if (!ifindex) {
            fprintf(stderr, "unknown dev: %s\n", cfg.routes[i].dev);
            return 1;
        }
        cfg.routes[i].ifindex = ifindex;
        cfg.routes[i].src_ip_be = src.s_addr;
        cfg.routes[i].nh_ip_be = nh.s_addr;
        cfg.routes[i].neigh_ready = 0;
        cfg.routes[i].last_arp_ms = 0;
        cfg.routes[i].last_ping_ms = 0;

        struct route_entry entry;
        memset(&entry, 0, sizeof(entry));
        entry.ifindex = ifindex;

        if (get_if_mac(cfg.routes[i].dev, entry.src_mac) != 0) {
            fprintf(stderr, "failed to get src mac for %s\n", cfg.routes[i].dev);
            return 1;
        }
        memcpy(cfg.routes[i].src_mac, entry.src_mac, ETH_ALEN);

        struct in_addr if_ip;
        if (get_if_ipv4(cfg.routes[i].dev, &if_ip) == 0) {
            cfg.routes[i].arp_src_ip = if_ip;
            cfg.routes[i].arp_src_set = 1;
        } else {
            cfg.routes[i].arp_src_ip = src;
            cfg.routes[i].arp_src_set = 1;
        }

        if (lookup_neigh_mac_nl(cfg.routes[i].nh_ip, ifindex, entry.dst_mac) != 0) {
            /* Try to trigger ARP, then continue if watch mode is enabled */
            (void)send_arp_request(cfg.routes[i].dev, ifindex, entry.src_mac,
                                   cfg.routes[i].arp_src_ip, nh);
            if (cfg.ping_on_miss)
                (void)run_ping(cfg.routes[i].dev, cfg.routes[i].nh_ip);
            if (!cfg.watch) {
                fprintf(stderr,
                    "no neighbor entry for %s on %s. "
                    "Populate neighbor cache first (ip neigh).\n",
                    cfg.routes[i].nh_ip, cfg.routes[i].dev);
                return 1;
            }
            fprintf(stderr,
                "neighbor missing for %s on %s, waiting for ARP...\n",
                cfg.routes[i].nh_ip, cfg.routes[i].dev);
            continue;
        }

        if (bpf_map_update_elem(map_fd, &cfg.routes[i].src_ip_be, &entry, BPF_ANY) != 0)
            die("bpf_map_update_elem");
        cfg.routes[i].neigh_ready = 1;
    }

    if (cfg.watch) {
        int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (nl < 0)
            die("netlink socket");

        struct sockaddr_nl sa = {
            .nl_family = AF_NETLINK,
            .nl_groups = RTMGRP_NEIGH,
        };
        if (bind(nl, (struct sockaddr *)&sa, sizeof(sa)) < 0)
            die("netlink bind");

        struct pollfd pfd = {
            .fd = nl,
            .events = POLLIN,
        };

        for (;;) {
            if (g_stop)
                break;
            __u64 now = now_ms();
            for (int i = 0; i < cfg.route_cnt; i++) {
                if (cfg.routes[i].neigh_ready)
                    continue;
                if (cfg.routes[i].arp_src_set == 0)
                    continue;
                if (now - cfg.routes[i].last_arp_ms < ARP_RETRY_MS)
                    goto maybe_ping;
                {
                    struct in_addr nh;
                    nh.s_addr = cfg.routes[i].nh_ip_be;
                    (void)send_arp_request(cfg.routes[i].dev, cfg.routes[i].ifindex,
                                           cfg.routes[i].src_mac, cfg.routes[i].arp_src_ip, nh);
                    cfg.routes[i].last_arp_ms = now;
                }
maybe_ping:
                if (cfg.ping_on_miss) {
                    if (now - cfg.routes[i].last_ping_ms >= PING_RETRY_MS) {
                        (void)run_ping(cfg.routes[i].dev, cfg.routes[i].nh_ip);
                        cfg.routes[i].last_ping_ms = now;
                    }
                }
            }

            int pret = poll(&pfd, 1, 1000);
            if (pret < 0) {
                if (errno == EINTR)
                    continue;
                die("poll");
            }
            if (pret == 0)
                continue;
            if (!(pfd.revents & POLLIN))
                continue;

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

                for (int i = 0; i < cfg.route_cnt; i++) {
                    if (cfg.routes[i].ifindex != m->ndm_ifindex)
                        continue;
                    if (cfg.routes[i].nh_ip_be != dst)
                        continue;

                    if (h->nlmsg_type == RTM_NEWNEIGH && have_lladdr) {
                        struct route_entry entry;
                        memset(&entry, 0, sizeof(entry));
                        entry.ifindex = cfg.routes[i].ifindex;
                        memcpy(entry.src_mac, cfg.routes[i].src_mac, ETH_ALEN);
                        memcpy(entry.dst_mac, lladdr, ETH_ALEN);

                        if (bpf_map_update_elem(map_fd, &cfg.routes[i].src_ip_be, &entry, BPF_ANY) != 0)
                            fprintf(stderr, "map update failed for %s\n", cfg.routes[i].src_ip);
                        cfg.routes[i].neigh_ready = 1;
                        cfg.routes[i].last_arp_ms = now_ms();
                    } else if (h->nlmsg_type == RTM_DELNEIGH) {
                        fprintf(stderr, "neighbor removed for %s on %s\n",
                                cfg.routes[i].nh_ip, cfg.routes[i].dev);
                        cfg.routes[i].neigh_ready = 0;
                        cfg.routes[i].last_arp_ms = 0;
                    }
                }
            }
        }
    }

    return 0;
}

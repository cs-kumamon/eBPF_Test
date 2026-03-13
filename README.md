# TC BPF 源地址分流路由

这是一个使用 **TC BPF** 实现的“按源 IP 选择出口接口”的软件路由方案，目标是替代策略路由表（`ip rule`），突破策略路由数量限制，并支持**动态邻居学习**（ARP/Netlink）。

## 功能概览
- 按源 IP 查表选择出口接口
- 动态获取下一跳 MAC（Netlink 监听邻居变化）
- TC egress 挂载，适配本机发起流量
- 自动触发 ARP 请求（邻居缺失时）
- 进程退出自动 detach（可配置）
- 兼容已有 tc filter（自动尝试新的 handle/prio）

## 目录结构
- `src/tc_router_kern.c`  BPF 内核态程序
- `src/tc_router_user.c`  用户态装载与动态更新
- `scripts/setup.sh`  示例 veth 环境
- `scripts/run.sh`  编译并加载
- `scripts/cleanup.sh`  卸载并清理
- `docs/USAGE.md`  使用手册（详细）

## 快速上手
```bash
sudo ./scripts/setup.sh
sudo ./scripts/run.sh
```

如果需要挂载到指定出口（如 `enp0s3`）：
```bash
sudo ATTACH_EGRESS_DEVS=enp0s3 ./scripts/run.sh
```

## 适用场景提示
本机发起的流量必须经过它选择的出口接口，TC 程序应挂在**实际出流量的接口**（通常是默认路由接口）。在该出口处将目标 MAC 改写为“下一跳 MAC”，并 `bpf_redirect` 到指定 veth。

如客户端绑定源地址但**不要**绑定设备（避免 `No route to host`）：
- 保持默认路由由系统选择
- 在默认路由出口（如 `enp0s3`）做 BPF 重定向

详细使用说明见：`docs/USAGE.md`（含配置文件说明与 `config/tc_router.conf` 示例）

## 编译依赖
- clang / llvm
- libbpf-dev
- pkg-config
- libelf / zlib

Ubuntu/Debian:
```bash
sudo apt-get install -y clang llvm libbpf-dev pkg-config libelf-dev zlib1g-dev
```

## 卸载
```bash
sudo ./tc_router --config config/tc_router_detach.conf
```

## 许可
GPL-2.0

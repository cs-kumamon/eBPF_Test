# 使用手册（TC BPF 源地址分流）

本文档说明如何在**不使用策略路由**的情况下，通过 TC BPF 按源 IP 选择出口接口，并动态学习下一跳 MAC。

## 目录结构
-
  `src/tc_router_kern.c`  
  TC BPF 程序（改写 L2 / TTL / 校验和 + redirect）
-
  `src/tc_router_user.c`  
  用户态装载与动态邻居更新（Netlink + ARP 触发）
-
  `scripts/run.sh`  
  编译并加载（默认挂载到默认路由出口）
-
  `scripts/setup.sh`  
  创建 veth 对（示例环境）
-
  `scripts/cleanup.sh`  
  卸载与清理

## 依赖
-
  `clang` / `llvm`
-
  `libbpf-dev`
-
  `pkg-config`
-
  `libelf`, `zlib`

Ubuntu/Debian:
```bash
sudo apt-get install -y clang llvm libbpf-dev pkg-config libelf-dev zlib1g-dev
```

## 架构说明（关键点）
-
  本机发出的流量**只会经过它选择的出口接口**。
-
  TC 程序必须挂在**实际出流量的接口**上（通常是默认路由接口，如 `enp0s3`）。
-
  BPF 程序按源 IP 查表，改写目的 MAC 为**下一跳 MAC**，并 `bpf_redirect()` 到目标 `veth` 接口。
-
  下一跳 MAC 通过 Netlink 邻居表获取；若缺失，在 `--watch` 模式下会发送 ARP 请求并等待邻居事件。

## 一键运行（示例环境）
```bash
sudo ./scripts/setup.sh
sudo ./scripts/run.sh
```

`scripts/run.sh` 默认挂载到**系统默认路由接口**。如需指定：
```bash
sudo ATTACH_DEVS=enp0s3 ./scripts/run.sh
```

## 手动运行
```bash
make -s

sudo ./tc_router --watch \
  --attach-devs enp0s3 \
  --devs veth0,veth1 \
  --route 10.10.1.1@10.10.1.254@veth0 \
  --route 10.10.2.1@10.10.2.254@veth1
```

### 参数说明
-
  `--attach-devs`  
  实际挂载 TC 的设备（必须是本机流量将要发出的设备）。
-
  `--devs`  
  需要按源 IP 选择的出口设备列表（路由表里的“目标出口”）。
-
  `--route SRC@NH@DEV`  
  源 IP → 下一跳 IP → 出口设备  
  例：`10.10.2.1@10.10.2.254@veth1`
-
  `--watch`  
  进入常驻模式，监听邻居变化并动态更新 map。
-
  `--attach-point`  
  默认 `egress`。本机发流量必须使用 `egress`。
-
  `--handle` / `--prio`  
  指定 tc 过滤器的 handle/prio（用于避免冲突）。

## 典型场景：本机流量分流
如果客户端绑定源地址 `10.10.2.1`，访问 `192.168.2.1`：
-
  **不要**对 socket 使用 `SO_BINDTODEVICE(veth1)`。  
  否则内核会强制在 `veth1` 上查路由，找不到就会 `No route to host`。
-
  让内核走默认路由（如 `enp0s3`），在 `enp0s3` egress 处由 BPF 改写并重定向到 `veth1`。

## 动态邻居学习
-
  若 `10.10.2.254` 还没有邻居条目，程序会发送 ARP 请求。
-
  一旦仿真软件回应，Netlink 事件触发更新 map。
-
  你也可以手工触发：
  ```bash
  ip neigh show dev veth1
  ```

## 常见问题
-
  **`Exclusivity flag on, cannot modify` / `Filter already exists`**  
  说明已有 tc filter 占用相同 prio/handle。  
  可通过 `--handle` / `--prio` 换一组，或先卸载：
  ```bash
  sudo ./tc_router --detach --attach-devs enp0s3 --devs veth0,veth1
  ```
-
  **`No route to host`**  
  多半是 socket 绑定了设备（`SO_BINDTODEVICE`）导致路由失败。  
  请移除绑定或保证该设备上存在路由。
-
  **邻居不存在**  
  使用 `--watch` 会自动发 ARP 并等待邻居事件。

## 卸载
```bash
sudo ./tc_router --detach --attach-devs enp0s3 --devs veth0,veth1
```

## 清理示例环境
```bash
sudo ./scripts/cleanup.sh
```

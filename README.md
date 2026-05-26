# NGINX Rift — CVE-2026-42945 / CVE-2026-9256 漏洞扫描与验证工具

<p align="center">
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/CVE--2026--42945%20%7C%20CVE--2026--9256-red?style=flat-square" alt="CVE-2026-42945 | CVE-2026-9256">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

NGINX Rift 是一款针对 **CVE-2026-42945** 和 **CVE-2026-9256**（NGINX `ngx_http_rewrite_module` 堆溢出漏洞）的开源扫描与验证工具。支持远程网络指纹扫描和本地深度配置审计，帮助安全团队快速排查 NGINX 环境中的潜在风险。

## 漏洞概述

### CVE-2026-9256 (CVSS 4.0: 9.2 Critical)

| 属性 | 详情 |
|------|------|
| **CVE 编号** | CVE-2026-9256 |
| **漏洞类型** | 堆缓冲区溢出 (Heap-based Buffer Overflow, CWE-122) |
| **影响组件** | NGINX `ngx_http_rewrite_module` |
| **影响版本** | NGINX 开源版 0.1.17 ~ 1.31.0 (mainline) / 0.1.17 ~ 1.30.1 (stable) |
| **修复版本** | NGINX 1.31.1 (mainline) / 1.30.2 (stable)，发布于 2026-05-22 |
| **危害等级** | 高危 — 可导致拒绝服务 (DoS)，ASLR 关闭时可实现远程代码执行 (RCE) |

**触发条件**：`rewrite` 指令使用 PCRE 正则表达式且存在重叠捕获，替换字符串中引用了多个未命名捕获组。

### CVE-2026-42945

| 属性 | 详情 |
|------|------|
| **CVE 编号** | CVE-2026-42945 |
| **漏洞类型** | 堆溢出 (Heap Overflow) |
| **影响组件** | NGINX `ngx_http_rewrite_module` |
| **影响版本** | NGINX 开源版 0.6.27 ~ 1.30.0 / NGINX Plus R32 ~ R36 |
| **修复版本** | NGINX 1.30.1 (stable) / 1.31.0 (mainline) / NGINX Plus R32 P6+ |
| **危害等级** | 高危 — 可导致拒绝服务 (DoS) 和远程代码执行 (RCE) |

**触发条件**：`rewrite` 指令的替换 URL 中同时包含 `?` 和未命名捕获组引用（如 `$1`）。

### 存在漏洞的配置示例

```nginx
# CVE-2026-42945 触发配置: ? + $1
rewrite ^/api/(.*)$ /internal?id=$1 last;

# CVE-2026-9256 触发配置: 多个 $N 捕获引用
rewrite ^/(\w+)/(\d+)$ /$2/$1 last;

# 安全配置 (使用命名捕获组)
rewrite ^/api/(?<myid>.*)$ /internal?id=$myid last;
```

## 功能特性

- **远程扫描模式 (Scan)** — 通过 HTTP 响应头指纹识别 NGINX 版本，支持单目标和批量扫描
- **本地验证模式 (Verify)** — 三步立体审计：二进制版本检测 → 配置文件语义分析 → K8s Ingress 资源探测
- **OS 补丁回溯检测** — 联动 `dpkg`/`rpm` 包管理器，检测发行版是否已通过 Backport 修复漏洞
- **K8s 云原生支持** — 自动发现 Kubernetes Ingress 资源中的危险 `rewrite-target` 注解
- **零依赖** — 纯 Go 标准库实现，单文件编译，无第三方依赖
- **跨平台** — 支持 Windows / Linux / macOS (amd64 + arm64)

## 安装

### 方式一：下载预编译二进制

从 [Releases](../../releases) 页面下载对应平台的二进制文件。

### 方式二：源码编译

```bash
git clone https://github.com/nu0l/NGINX-Rift.git
cd NGINX-Rift

# 单平台编译
go build -o nginx_rift_scanner nginx_rift_scanner.go

# 全平台交叉编译
chmod +x build.sh && ./build.sh
```

## 使用方法

### 查看帮助

```bash
./nginx_rift_scanner -h
```

### Scan 模式 — 远程网络扫描

```bash
# 扫描单个目标
./nginx_rift_scanner scan -u http://example.com

# 批量扫描（从文件读取 URL 列表）
./nginx_rift_scanner scan -f url.txt
```

`url.txt` 每行一个 URL，例如：

```
http://target1.com
https://target2.com
target3.com
```

### Verify 模式 — 本地深度审计

```bash
# 自动查找默认 NGINX 配置路径
./nginx_rift_scanner verify

# 指定配置文件路径
./nginx_rift_scanner verify -p /etc/nginx/nginx.conf
```

Verify 模式执行三步审计：

1. **二进制版本检测** — 运行 `nginx -v` 获取版本，并检查 OS 包管理器的 Backport 补丁
2. **配置文件分析** — 递归解析 NGINX 配置（含 `include` 指令），识别危险的 rewrite 规则
3. **K8s Ingress 探测** — 若检测到 `kubectl`，自动扫描集群中所有 Ingress 资源

## 修复建议

| 优先级 | 方案 | 说明 |
|--------|------|------|
| P0 | 升级 NGINX | 升级至 1.30.2+ (stable) / 1.31.1+ (mainline) / NGINX Plus 最新安全版本 |
| P0 | OS 包管理器更新 | `apt-get upgrade nginx` 或 `yum update nginx` |
| P1 | 紧急配置缓解 | 将 rewrite 中的 `$1`、`$2` 等改为命名捕获组 `$name`，无需停机 |
| P2 | K8s Ingress 修复 | 升级 Ingress Controller 并修改 `rewrite-target` 注解 |
| P3 | 纵深防御 | 配置 `server_tokens off;` 隐藏版本指纹 |

## 项目结构

```
NGINX-Rift/
├── nginx_rift_scanner.go         # 主程序源码
├── build.sh                      # 全平台交叉编译脚本
├── go.mod                        # Go 模块定义
└── README.md
```

## 技术实现

- 使用 Go 标准库 `net/http` 发送 HTTP 请求，解析 `Server` 响应头
- 正则匹配提取开源版 (`nginx/X.Y.Z`) 和商业版 (`NGINX Plus RXX`) 版本号
- 版本范围覆盖 CVE-2026-42945 (0.6.27 - 1.30.0) 和 CVE-2026-9256 (0.1.17 - 1.31.0) 的并集
- 递归解析 NGINX 配置文件，跟踪 `include` 指令，使用 `visited` map 防止循环引用
- 配置检测同时识别两种漏洞模式: `?` + `$N` (CVE-2026-42945) 和多个 `$N` 引用 (CVE-2026-9256)
- 通过 `kubectl get ingress --all-namespaces -o yaml` 动态获取 K8s Ingress 配置
- 调用 `dpkg-query`/`rpm --changelog` 检测 OS 级 Backport 补丁 (同时搜索两个 CVE 编号)
- 静态编译 (`CGO_ENABLED=0`)，生成无 C 依赖的独立二进制

## 许可证

MIT License

## 致谢

由安全社区贡献。

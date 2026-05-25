# NGINX Rift — CVE-2026-42945 漏洞扫描与验证工具

<p align="center">
  <img src="https://img.shields.io/badge/language-Go-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/CVE-2026--42945-red?style=flat-square" alt="CVE-2026-42945">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

NGINX Rift 是一款针对 **CVE-2026-42945**（NGINX `ngx_http_rewrite_module` 堆溢出漏洞）的开源扫描与验证工具。支持远程网络指纹扫描和本地深度配置审计，帮助安全团队快速排查 NGINX 环境中的潜在风险。

## 漏洞概述

| 属性 | 详情 |
|------|------|
| **CVE 编号** | CVE-2026-42945 |
| **漏洞类型** | 堆溢出 (Heap Overflow) |
| **影响组件** | NGINX `ngx_http_rewrite_module` |
| **影响版本** | NGINX 开源版 0.6.27 ~ 1.30.0 / NGINX Plus R32 ~ R36 |
| **修复版本** | NGINX 1.30.1 (stable) / 1.31.0 (mainline) / NGINX Plus R32 P6+ |
| **危害等级** | 高危 — 可导致拒绝服务 (DoS) 和远程代码执行 (RCE) |

**触发条件**（三者需同时满足）：

1. NGINX 配置中存在 `rewrite` 指令
2. 替换 URL 中包含 `?`（查询字符串分隔符）
3. 替换 URL 中引用了未命名捕获组（如 `$1`、`$2`）

**存在漏洞的配置示例：**

```nginx
rewrite ^/api/(.*)$ /internal?id=$1 last;
```

**安全配置（使用命名捕获组）：**

```nginx
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
git clone https://github.com/ZunAn-Tech/NGINX-Rift.git
cd NGINX-Rift

# 单平台编译
go build -o nginx_rift_scanner zakj_nginx_rift_scanner.go

# 全平台交叉编译
chmod +x build.sh && ./build.sh
```

## 使用方法

### 查看帮助

```bash
./zakj_nginx_rift_scanner -h
```

### Scan 模式 — 远程网络扫描

```bash
# 扫描单个目标
./zakj_nginx_rift_scanner scan -u http://example.com

# 批量扫描（从文件读取 URL 列表）
./zakj_nginx_rift_scanner scan -f url.txt
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
./zakj_nginx_rift_scanner verify

# 指定配置文件路径
./zakj_nginx_rift_scanner verify -p /etc/nginx/nginx.conf
```

Verify 模式执行三步审计：

1. **二进制版本检测** — 运行 `nginx -v` 获取版本，并检查 OS 包管理器的 Backport 补丁
2. **配置文件分析** — 递归解析 NGINX 配置（含 `include` 指令），识别危险的 rewrite 规则
3. **K8s Ingress 探测** — 若检测到 `kubectl`，自动扫描集群中所有 Ingress 资源

## 修复建议

| 优先级 | 方案 | 说明 |
|--------|------|------|
| P0 | 升级 NGINX | 升级至 1.30.1+ / 1.31.0+ / NGINX Plus R32 P6+ |
| P0 | OS 包管理器更新 | `apt-get upgrade nginx` 或 `yum update nginx` |
| P1 | 紧急配置缓解 | 将 rewrite 中的 `$1` 改为命名捕获组 `$name`，无需停机 |
| P2 | K8s Ingress 修复 | 升级 Ingress Controller 并修改 `rewrite-target` 注解 |
| P3 | 纵深防御 | 配置 `server_tokens off;` 隐藏版本指纹 |

## 项目结构

```
NGINX-Rift/
├── zakj_nginx_rift_scanner.go    # 主程序源码
├── build.sh                      # 全平台交叉编译脚本
├── go.mod                        # Go 模块定义
└── README.md
```

## 技术实现

- 使用 Go 标准库 `net/http` 发送 HTTP 请求，解析 `Server` 响应头
- 正则匹配提取开源版 (`nginx/X.Y.Z`) 和商业版 (`NGINX Plus RXX`) 版本号
- 递归解析 NGINX 配置文件，跟踪 `include` 指令，使用 `visited` map 防止循环引用
- 通过 `kubectl get ingress --all-namespaces -o yaml` 动态获取 K8s Ingress 配置
- 调用 `dpkg-query`/`rpm --changelog` 检测 OS 级 Backport 补丁
- 静态编译 (`CGO_ENABLED=0`)，生成无 C 依赖的独立二进制

## 许可证

MIT License

## 致谢

由 [尊安科技 (ZunAn Technology)](https://github.com/ZunAn-Tech) 安全团队开发。

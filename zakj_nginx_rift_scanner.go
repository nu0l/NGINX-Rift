// 完整的、带有详尽注释的单文件 Go 语言脚本，用于检测 CVE-2026-42945 (NGINX Rift)
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorPurple = "\033[35m"
)

func printBanner() {
	fmt.Println(ColorCyan + strings.Repeat("=", 65) + ColorReset)
	fmt.Println(ColorCyan + " NGINX Rift (CVE-2026-42945) 漏洞扫描与验证工具" + ColorReset)
	fmt.Println(ColorCyan + strings.Repeat("=", 65) + ColorReset)
}

func printHelp() {
	fmt.Println(`
使用示例:
比如Linux环境, 就是:
  ./nginx_rift_scanner-linux -h

  [网络扫描模式 - Scan]
  ./nginx_rift_scanner-[具体环境版本] scan -u http://example.com            # 扫描单个目标，获取服务器响应及 NGINX 版本
  ./nginx_rift_scanner-[具体环境版本] scan -f url.txt                       # 批量扫描，从 url.txt 读取目标列表

  [本地验证模式 - Verify]
  ./nginx_rift_scanner-[具体环境版本] verify                                # 自动查找默认 NGINX 配置文件进行深度分析
  ./nginx_rift_scanner-[具体环境版本] verify -p /etc/nginx/nginx.conf       # 扫描指定的本地 NGINX 配置文件
  
  ./nginx_rift_scanner-[具体环境版本] -h                                    # 输出本使用教程


工具说明:
  【Scan 模式】关注 HTTP 响应头中的版本指纹暴露。支持识别 NGINX 开源版及 NGINX Plus (R系列) 商业版。
   注: 由于 Linux 发行版(如 CentOS/Ubuntu)的“向后移植(Backport)”特性，
       低版本可能已在内部打了补丁（产生版本错觉）。此模式兼具检查隐藏响应头的功能。
  
  【Verify 模式】关注漏洞的核心触发条件：
   1. 原生 NGINX: 配置文件中是否存在危险的 rewrite 规则 (包含 '?' 和 未命名捕获组如 '$1')。
   2. K8s Ingress: YAML 文件中是否存在危险的 rewrite-target 注解配置。
   同时联动底层操作系统的包管理器(apt/yum)进行安全基线检查。`)
}

func main() {
	printBanner() // 每次运行都打印尊安科技的 Banner

	if len(os.Args) < 2 {
		printHelp()
		return
	}

	command := os.Args[1]

	switch command {
	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		targetURL := scanCmd.String("u", "", "单个目标 URL (如 http://example.com)")
		fileList := scanCmd.String("f", "", "包含 URL 列表的文件路径")
		scanCmd.Parse(os.Args[2:])

		if *targetURL != "" {
			vuln, exposed, _ := runScan(*targetURL)
			if vuln {
				printRemediation()
			} else if exposed {
				printHideHeaderAdvice()
			}
		} else if *fileList != "" {
			vuln, exposed := runBatchScan(*fileList)
			if vuln {
				printRemediation()
			} else if exposed {
				printHideHeaderAdvice()
			}
		} else {
			fmt.Println(ColorRed + "[-] 必须提供 -u 或 -f 参数" + ColorReset)
			scanCmd.Usage()
		}

	case "verify":
		verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
		configPath := verifyCmd.String("p", "", "NGINX 配置文件路径 (可选，留空则自动查找默认路径)")
		verifyCmd.Parse(os.Args[2:])

		runVerify(*configPath)

	case "-h", "--help", "help":
		printHelp()

	default:
		fmt.Printf(ColorRed+"[-] 未知命令: %s\n"+ColorReset, command)
		printHelp()
	}
}

// ---------------------------
// Scan 模式相关逻辑
// ---------------------------

func runBatchScan(filePath string) (bool, bool) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf(ColorRed+"[-] 无法读取文件: %v\n"+ColorReset, err)
		return false, false
	}
	defer file.Close()

	var vulnList []string
	var safeList []string
	var failedList []string

	anyVuln := false
	anyExposed := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "http://" + url
			}
			vuln, exposed, success := runScan(url)
			if !success {
				failedList = append(failedList, url)
				continue
			}
			if vuln {
				anyVuln = true
				vulnList = append(vulnList, url)
			} else {
				safeList = append(safeList, url)
			}
			if exposed {
				anyExposed = true
			}
		}
	}

	// 打印美观的扫描结果汇总清单
	fmt.Println("\n" + ColorCyan + "================ 批量扫描结果汇总 ================" + ColorReset)
	fmt.Printf("[*] 总计扫描: %d 个目标\n", len(vulnList)+len(safeList)+len(failedList))

	if len(vulnList) > 0 {
		fmt.Println(ColorRed + "\n[!] 存在漏洞版本暴露的标靶 (需重点关注):" + ColorReset)
		for _, u := range vulnList {
			fmt.Println("  - " + u)
		}
	}

	if len(safeList) > 0 {
		fmt.Println(ColorGreen + "\n[+] 不受影响的标靶 (安全/版本已隐藏):" + ColorReset)
		for _, u := range safeList {
			fmt.Println("  - " + u)
		}
	}

	if len(failedList) > 0 {
		fmt.Println(ColorYellow + "\n[-] 请求失败的标靶 (无法连接或超时):" + ColorReset)
		for _, u := range failedList {
			fmt.Println("  - " + u)
		}
	}
	fmt.Println(ColorCyan + "==================================================" + ColorReset)

	return anyVuln, anyExposed
}

func runScan(targetURL string) (bool, bool, bool) {
	fmt.Printf("\n[*] 正在扫描目标: %s\n", targetURL)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 忽略证书错误以便扫描
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		fmt.Printf(ColorRed+"[-] 请求失败: %v\n"+ColorReset, err)
		return false, false, false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // 读取并丢弃 body，复用连接

	serverHeader := resp.Header.Get("Server")
	if serverHeader == "" {
		fmt.Println(ColorGreen + "[+] 目标未返回 Server 响应头，指纹隐藏良好。" + ColorReset)
		return false, false, true
	}

	fmt.Printf("[*] 发现 Server 响应头: %s\n", serverHeader)

	if !strings.Contains(strings.ToLower(serverHeader), "nginx") {
		fmt.Println(ColorGreen + "[+] 未检测到 NGINX 标识，似乎不受影响。" + ColorReset)
		return false, false, true
	}

	// 提取 NGINX Plus 版本
	plusVersion := extractPlusVersion(serverHeader)
	version := extractVersion(serverHeader)

	if version == "" && plusVersion == "" {
		// 包含 nginx 但没有版本号，说明使用了 server_tokens off;
		fmt.Println(ColorGreen + "[+] NGINX 服务头存在，但版本号已隐藏 (server_tokens off 生效)，具备良好的纵深防御配置。" + ColorReset)
		return false, false, true
	}

	if plusVersion != "" {
		fmt.Printf(ColorYellow+"[!] 发现 NGINX Plus (商业版) 版本暴露: %s\n"+ColorReset, plusVersion)
		if isPlusVersionInVulnerableRange(plusVersion) {
			fmt.Println(ColorRed + "[!] 警告: 该版本在 NGINX Plus 的已知受影响范围内 (R32 - R36)!" + ColorReset)
			return true, false, true
		} else {
			fmt.Println(ColorGreen + "[+] 该商业版本不在已知的受影响范围内。" + ColorReset)
			return false, true, true
		}
	} else {
		fmt.Printf(ColorYellow+"[!] 发现 NGINX 开源版版本暴露: %s\n"+ColorReset, version)
		if isVersionInVulnerableRange(version) {
			fmt.Println(ColorRed + "[!] 警告: 该版本在 CVE-2026-42945 的潜在受影响范围内 (0.6.27 - 1.30.0)!" + ColorReset)
			fmt.Println(ColorYellow + "    -> 请注意: 即使版本匹配，如果系统是由 APT/YUM 包管理器安装，补丁可能已被向后移植(Backported)。")
			fmt.Println("    -> 同时，漏洞的触发强依赖于特定的 rewrite 配置。建议使用 verify 模式在服务器本地进行确认。" + ColorReset)
			return true, false, true
		} else {
			fmt.Println(ColorGreen + "[+] 该版本不在已知的受影响范围内。" + ColorReset)
			return false, true, true
		}
	}
}

func extractVersion(serverHeader string) string {
	re := regexp.MustCompile(`[nN][gG][iI][nN][xX]/(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(serverHeader)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// 提取 NGINX Plus 的 R 版本号
func extractPlusVersion(serverHeader string) string {
	re := regexp.MustCompile(`(?i)NGINX\s+Plus\s+(R\d+)`)
	matches := re.FindStringSubmatch(serverHeader)
	if len(matches) > 1 {
		return strings.ToUpper(matches[1]) // 返回大写的 Rxx
	}
	return ""
}

// 检查是否在 0.6.27 到 1.30.0 之间
func isVersionInVulnerableRange(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	patch, _ := strconv.Atoi(parts[2])

	if major == 0 && minor == 6 && patch >= 27 {
		return true
	}
	if major == 0 && minor > 6 {
		return true
	}
	if major == 1 && minor < 30 {
		return true
	}
	if major == 1 && minor == 30 && patch == 0 {
		return true
	}
	return false
}

// 检查 NGINX Plus 版本是否在 R32 到 R36 之间
func isPlusVersionInVulnerableRange(plusVersion string) bool {
	if len(plusVersion) < 2 {
		return false
	}
	rNumStr := plusVersion[1:]
	rNum, err := strconv.Atoi(rNumStr)
	if err != nil {
		return false
	}

	if rNum >= 32 && rNum <= 36 {
		return true
	}
	return false
}

func printRemediation() {
	fmt.Println("\n" + ColorCyan + "=== 尊安科技修复与缓解建议 ===" + ColorReset)
	fmt.Println(ColorYellow + "方案一：紧急配置缓解 (推荐，无需停机重启即可生效)" + ColorReset)
	fmt.Println("   若无法立即升级，请修改 nginx.conf。将包含未命名捕获组($1,$2)和问号(?)的 rewrite 改为命名捕获组。")
	fmt.Println("   [存在漏洞] rewrite ^/api/(.*)$ /internal?id=$1 last;")
	fmt.Println("   [安全配置] rewrite ^/api/(?<myid>.*)$ /internal?id=$myid last;")
	fmt.Println("   修改后执行: nginx -t && nginx -s reload")

	fmt.Println(ColorYellow + "\n方案二：云原生 K8s Ingress 缓解" + ColorReset)
	fmt.Println("   排查所有 Ingress 资源，避免在 rewrite-target 注解中使用带问号和未命名捕获组的配置。")
	fmt.Println("   升级 NGINX Ingress Controller 至 3.7.3, 4.0.2 或 5.4.2 及以上版本。")

	fmt.Println(ColorYellow + "\n方案三：操作系统包管理器更新 (Backport补丁)" + ColorReset)
	fmt.Println("   对于 Ubuntu/Debian: 执行 apt-get update && apt-get upgrade nginx")
	fmt.Println("   对于 CentOS/RHEL: 执行 yum update nginx")
	fmt.Println("   更新后，请通过本工具的 verify 模式确认是否包含安全基线补丁。")

	fmt.Println(ColorYellow + "\n方案四：源码编译升级" + ColorReset)
	fmt.Println("   将 NGINX 开源版升级至 1.30.1 / 1.31.0 或更高版本。")
	fmt.Println("   商业版 NGINX Plus 请升级至 R32 P6, R36 P4 等包含补丁的安全版本。")

	fmt.Println(ColorYellow + "\n方案五：纵深防御 (隐藏响应头版本暴露)" + ColorReset)
	fmt.Println("   无论版本是否安全，当前服务器暴露了确切的 NGINX 版本号，为攻击者提供了指纹便利。")
	fmt.Println("   1. 原生 NGINX: 在 nginx.conf 的 http { ... } 块中配置 server_tokens off;")
	fmt.Println("   2. K8s Ingress: 在 NGINX ConfigMap 资源中配置 server-tokens: \"False\"")
}

func printHideHeaderAdvice() {
	fmt.Println("\n" + ColorCyan + "=== 纵深防御建议: 隐藏响应头版本暴露 ===" + ColorReset)
	fmt.Println("虽然当前系统版本处于安全范围，但暴露确切的组件版本号会给潜在攻击者提供侦察信息。")
	fmt.Println("建议您进行如下配置以增加攻击试探成本：")
	fmt.Println("1. 原生 NGINX: 打开主配置文件 (如 /etc/nginx/nginx.conf)，在 http { ... } 块中添加 server_tokens off;")
	fmt.Println("2. 云原生 K8s Ingress: 在 NGINX Ingress Controller 的 ConfigMap 中添加 server-tokens: \"False\"")
	fmt.Println("3. 修改后重载配置使其生效 (nginx -s reload)。")
}

// ---------------------------
// Verify 模式相关逻辑 (三步立体防御审计)
// ---------------------------

func runVerify(customPath string) {
	isBinaryVulnerable := false
	hasOSPatch := false

	// --- 步骤一：检测本地 NGINX 核心二进制版本 ---
	fmt.Println(ColorCyan + "\n[1/3] 正在检测本地 NGINX 核心组件版本 (防范潜在环境风险)..." + ColorReset)
	if customPath == "" {
		isVulnVer, verStr, found := checkLocalNginxVersion()
		if found {
			if isVulnVer {
				fmt.Printf(ColorYellow+"  [!] 警告: 本地 NGINX 二进制版本 (%s) 处于受影响范围内！\n"+ColorReset, verStr)
				fmt.Println("  [*] 正在进行操作系统级安全包基线检查 (检测向后移植补丁)...")
				hasOSPatch = checkOSPackageBaseline()
				if hasOSPatch {
					fmt.Println(ColorGreen + "  [+] 结论: 检测到操作系统 NGINX 包已包含补丁 (Backport生效)，核心组件安全！" + ColorReset)
				} else {
					fmt.Println(ColorRed + "  [-] 结论: 未检测到操作系统补丁。纵使当前配置安全，未来更改配置仍有随时被执行 RCE 的风险！(强烈建议打补丁)" + ColorReset)
					isBinaryVulnerable = true
				}
			} else {
				fmt.Printf(ColorGreen+"  [+] 发现本地 NGINX 版本 (%s)，不在受影响范围内，核心组件安全。\n"+ColorReset, verStr)
			}
		} else {
			fmt.Println(ColorYellow + "  [-] 当前环境变量中未找到 nginx 命令，无法执行二进制版本探测。" + ColorReset)
		}
	} else {
		fmt.Println(ColorYellow + "  [-] 您指定了单独扫描配置文件，将跳过本地二进制环境检测。" + ColorReset)
	}

	// --- 步骤二：检测本地 NGINX 配置文件 ---
	fmt.Println(ColorCyan + "\n[2/3] 正在审计本地 NGINX 配置文件语义 (排查当前攻击面)..." + ColorReset)
	var pathsToCheck []string
	if customPath != "" {
		pathsToCheck = append(pathsToCheck, customPath)
	} else {
		pathsToCheck = []string{
			"/etc/nginx/nginx.conf",
			"/usr/local/nginx/conf/nginx.conf",
			"/opt/nginx/conf/nginx.conf",
		}
	}

	foundConfig := false
	visited := make(map[string]bool)
	vulnCountTotal := 0

	for _, p := range pathsToCheck {
		if _, err := os.Stat(p); err == nil {
			fmt.Printf("  [*] 找到本地配置文件: %s，开始深度分析...\n", p)
			foundConfig = true
			vulnCountTotal = parseConfigForVulnerability(p, visited)

			if vulnCountTotal > 0 {
				fmt.Printf(ColorRed+"  [!] 警告: 本地配置中共发现 %d 处高度疑似存在漏洞的高危配置模式！\n"+ColorReset, vulnCountTotal)
				if hasOSPatch {
					fmt.Println(ColorGreen + "  [+] 最终判定: 危险配置存在，但操作系统包已包含补丁，系统当前安全 (仍建议修正危险写法)。" + ColorReset)
				} else {
					fmt.Println(ColorRed + "  [-] 最终判定: 危险配置存在，且核心组件未打补丁，系统处于【高危易受攻击】状态！" + ColorReset)
				}
			} else {
				fmt.Println(ColorGreen + "  [+] 配置审计通过: 未在本地配置中发现 NGINX Rift 漏洞触发条件。" + ColorReset)
			}
			break
		}
	}

	if !foundConfig && customPath == "" {
		fmt.Println(ColorYellow + "  [-] 未找到默认的 NGINX 物理配置文件。" + ColorReset)
	}

	// --- 步骤三：探测云原生 K8s Ingress 资源 ---
	k8sVulnCount := 0
	if customPath == "" {
		fmt.Println(ColorCyan + "\n[3/3] 正在探测云原生环境，尝试自动发现 K8s 集群 Ingress 资源 (排查次生灾害)..." + ColorReset)
		k8sVulnCount = checkKubernetesIngress()

		if k8sVulnCount > 0 {
			fmt.Printf(ColorRed+"\n[!] 警告: 共发现 %d 处云原生 K8s Ingress 高危配置！\n"+ColorReset, k8sVulnCount)
			fmt.Println(ColorYellow + "    -> 注: K8s 漏洞触发取决于 NGINX Ingress Controller 的版本，请参考修复建议进行升级。" + ColorReset)
		}
	}

	// --- 综合输出总结与建议 ---
	fmt.Println(ColorCyan + "\n================ 审计结果汇总 ================" + ColorReset)
	if vulnCountTotal == 0 && k8sVulnCount == 0 && !isBinaryVulnerable {
		fmt.Println(ColorGreen + "[+] 综合验证完成: 未在环境中发现漏洞触发条件及脆弱组件，当前系统整体安全。" + ColorReset)
	} else if vulnCountTotal > 0 || k8sVulnCount > 0 || isBinaryVulnerable {
		printRemediation()
	}
}

// 新增：检测本地 NGINX 二进制文件的版本
func checkLocalNginxVersion() (bool, string, bool) {
	// NGINX -v 输出到 stderr
	cmd := exec.Command("nginx", "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, "", false
	}

	outStr := string(output)

	// 首先检查是否为 NGINX Plus
	plusRegex := regexp.MustCompile(`(?i)NGINX\s+Plus\s+(R\d+)`)
	if matches := plusRegex.FindStringSubmatch(outStr); len(matches) > 1 {
		rVer := strings.ToUpper(matches[1])
		return isPlusVersionInVulnerableRange(rVer), "NGINX Plus " + rVer, true
	}

	// 检查普通开源版
	verRegex := regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`)
	if matches := verRegex.FindStringSubmatch(outStr); len(matches) > 1 {
		ver := matches[1]
		return isVersionInVulnerableRange(ver), ver, true
	}

	return false, outStr, true
}

// 递归解析配置文件及 Include 指令
func parseConfigForVulnerability(path string, visited map[string]bool) int {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return 0
	}

	if visited[absPath] {
		return 0
	}
	visited[absPath] = true

	content, err := os.ReadFile(absPath)
	if err != nil {
		fmt.Printf(ColorYellow+"[-] 无法读取文件 (权限不足或文件不存在): %s\n"+ColorReset, absPath)
		return 0
	}

	vulnCount := 0
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	lineNum := 0

	reInclude := regexp.MustCompile(`(?i)^\s*include\s+([^;]+);`)
	isYaml := strings.HasSuffix(strings.ToLower(absPath), ".yaml") || strings.HasSuffix(strings.ToLower(absPath), ".yml")

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		if isYaml {
			if isVulnerableIngressAnnotation(line) {
				fmt.Printf(ColorRed+"      [!] 云原生高危 Ingress 注解触发 %s:%d\n          -> %s\n"+ColorReset, absPath, lineNum, strings.TrimSpace(line))
				vulnCount++
			}
		} else {
			if isVulnerableRewrite(line) {
				fmt.Printf(ColorRed+"      [!] 高危规则触发 %s:%d\n          -> %s\n"+ColorReset, absPath, lineNum, strings.TrimSpace(line))
				vulnCount++
			}

			includeMatch := reInclude.FindStringSubmatch(line)
			if len(includeMatch) > 1 {
				includePattern := includeMatch[1]

				if !filepath.IsAbs(includePattern) {
					includePattern = filepath.Join(filepath.Dir(absPath), includePattern)
				}

				matches, globErr := filepath.Glob(includePattern)
				if globErr == nil {
					for _, match := range matches {
						vulnCount += parseConfigForVulnerability(match, visited)
					}
				}
			}
		}
	}

	return vulnCount
}

// 判断原生配置特征
func isVulnerableRewrite(line string) bool {
	if !strings.Contains(line, "rewrite") || !strings.Contains(line, "?") {
		return false
	}
	re := regexp.MustCompile(`(?i)\s*rewrite\s+([^\s]+)\s+([^\s;]+)`)
	matches := re.FindStringSubmatch(line)

	if len(matches) > 2 {
		replacement := matches[2]
		if strings.Contains(replacement, "?") {
			for i := 1; i <= 9; i++ {
				if strings.Contains(replacement, fmt.Sprintf("$%d", i)) {
					return true
				}
			}
		}
	}
	return false
}

// 判断 K8s YAML 特征
func isVulnerableIngressAnnotation(line string) bool {
	if !strings.Contains(line, "rewrite-target:") && !strings.Contains(line, "configuration-snippet:") {
		return false
	}
	if strings.Contains(line, "?") {
		for i := 1; i <= 9; i++ {
			if strings.Contains(line, fmt.Sprintf("$%d", i)) {
				return true
			}
		}
	}
	return false
}

// ---------------------------
// Kubernetes 探测逻辑
// ---------------------------
func checkKubernetesIngress() int {
	if _, err := exec.LookPath("kubectl"); err != nil {
		fmt.Println(ColorYellow + "  [-] 当前环境未安装 kubectl，无法动态获取 K8s 集群配置 (跳过扫描)。" + ColorReset)
		return 0
	}

	cmd := exec.Command("kubectl", "get", "ingress", "--all-namespaces", "-o", "yaml")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println(ColorYellow + "  [-] 无法获取 K8s Ingress 资源，可能原因: 权限不足或集群不可达。" + ColorReset)
		return 0
	}

	fmt.Println(ColorGreen + "  [+] 成功连接至 Kubernetes 集群，正在对动态提取的 Ingress 规则进行语义分析..." + ColorReset)

	vulnCount := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	currentNamespace := "default"
	currentName := "unknown"
	reNamespace := regexp.MustCompile(`^\s*namespace:\s*([^\s]+)`)
	reName := regexp.MustCompile(`^\s*name:\s*([^\s]+)`)

	for scanner.Scan() {
		line := scanner.Text()
		if matches := reNamespace.FindStringSubmatch(line); len(matches) > 1 {
			currentNamespace = matches[1]
		}
		if matches := reName.FindStringSubmatch(line); len(matches) > 1 {
			currentName = matches[1]
		}
		if isVulnerableIngressAnnotation(line) {
			fmt.Printf(ColorRed+"  [!] 发现高危 Ingress 资源! [Namespace: %s] [Name: %s]\n      -> 触发配置: %s\n"+ColorReset, currentNamespace, currentName, strings.TrimSpace(line))
			vulnCount++
		}
	}

	if vulnCount == 0 {
		fmt.Println(ColorGreen + "  [+] K8s 集群 Ingress 配置审计通过，未发现危险的 rewrite-target 注解。" + ColorReset)
	}
	return vulnCount
}

// ---------------------------
// 操作系统包管理器(Backport)检查
// ---------------------------
func checkOSPackageBaseline() bool {
	if _, err := exec.LookPath("dpkg"); err == nil {
		return checkDebianBaseline()
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		return checkRedHatBaseline()
	}
	fmt.Println(ColorYellow + "  [-] 未知包管理器，请手动确认(或为编译安装)。" + ColorReset)
	return false
}

func checkDebianBaseline() bool {
	cmd := exec.Command("dpkg-query", "-W", "-f=${Version}", "nginx")
	version, err := cmd.Output()
	if err == nil && string(version) != "" {
		fmt.Printf("    -> Debian/Ubuntu NGINX 包版本: %s\n", string(version))
	} else {
		return false
	}
	grepCmd := exec.Command("sh", "-c", "zgrep -i 'CVE-2026-42945' /usr/share/doc/nginx*/changelog.Debian.gz 2>/dev/null")
	output, err := grepCmd.Output()
	if err == nil && len(output) > 0 {
		fmt.Printf("    -> "+ColorGreen+"[发现补丁] Changelog 记录:\n%s"+ColorReset, strings.TrimSpace(string(output))+"\n")
		return true
	}
	return false
}

func checkRedHatBaseline() bool {
	cmd := exec.Command("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\n", "nginx")
	version, err := cmd.Output()
	if err == nil && string(version) != "" {
		fmt.Printf("    -> RHEL/CentOS NGINX 包版本: %s\n", string(version))
	} else {
		return false
	}
	grepCmd := exec.Command("sh", "-c", "rpm -q --changelog nginx | grep -i 'CVE-2026-42945'")
	output, err := grepCmd.Output()
	if err == nil && len(output) > 0 {
		fmt.Printf("    -> "+ColorGreen+"[发现补丁] RPM Changelog 记录:\n%s"+ColorReset, strings.TrimSpace(string(output))+"\n")
		return true
	}
	return false
}

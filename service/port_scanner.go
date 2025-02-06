package service

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

type ScanResult struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	State string `json:"state"`
}

type PortScanner struct {
	timeout time.Duration
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewPortScanner() *PortScanner {
	return &PortScanner{
		timeout: time.Second, // 默认1秒，会被实际扫描时的参数覆盖
	}
}

// 生成随机源端口
func randomPort() uint16 {
	return uint16(rand.Intn(65535-1024) + 1024)
}

func (s *PortScanner) checkPermissions() error {
	if runtime.GOOS != "windows" {
		if os.Geteuid() != 0 {
			return fmt.Errorf("需要 root 权限才能进行 SYN 扫描，请使用 sudo 运行程序")
		}
	}
	return nil
}

// TCP 头部结构
type TCPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Seq      uint32
	Ack      uint32
	Offset   uint8
	Flags    uint8
	Window   uint16
	Checksum uint16
	Urgent   uint16
	Options  []TCPOption
}

type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

func (s *PortScanner) ScanPort(ip string, port int) ScanResult {
	result := ScanResult{
		IP:   ip,
		Port: port,
	}

	// 创建 nmap 扫描器
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets(ip),
		nmap.WithPorts(strconv.Itoa(port)),
		nmap.WithSYNScan(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithHostTimeout(time.Duration(s.timeout)),
	)
	if err != nil {
		result.State = err.Error()
		return result
	}

	// 运行扫描
	run, warnings, err := scanner.Run()
	if err != nil {
		result.State = err.Error()
		return result
	}
	if warnings != nil && len(*warnings) > 0 {
		result.State = strings.Join(*warnings, "; ")
		return result
	}

	// 解析结果
	if len(run.Hosts) == 0 {
		result.State = "closed"
		return result
	}

	for _, host := range run.Hosts {
		for _, p := range host.Ports {
			if int(p.ID) == port {
				result.State = string(p.State.State)
				return result
			}
		}
	}

	result.State = "closed"
	return result
}

// 获取默认网络接口
func getDefaultInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						return &iface, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("no suitable interface found")
}

// 获取本地IP
func getLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.IPv4(127, 0, 0, 1)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// IP校验和计算
func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(data[i]) << 8
		if i+1 < len(data) {
			sum += uint32(data[i+1])
		}
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}

// TCP校验和计算
func tcpChecksum(pseudo []byte, tcp []byte) uint16 {
	var sum uint32

	// 计算伪头部校验和
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(pseudo[i]) << 8
		if i+1 < len(pseudo) {
			sum += uint32(pseudo[i+1])
		}
	}

	// 计算TCP头校验和
	for i := 0; i < len(tcp); i += 2 {
		sum += uint32(tcp[i]) << 8
		if i+1 < len(tcp) {
			sum += uint32(tcp[i+1])
		}
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}

// 添加一个普通的TCP连接扫描方法作为备选
func (s *PortScanner) ScanPortTCP(ip string, port int) ScanResult {
	result := ScanResult{
		IP:   ip,
		Port: port,
	}

	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, s.timeout)

	if err != nil {
		result.State = "closed"
		return result
	}

	defer conn.Close()
	result.State = "open"
	return result
}

func (s *PortScanner) CheckPermission() error {
	return s.checkPermissions()
}

func ParseIPRange(ipRange string) ([]string, error) {
	// 处理单个IP
	if !strings.Contains(ipRange, "-") {
		return []string{ipRange}, nil
	}

	// 处理IP范围
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("IP范围格式错误")
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("无效的IP地址")
	}

	// 转换为uint32以便计算范围
	start := ipToUint32(startIP)
	end := ipToUint32(endIP)

	if end < start {
		return nil, fmt.Errorf("IP范围无效")
	}

	var ips []string
	for i := start; i <= end; i++ {
		ips = append(ips, uint32ToIP(i).String())
	}

	return ips, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func ParsePortRange(portRange string) ([]int, error) {
	var ports []int
	// 分割多个端口/端口范围
	for _, p := range strings.Split(portRange, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// 处理端口范围 (例如: 80-1000)
		if strings.Contains(p, "-") {
			rangeParts := strings.Split(p, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("端口范围格式错误")
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("无效的起始端口")
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("无效的结束端口")
			}

			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("端口范围无效")
			}

			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			// 处理单个端口
			port, err := strconv.Atoi(p)
			if err != nil {
				return nil, fmt.Errorf("无效的端口号")
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("端口号超出范围")
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func (s *PortScanner) ScanPorts(ctx context.Context, ips string, ports string, useSYN bool, threads int, timeoutMs int, resultChan chan<- ScanResult) {
	defer close(resultChan)

	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()

	s.timeout = time.Duration(timeoutMs) * time.Millisecond

	// 解析IP和端口范围
	ipRanges := strings.Split(ips, ",")
	var allIPs []string
	for _, ipRange := range ipRanges {
		ips, err := ParseIPRange(strings.TrimSpace(ipRange))
		if err != nil {
			resultChan <- ScanResult{IP: ipRange, State: err.Error()}
			return
		}
		allIPs = append(allIPs, ips...)
	}

	portList, err := ParsePortRange(ports)
	if err != nil {
		resultChan <- ScanResult{State: err.Error()}
		return
	}

	// 创建工作池
	taskChan := make(chan struct {
		ip   string
		port int
	}, threads)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				var result ScanResult
				if useSYN {
					result = s.ScanPort(task.ip, task.port)
				} else {
					result = s.ScanPortTCP(task.ip, task.port)
				}
				select {
				case resultChan <- result:
				case <-s.ctx.Done():
					return
				}
			}
		}()
	}

	// 分发任务
	go func() {
		defer close(taskChan)
		for _, ip := range allIPs {
			for _, port := range portList {
				select {
				case taskChan <- struct {
					ip   string
					port int
				}{ip, port}:
				case <-s.ctx.Done():
					return
				}
			}
		}
	}()

	wg.Wait()
}

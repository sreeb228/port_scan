package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"port_scan/service" // 替换为你的项目名

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx           context.Context
	scanner       *service.PortScanner
	cancel        context.CancelFunc
	totalTasks    int
	finishedTasks int
	lastProgress  float64
	lastUpdate    time.Time
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{
		scanner: service.NewPortScanner(),
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	runtime.WindowSetTitle(ctx, "端口扫描")
}

// CheckSYNPermission 检查是否有SYN扫描权限
func (a *App) CheckSYNPermission() bool {
	return a.scanner.CheckPermission() == nil
}

// ScanPorts 扫描端口
func (a *App) ScanPorts(ips string, ports string, useSYN bool, threads int, timeoutMs int) string {
	// 如果已有扫描在进行，先取消它
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}

	ctx, cancel := context.WithCancel(a.ctx)
	a.cancel = cancel

	resultChan := make(chan service.ScanResult)

	// 创建完成通道
	scanComplete := make(chan struct{})

	// 重置进度相关变量
	a.totalTasks = 0
	a.finishedTasks = 0
	a.lastProgress = 0
	a.lastUpdate = time.Now()

	// 计算总任务数
	portList, _ := service.ParsePortRange(ports)
	// 计算所有IP和端口组合的总数
	totalIPs := 0
	for _, ipRange := range strings.Split(ips, ",") {
		ips, err := service.ParseIPRange(strings.TrimSpace(ipRange))
		if err != nil {
			continue
		}
		totalIPs += len(ips)
	}
	a.totalTasks = totalIPs * len(portList)

	// 启动扫描
	go func() {
		defer close(scanComplete)
		a.scanner.ScanPorts(ctx, ips, ports, useSYN, threads, timeoutMs, resultChan)
	}()

	// 处理结果
	go func() {
		const minProgressInterval = 100 * time.Millisecond // 最小进度更新间隔
		for result := range resultChan {
			select {
			case <-ctx.Done():
				return
			default:
				jsonData, err := json.Marshal(result)
				if err != nil {
					continue
				}
				runtime.EventsEmit(a.ctx, "scan_result", string(jsonData))

				a.finishedTasks++
				progress := float64(a.finishedTasks) * 100 / float64(a.totalTasks)

				// 只有当进度变化超过1%或距离上次更新超过100ms时才更新
				now := time.Now()
				if progress-a.lastProgress >= 1.0 || now.Sub(a.lastUpdate) >= minProgressInterval {
					runtime.EventsEmit(a.ctx, "scan_progress", progress)
					a.lastProgress = progress
					a.lastUpdate = now
				}
			}
		}
	}()

	// 等待扫描完成或取消
	select {
	case <-ctx.Done():
		return "scan_cancelled"
	case <-scanComplete:
		return "scan_complete"
	}
}

// CancelScan 取消扫描
func (a *App) CancelScan() {
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
		// 发送取消消息到前端
		runtime.EventsEmit(a.ctx, "scan_result", `{"ip":"","port":0,"state":"cancelled"}`)
	}
}

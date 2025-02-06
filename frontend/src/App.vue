<template>
  <div class="container">
    <div class="input-group">
      <label>IP地址：</label>
      <input 
        type="text" 
        v-model="ip" 
        :class="{ 'error': ipError }"
        placeholder="支持范围，例如：192.168.0.1-192.168.0.255,192.168.1.1"
        @input="ipError = false"
      >
    </div>
    
    <div class="input-group">
      <label>端口：</label>
      <input 
        type="text" 
        v-model="port" 
        :class="{ 'error': portError }"
        placeholder="支持范围，例如：80-10000,3306,6379"
        @input="portError = false"
      >
    </div>

    <div class="input-group">
      <label>线程数：</label>
      <input 
        type="number" 
        v-model="threads"
        min="1"
        max="2000"
        placeholder="设置扫描线程数(1-2000)"
      >
    </div>

    <div class="input-group">
      <label>超时(ms)：</label>
      <input 
        type="number" 
        v-model="timeout"
        min="100"
        max="10000"
        placeholder="设置超时时间(100-10000ms)"
      >
    </div>

    <div class="scan-type">
      <label :class="{ 'disabled': !hasSYNPermission }">
        <input 
          type="checkbox" 
          v-model="useSYN"
          :disabled="!hasSYNPermission"
        >
        使用SYN扫描（需要管理员权限）
      </label>
      <div class="syn-tip" v-if="!hasSYNPermission">
        SYN扫描需要管理员权限，请使用管理员权限运行程序
      </div>
    </div>

    <div class="button-group">
      <button 
        class="scan-btn" 
        @click="startScan" 
        :disabled="scanning"
      >
        {{ scanning ? '扫描中...' : '开始扫描' }}
      </button>

      <button 
        v-if="scanning"
        class="cancel-btn" 
        @click="cancelScan"
      >
        取消扫描
      </button>
    </div>

    <div v-if="scanning" class="progress-container">
      <div class="progress-bar" :style="{ width: progress + '%' }">
        <span class="progress-text">{{ progress.toFixed(1) }}%</span>
      </div>
    </div>

    <div class="results" v-if="allResults.length > 0">
      <div class="results-header">
        <div class="results-info">
          <h3>扫描结果：</h3>
          <span class="scan-time" v-if="scanDuration">
            耗时: {{ scanDuration }}秒
          </span>
        </div>
        <div class="results-actions">
          <label class="filter-option">
            <input 
              type="checkbox" 
              v-model="showOnlyOpen"
            >
            只显示开放端口
          </label>
          <button 
            class="clear-btn" 
            @click="clearResults"
          >
            清空结果
          </button>
        </div>
      </div>
      <textarea 
        class="results-text" 
        readonly 
        :value="formattedResults"
      ></textarea>
    </div>
  </div>
</template>


<script setup>
import {ref, computed, onMounted, onUnmounted, watch} from 'vue'

const ip = ref('127.0.0.1')
const port = ref('1-65535')
const threads = ref(200) // 默认200线程
const timeout = ref(500) // 默认1000ms超时
const ipError = ref(false)
const portError = ref(false)
const allResults = ref("")      // 存储所有扫描结果
const openResults = ref("")     // 只存储开放端口结果
const hasSYNPermission = ref(false)
const useSYN = ref(false)
const scanning = ref(false)
const showOnlyOpen = ref(false)
const scanDuration = ref(null)
const formattedResults = ref(null)
const progress = ref(0)
let startTime = null
let timerId = null
// 监听扫描结果
const setupScanListener = () => {
  window.runtime.EventsOn("scan_result", (resultJson) => {
    const result = JSON.parse(resultJson)
    if (result.state === "cancelled") {
      scanning.value = false
      return
    }
    
    allResults.value += `${result.ip}:${result.port} - ${result.state}\n`
    if (result.state === 'open') {
      openResults.value += `${result.ip}:${result.port} - ${result.state}\n`
    }
  })

  window.runtime.EventsOn("scan_progress", (value) => {
    progress.value = value
  })
}

// 清理监听器
const cleanupListener = () => {
  window.runtime.EventsOff("scan_result")
  window.runtime.EventsOff("scan_progress")
}

// 检查SYN扫描权限
const checkSYNPermission = async () => {
  try {
    hasSYNPermission.value = await window.go.main.App.CheckSYNPermission()
  } catch (error) {
    console.error('权限检查失败:', error)
    hasSYNPermission.value = false
  }
}

// 组件挂载时设置监听器并检查权限
onMounted(() => {
  setupScanListener()
  checkSYNPermission()
})

// 组件卸载时清理监听器
onUnmounted(() => {
  cleanupListener()
})

const startScan = async () => {
  if (ip.value === '') {
    ipError.value = true
  }
  if (port.value === '') {
    portError.value = true
  }
  if (ip.value === '' || port.value === '') {
    return
  }

  const threadCount = parseInt(threads.value)
  if (isNaN(threadCount) || threadCount < 1 || threadCount > 2000) {
    alert('请设置正确的线程数(1-2000)')
    return
  }

  const timeoutMs = parseInt(timeout.value)
  if (isNaN(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) {
    alert('请设置正确的超时时间(100-10000ms)')
    return
  }

  scanning.value = true
  progress.value = 0
  allResults.value = []
  openResults.value = []
  startTime = Date.now()
  scanDuration.value = null
  
  try {
    await window.go.main.App.ScanPorts(
      ip.value, 
      port.value, 
      useSYN.value, 
      threadCount,
      timeoutMs
    )
  } catch (error) {
    console.error('扫描出错:', error)
  } finally {
    scanning.value = false
    // 计算扫描时间
    const endTime = Date.now()
    scanDuration.value = ((endTime - startTime) / 1000).toFixed(2)
  }
}

const cancelScan = async () => {
  try {
    await window.go.main.App.CancelScan()
    scanning.value = false
    // 计算取消时的扫描时间
    if (startTime) {
      const endTime = Date.now()
      scanDuration.value = ((endTime - startTime) / 1000).toFixed(2)
    }
  } catch (error) {
    console.error('取消扫描失败:', error)
  }
}


watch(showOnlyOpen, () => {
  formattedResults.value =  showOnlyOpen.value ? openResults.value : allResults.value;
});


watch(allResults, () => {
  if (timerId) {
    return;
  }else{
    formattedResults.value =  showOnlyOpen.value ? openResults.value : allResults.value;
  }
  timerId = setTimeout(() => {
    formattedResults.value =  showOnlyOpen.value ? openResults.value : allResults.value;
  }, 300); // 延迟更新
});

const clearResults = () => {
  allResults.value = ''
  openResults.value = ''
  scanDuration.value = null
  progress.value = 0
}
</script>
<style>
.container {
  padding: 20px;
  max-width: 480px;
  margin: 0 auto;
}

.input-group {
  margin-bottom: 15px;
  display: flex;
  align-items: center;
}

.input-group label {
  min-width: 70px;
  color: #333;
  margin-right: 10px;
}

.input-group input {
  flex: 1;
  padding: 8px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
}

.input-group input:focus {
  outline: none;
  border-color: #4a9eff;
}

.scan-btn {
  width: 100%;
  padding: 10px;
  background-color: #4a9eff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
}

.scan-btn:hover {
  background-color: #3d8be6;
}

.scan-btn:active {
  background-color: #3278d1;
}

.input-group input.error {
  border-color: #ff4444;
  background-color: #fff0f0;
}

.input-group input.error:focus {
  border-color: #ff4444;
  outline: none;
  box-shadow: 0 0 0 2px rgba(255, 68, 68, 0.1);
}

.results {
  margin-top: 20px;
}

.results-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}

.results-header h3 {
  margin: 0;
}

.results-actions {
  display: flex;
  align-items: center;
  gap: 15px;
}

.filter-option {
  display: flex;
  align-items: center;
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
}

.filter-option input[type="checkbox"] {
  margin-right: 8px;
}

input[type="number"] {
  -moz-appearance: textfield;
}

input[type="number"]::-webkit-outer-spin-button,
input[type="number"]::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}

.button-group {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
}

.scan-btn {
  flex: 2;
}

.cancel-btn {
  flex: 1;
  padding: 10px;
  background-color: #ff4444;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
}

.cancel-btn:hover {
  background-color: #ff3333;
}

.cancel-btn:active {
  background-color: #e60000;
}

.clear-btn {
  padding: 5px 10px;
  background-color: #ff4444;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 12px;
  transition: background-color 0.2s;
}

.clear-btn:hover {
  background-color: #ff3333;
}

.clear-btn:active {
  background-color: #e60000;
}

.results-info {
  display: flex;
  align-items: center;
  gap: 10px;
}

.scan-time {
  font-size: 14px;
  color: #666;
  white-space: nowrap;
}

.results-text {
  width: 100%;
  min-height: 200px;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-family: monospace;
  font-size: 14px;
  line-height: 1.5;
  background-color: #f8f8f8;
  resize: vertical;
  white-space: pre;
  overflow-y: auto;
}

.results-text:focus {
  outline: none;
  border-color: #4a9eff;
}

/* 移除表格相关样式 */
table, th, td, td.open, td.closed {
  display: none;
}

.scan-type label.disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.scan-type label.disabled input[type="checkbox"] {
  cursor: not-allowed;
}

.syn-tip {
  margin-top: 5px;
  color: #ff4444;
  font-size: 12px;
}

.progress-container {
  margin: 10px 0;
  height: 10px;
  background-color: #f0f0f0;
  border-radius: 4px;
  overflow: hidden;
  position: relative;
}

.progress-bar {
  height: 100%;
  background-color: #4a9eff;
  transition: width 0.3s ease;
  display: flex;
  align-items: center;
  justify-content: center;
}

.progress-text {
  color: white;
  font-size: 12px;
  text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
  position: absolute;
  width: 100%;
  text-align: center;
}
</style>

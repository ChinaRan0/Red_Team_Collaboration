<template>
  <div class="domain-map-container">
    <div class="light-bg-grid"></div>

    <div class="map-header">
      <div class="header-left">
        <el-button class="light-btn" icon="ArrowLeft" @click="goBack">返回</el-button>
        <div class="title-box">
          <h2>域名透视</h2>
          <span class="subtitle">DOMAIN RELATIONSHIP TOPOLOGY</span>
        </div>
      </div>
      <div class="header-right">
        <el-select 
          v-model="selectedDomain" 
          placeholder="请选择目标域名" 
          style="width: 320px;" 
          class="light-select"
          popper-class="light-select-dropdown"
          @change="handleDomainChange">
          <el-option
            v-for="item in domainList"
            :key="item.domain"
            :label="item.domain"
            :value="item.domain"
          >
            <span class="option-label">{{ item.domain }}</span>
            <span class="option-desc">
              {{ item.subdomain_count }} 子域 | {{ item.ip_count }} IP
            </span>
          </el-option>
        </el-select>
        <el-button class="light-btn" icon="Refresh" @click="loadDomainMap">刷新</el-button>
      </div>
    </div>

    <div class="map-content" v-loading="loading" element-loading-background="rgba(255, 255, 255, 0.8)">
      <div v-if="!selectedDomain && domainList && domainList.length > 0" class="domain-overview">
        <div class="section-title">
          <h3>项目资产概览</h3>
          <div class="decoration-line"></div>
        </div>
        <el-row :gutter="24">
          <el-col :span="8" v-for="domain in domainList" :key="domain.domain">
            <div class="clean-card" @click="selectDomain(domain.domain)">
              <div class="card-top-bar"></div>
              <div class="domain-card-header">
                <h4>{{ domain.domain }}</h4>
                <el-tag effect="plain" round size="small">{{ domain.asset_count }} 资产</el-tag>
              </div>
              <div class="domain-stats">
                <div class="stat-item">
                  <span class="stat-value">{{ domain.subdomain_count }}</span>
                  <span class="stat-label">子域名</span>
                </div>
                <div class="stat-divider"></div>
                <div class="stat-item">
                  <span class="stat-value">{{ domain.ip_count }}</span>
                  <span class="stat-label">IP 地址</span>
                </div>
              </div>
              <div class="card-footer">
                <span>View Graph</span>
                <el-icon><ArrowRight /></el-icon>
              </div>
            </div>
          </el-col>
        </el-row>
      </div>

      <div v-else-if="selectedDomain" class="graph-container">
        <div ref="chartRef" class="chart"></div>
        
        <div class="float-panel legend-panel">
          <h4>图例 / LEGEND</h4>
          <div class="legend-grid">
            <div class="legend-item">
              <span class="legend-dot" style="background: #2b5afb;"></span>
              <span>主域名 Root</span>
            </div>
            <div class="legend-item">
              <span class="legend-dot" style="background: #00b894;"></span>
              <span>子域名 Sub</span>
            </div>
            <div class="legend-item">
              <span class="legend-dot" style="background: #fdcb6e;"></span>
              <span>IP 地址</span>
            </div>
            <div class="legend-item">
              <span class="legend-dot" style="background: #ff7675;"></span>
              <span>高危 Risk</span>
            </div>
          </div>
        </div>

        <transition name="slide-fade">
          <div class="float-panel info-panel" v-if="selectedNode">
            <div class="panel-header">
              <h4>节点详情</h4>
              <el-tag size="small" effect="dark" :color="getNodeColor(selectedNode.category)" style="border:none">
                  {{ getCategoryName(selectedNode.category) }}
              </el-tag>
            </div>
            
            <div class="info-content">
              <div class="node-name-row">
                  <span>{{ selectedNode.name }}</span>
              </div>

              <div class="info-meta" v-if="selectedNode.assets">
                <span>关联资产: <strong>{{ selectedNode.assets.length }}</strong></span>
              </div>
              
              <div v-if="selectedNode.assets && selectedNode.assets.length > 0" class="assets-list">
                <div class="list-title">资产列表</div>
                <div v-for="asset in selectedNode.assets" :key="asset.id" class="asset-item">
                  <div class="asset-main">
                    <el-tag size="small" effect="light" :type="getAssetTypeColor(asset.type)">{{ asset.type }}</el-tag>
                    <span class="asset-val" :title="asset.value">{{ asset.value }}</span>
                  </div>
                  <div class="asset-badges">
                    <el-tag v-if="asset.status" size="small" type="info" effect="plain">{{ asset.status }}</el-tag>
                    <el-tag v-if="asset.risk_level" size="small" type="danger" effect="dark">{{ asset.risk_level }}</el-tag>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </transition>
      </div>

      <el-empty v-else description="暂无域名数据" />
    </div>
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import request from '../utils/request'
import * as echarts from 'echarts'

export default {
  name: 'DomainMap',
  setup() {
    const router = useRouter()
    const route = useRoute()
    const loading = ref(false)
    const domainList = ref([])
    const selectedDomain = ref('')
    const selectedNode = ref(null)
    const chartRef = ref(null)
    let chartInstance = null

    const projectId = route.params.id

    // --- 核心数据逻辑保持 100% 不变 ---
    const loadDomainMap = async () => {
      loading.value = true
      try {
        const response = await request.get(`/projects/${projectId}/domain-map`)
        domainList.value = response.domain_map || []
      } catch (error) {
        console.error('Load domain map error:', error)
      } finally {
        loading.value = false
      }
    }

    const selectDomain = (domain) => {
      selectedDomain.value = domain
      nextTick(() => {
        renderGraph()
      })
    }

    const handleDomainChange = () => {
      selectedNode.value = null
      renderGraph()
    }

    const isIPAddress = (str) => {
      if (!str) return false
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
      const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
      return ipv4Regex.test(str) || ipv6Regex.test(str)
    }

    // 辅助函数：获取颜色
    const getNodeColor = (catIndex) => {
        const colors = ['#2b5afb', '#00b894', '#fdcb6e']; // 蓝、绿、黄
        return colors[catIndex] || '#b2bec3';
    }
    
    const getCategoryName = (catIndex) => {
        const names = ['主域名', '子域名', 'IP地址'];
        return names[catIndex] || '未知';
    }

    const renderGraph = () => {
      if (!chartRef.value) return

      const domainData = domainList.value.find(d => d.domain === selectedDomain.value)
      if (!domainData) return

      if (!domainData.subdomains) domainData.subdomains = []
      if (!domainData.ips) domainData.ips = []
      if (!domainData.assets) domainData.assets = []

      if (!chartInstance) {
        chartInstance = echarts.init(chartRef.value)
      }

      try {
        const nodes = []
        const links = []
        const categories = [
          { name: '主域名' },
          { name: '子域名' },
          { name: 'IP地址' }
        ]

        const nodeSet = new Set()
        
        // --- 样式定义：白色清爽系 ---
        const COLOR_MAIN = '#2b5afb' // 深蓝
        const COLOR_SUB = '#00b894'  // 湖绿
        const COLOR_IP = '#fdcb6e'   // 暖黄
        const COLOR_RISK = '#ff7675' // 柔红

        // 主域名
        const mainDomain = String(domainData.domain)
        nodeSet.add(mainDomain)
        nodes.push({
          id: mainDomain,
          name: mainDomain,
          category: 0,
          symbolSize: 75,
          itemStyle: { 
            color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                { offset: 0, color: '#4a7dff' },
                { offset: 1, color: '#2b5afb' }
            ]),
            shadowBlur: 10,
            shadowColor: 'rgba(43, 90, 251, 0.3)'
          },
          label: {
             show: true,
             fontSize: 14,
             fontWeight: 600,
             color: '#fff' // 深色球体用白色字
          }
        })

        // 子域名
        const subdomains = (domainData.subdomains || []).filter(s => s && !isIPAddress(s))
        for (const subdomain of subdomains) {
          const id = String(subdomain)
          if (nodeSet.has(id)) continue
          
          nodeSet.add(id)
          const assets = (domainData.assets || []).filter(a => 
            a && a.value && a.value.includes(subdomain)
          )
          const hasRisk = assets.some(a => a.risk_level === '高危' || a.risk_level === '重点打点')
          
          nodes.push({
            id: id,
            name: id,
            category: 1,
            symbolSize: 35,
            itemStyle: { 
                color: hasRisk ? COLOR_RISK : COLOR_SUB,
                shadowBlur: 5,
                shadowColor: 'rgba(0,0,0,0.1)'
            },
            label: { 
                color: '#2d3436', // 浅色球体旁边用深色字
                fontWeight: 500
            }, 
            assets: assets
          })
          links.push({ source: mainDomain, target: id })
        }

        // IP
        const ips = (domainData.ips || []).filter(ip => ip && isIPAddress(ip))
        for (const ip of ips) {
          const id = String(ip)
          if (nodeSet.has(id)) continue
          
          nodeSet.add(id)
          const assets = (domainData.assets || []).filter(a => a && a.ip === ip)
          
          nodes.push({
            id: id,
            name: id,
            category: 2,
            symbolSize: 25,
            itemStyle: { color: COLOR_IP, opacity: 0.9 },
            label: { color: '#636e72' },
            assets: assets
          })

          // 连线逻辑
          const connectedTo = new Set()
          for (const asset of assets) {
            let targetId = mainDomain
            if (asset.type === 'domain') {
              const domain = asset.value.split(':')[0]
              if (nodeSet.has(domain)) targetId = domain
            } else if (asset.type === 'http' || asset.type === 'https') {
              const match = asset.value.match(/https?:\/\/([^:/]+)/)
              if (match && nodeSet.has(match[1])) targetId = match[1]
            }
            const linkKey = `${targetId}-${id}`
            if (!connectedTo.has(linkKey)) {
              connectedTo.add(linkKey)
              links.push({ source: targetId, target: id })
            }
          }
        }

        if (nodes.length === 0) return

        // --- ECharts 配置：白色简约风 ---
        const option = {
          backgroundColor: 'transparent',
          title: {
            text: `${domainData.domain}`,
            subtext: `Subdomains: ${domainData.subdomain_count} | IPs: ${domainData.ip_count}`,
            left: 'center',
            top: 20,
            textStyle: { color: '#2d3436', fontSize: 20, fontWeight: 600 },
            subtextStyle: { color: '#636e72' }
          },
          tooltip: {
            backgroundColor: 'rgba(255, 255, 255, 0.95)',
            borderColor: '#dfe6e9',
            textStyle: { color: '#2d3436' },
            extraCssText: 'box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);',
            formatter: (params) => {
              if (params.dataType === 'node') {
                const node = params.data
                return `
                  <div style="font-weight:600; color:#2d3436; margin-bottom:4px;">${node.name}</div>
                  <div style="font-size:12px; color:#636e72">类型: ${categories[node.category].name}</div>
                  ${node.assets && node.assets.length ? `<div style="font-size:12px; color:#636e72">资产: ${node.assets.length} 个</div>` : ''}
                `
              }
              return ''
            }
          },
          series: [{
            type: 'graph',
            layout: 'force',
            data: nodes,
            links: links,
            categories: categories,
            roam: true,
            draggable: true,
            label: {
              show: true,
              position: 'right',
              formatter: '{b}',
              fontSize: 12
            },
            labelLayout: { hideOverlap: true },
            scaleLimit: { min: 0.4, max: 3 },
            lineStyle: {
              color: '#b2bec3', // 浅灰色连线
              width: 1.5,
              curveness: 0.1,
              opacity: 0.6
            },
            emphasis: {
              focus: 'adjacency',
              lineStyle: { width: 2, color: '#2d3436' }
            },
            force: {
              repulsion: 800,
              edgeLength: [60, 250],
              gravity: 0.08,
              friction: 0.6
            }
          }]
        }

        chartInstance.clear()
        chartInstance.setOption(option, true)

        chartInstance.off('click')
        chartInstance.on('click', (params) => {
          if (params.dataType === 'node') selectedNode.value = params.data
        })
      } catch (error) {
        console.error('Render error:', error)
        ElMessage.error('渲染失败: ' + error.message)
      }
    }

    const getAssetTypeColor = (type) => {
      const colorMap = {
        'domain': 'primary', 'http': 'success', 'https': 'danger', 'ip': 'info', 'ip_port': 'warning'
      }
      return colorMap[type] || 'info'
    }

    const goBack = () => {
      router.push(`/project/${projectId}`)
    }

    onMounted(() => {
      loadDomainMap()
      window.addEventListener('resize', () => {
        if (chartInstance) chartInstance.resize()
      })
    })

    onUnmounted(() => {
      if (chartInstance) chartInstance.dispose()
    })

    return {
      loading, domainList, selectedDomain, selectedNode, chartRef,
      loadDomainMap, selectDomain, handleDomainChange, getAssetTypeColor, goBack,
      getNodeColor, getCategoryName
    }
  }
}
</script>

<style lang="scss" scoped>
/* 浅色系变量定义 */
$bg-color: #f5f7fa;
$header-bg: rgba(255, 255, 255, 0.95);
$text-main: #2c3e50;
$text-sec: #606266;
$accent-color: #2b5afb; /* 科技蓝 */
$card-bg: #ffffff;
$shadow-soft: 0 8px 24px rgba(149, 157, 165, 0.1);
$border-light: #ebeef5;

.domain-map-container {
  width: 100%;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background-color: $bg-color;
  color: $text-main;
  position: relative;
  overflow: hidden;

  /* 极简网格背景 */
  .light-bg-grid {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-image: 
      radial-gradient(#dce1e6 1.5px, transparent 1.5px);
    background-size: 30px 30px;
    opacity: 0.6;
    z-index: 0;
    pointer-events: none;
  }

  .map-header {
    height: 64px;
    background: $header-bg;
    backdrop-filter: blur(12px);
    border-bottom: 1px solid $border-light;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 32px;
    z-index: 10;
    box-shadow: 0 1px 4px rgba(0,0,0,0.03);

    .header-left {
      display: flex;
      align-items: center;
      gap: 24px;

      .title-box {
        display: flex;
        flex-direction: column;
        
        h2 {
          margin: 0;
          font-size: 18px;
          font-weight: 700;
          color: $text-main;
          letter-spacing: -0.5px;
        }
        .subtitle {
          font-size: 10px;
          color: #909399;
          letter-spacing: 1px;
          margin-top: 2px;
          font-weight: 500;
        }
      }
    }

    .header-right {
      display: flex;
      gap: 16px;
    }
  }

  .map-content {
    flex: 1;
    padding: 24px;
    overflow: auto;
    position: relative;
    z-index: 1;

    .domain-overview {
      max-width: 1400px;
      margin: 0 auto;
      padding: 20px 0;
      
      .section-title {
        margin-bottom: 32px;
        display: flex;
        align-items: center;
        gap: 16px;
        
        h3 {
          margin: 0;
          font-weight: 600;
          font-size: 18px;
          color: $text-main;
        }
        .decoration-line {
          flex: 1;
          height: 1px;
          background: #e4e7ed;
        }
      }

      .clean-card {
        background: $card-bg;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
        cursor: pointer;
        position: relative;
        transition: all 0.3s ease;
        border: 1px solid #f0f2f5;
        overflow: hidden;
        box-shadow: $shadow-soft;

        .card-top-bar {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          height: 4px;
          background: #eef1f6;
          transition: background 0.3s;
        }

        &:hover {
          transform: translateY(-6px);
          box-shadow: 0 16px 40px rgba(149, 157, 165, 0.15);
          
          .card-top-bar {
            background: $accent-color;
          }
          .card-footer {
            color: $accent-color;
            transform: translateX(4px);
          }
        }

        .domain-card-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 24px;
          
          h4 {
            margin: 0;
            color: $text-main;
            font-size: 18px;
            font-weight: 600;
          }
        }

        .domain-stats {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
          padding: 0 10px;

          .stat-divider {
            width: 1px;
            height: 32px;
            background: #f2f6fc;
          }

          .stat-item {
            text-align: center;
            .stat-value {
              display: block;
              font-size: 28px;
              font-weight: 700;
              color: $text-main;
              line-height: 1.2;
            }
            .stat-label {
              font-size: 12px;
              color: #909399;
            }
          }
        }

        .card-footer {
          border-top: 1px solid #f5f7fa;
          padding-top: 16px;
          display: flex;
          justify-content: flex-end;
          align-items: center;
          gap: 8px;
          font-size: 13px;
          color: #909399;
          font-weight: 500;
          transition: all 0.3s;
        }
      }
    }

    .graph-container {
      width: 100%;
      height: 100%;
      position: relative;

      .chart {
        width: 100%;
        height: 100%;
      }

      .float-panel {
        position: absolute;
        background: rgba(255, 255, 255, 0.9);
        backdrop-filter: blur(16px);
        border: 1px solid #fff;
        border-radius: 12px;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.08);
        padding: 20px;
      }

      .legend-panel {
        top: 24px;
        right: 24px;
        min-width: 160px;

        h4 {
          margin: 0 0 16px 0;
          font-size: 12px;
          color: #909399;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .legend-item {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 12px;
          font-size: 13px;
          color: $text-main;
          font-weight: 500;

          .legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            box-shadow: 0 2px 6px rgba(0,0,0,0.1);
          }
        }
      }

      .info-panel {
        bottom: 24px;
        right: 24px;
        width: 360px;
        max-height: 600px;
        display: flex;
        flex-direction: column;

        .panel-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
          
          h4 { margin: 0; font-size: 14px; color: #909399; }
        }

        .info-content {
          overflow-y: auto;
          /* 隐藏滚动条但保留功能 */
          &::-webkit-scrollbar { width: 4px; }
          &::-webkit-scrollbar-thumb { background: #e4e7ed; border-radius: 2px; }

          .node-name-row {
            font-size: 18px;
            font-weight: 700;
            color: $text-main;
            margin-bottom: 8px;
            word-break: break-all;
            line-height: 1.4;
          }

          .info-meta {
            color: $text-sec;
            font-size: 13px;
            margin-bottom: 20px;
          }

          .assets-list {
            background: #f9fafc;
            border-radius: 8px;
            padding: 12px;

            .list-title {
              font-size: 12px;
              color: #909399;
              margin-bottom: 12px;
              font-weight: 600;
            }

            .asset-item {
              background: #fff;
              border: 1px solid #ebeef5;
              border-radius: 6px;
              padding: 10px;
              margin-bottom: 8px;
              box-shadow: 0 2px 4px rgba(0,0,0,0.02);

              .asset-main {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 6px;
                
                .asset-val {
                  font-family: 'Consolas', monospace;
                  font-size: 13px;
                  color: $text-main;
                  overflow: hidden;
                  text-overflow: ellipsis;
                  white-space: nowrap;
                }
              }
              
              .asset-badges {
                display: flex;
                gap: 6px;
              }
            }
          }
        }
      }
    }
  }
}

/* Element Plus 样式覆盖 (简约白风格) */
::v-deep(.light-btn) {
  background: #fff;
  border: 1px solid #dcdfe6;
  color: $text-sec;
  border-radius: 6px;
  transition: all 0.2s;
  
  &:hover {
    color: $accent-color;
    border-color: lighten($accent-color, 30%);
    background-color: lighten($accent-color, 45%);
  }
}

::v-deep(.light-select) {
  .el-input__wrapper {
    background: #f5f7fa;
    box-shadow: none !important;
    border: 1px solid transparent;
    border-radius: 6px;
    
    &:hover, &.is-focus {
      background: #fff;
      border-color: #dcdfe6;
      box-shadow: 0 0 0 1px #dcdfe6 !important;
    }
  }
}

/* 动画 */
.slide-fade-enter-active,
.slide-fade-leave-active {
  transition: all 0.3s cubic-bezier(0.165, 0.84, 0.44, 1);
}
.slide-fade-enter-from,
.slide-fade-leave-to {
  opacity: 0;
  transform: translateY(10px);
}
</style>

<style>
/* 全局下拉框样式 */
.light-select-dropdown {
  border-radius: 8px !important;
  box-shadow: 0 10px 30px rgba(0,0,0,0.08) !important;
  border: 1px solid #ebeef5 !important;
}
.light-select-dropdown .option-label {
  font-weight: 500;
  color: #2c3e50;
}
.light-select-dropdown .option-desc {
  color: #909399;
  font-size: 12px;
  margin-left: 12px;
}
</style>
<script setup>
import { ref, reactive, onMounted, onUnmounted, inject, computed, watch } from "vue";
import { Bar, Line } from 'vue-chartjs';
import {
  Chart as ChartJS,
  Title,
  Tooltip,
  Legend,
  BarElement,
  LineElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Filler
} from 'chart.js';

ChartJS.register(
  Title,
  Tooltip,
  Legend,
  BarElement,
  LineElement,
  CategoryScale,
  LinearScale,
  PointElement,
  Filler
);

const $api = inject("$api");

const isLoading = ref(false);
const showSubText = ref(false);
const selectedAgentHost = ref(null);

// Dashboard Summary Data
const dashboardData = reactive({
  kpi: {
    total_operations: 0,
    total_agents: 0,
    total_attack_steps: 0,
    total_detections: 0,
    coverage: 0,
    last_seen: null
  },
  operations: [],
  detection_events: [],
  query_time: null
});

// Filter State
const filters = reactive({
  hours: 72,
  min_level: 5,
  operation_id: 'all',
  os_filter: 'all',
  env_filter: 'all',
  search: ''
});

// All Operations (unfiltered) for dropdown
const allOperations = ref([]);

// Agents Data
const agentQueryHours = ref(24);
const agentsData = reactive({
  total_agents: 0,
  agents: [],
  query_time: null
});

// Correlation
const correlationOperationId = ref('');
const correlationResult = ref(null);
const isCorrelating = ref(false);

// Week 11: MITRE Heat Map Data
const heatMapData = reactive({
  techniques: [],
  tactics: [],
  summary: {
    total_techniques: 0,
    total_simulated: 0,
    total_detected: 0,
    overall_detection_rate: 0
  }
});

// Watch filters and reload data when changed
watch(() => filters.operation_id, async (newValue, oldValue) => {
  if (newValue !== oldValue) {
    await fetchDashboardSummary();
    await fetchAgents();
    await fetchHeatMapData();
  }
});

watch(() => filters.os_filter, async (newValue, oldValue) => {
  if (newValue !== oldValue) {
    await fetchDashboardSummary();
    await fetchAgents();
  }
});

watch(() => filters.search, async (newValue, oldValue) => {
  if (newValue !== oldValue) {
    await fetchDashboardSummary();
    await fetchAgents();
  }
});

let refreshInterval;

onMounted(async () => {
  await fetchAgents();
  await fetchDashboardSummary();
  await fetchHeatMapData();

  refreshInterval = setInterval(async () => {
    await fetchAgents();
    await fetchDashboardSummary();
    await fetchHeatMapData();
  }, 30000);
});

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval);
  }
});

const fetchDashboardSummary = async () => {
  try {
    let url = `/plugin/bastion/dashboard?hours=${filters.hours}&min_level=${filters.min_level}`;

    if (filters.operation_id && filters.operation_id !== 'all') {
      url += `&operation_id=${filters.operation_id}`;
    }

    if (filters.os_filter && filters.os_filter !== 'all') {
      url += `&os_filter=${filters.os_filter}`;
    }

    if (filters.search) {
      url += `&search=${encodeURIComponent(filters.search)}`;
    }

    const response = await $api.get(url);
    Object.assign(dashboardData, response.data);

    // Store all operations for dropdown (only when no operation filter applied)
    if (filters.operation_id === 'all' && response.data.operations) {
      allOperations.value = response.data.operations;
    }
  } catch (error) {
    console.error('Failed to fetch dashboard summary:', error);
  }
};

const fetchAgents = async () => {
  try {
    let url = `/plugin/bastion/agents?hours=${agentQueryHours.value}`;

    if (filters.operation_id && filters.operation_id !== 'all') {
      url += `&operation_id=${filters.operation_id}`;
    }

    if (filters.os_filter && filters.os_filter !== 'all') {
      url += `&os_filter=${filters.os_filter}`;
    }

    if (filters.search) {
      url += `&search=${encodeURIComponent(filters.search)}`;
    }

    const response = await $api.get(url);
    Object.assign(agentsData, response.data);
  } catch (error) {
    console.error('Failed to fetch agents:', error);
  }
};

// Week 11: Fetch MITRE Heat Map Data
const fetchHeatMapData = async () => {
  try {
    const response = await $api.get(`/plugin/bastion/dashboard/techniques?hours=${filters.hours}`);
    Object.assign(heatMapData, response.data);
  } catch (error) {
    console.error('Failed to fetch heat map data:', error);
  }
};

const refreshData = async () => {
  isLoading.value = true;
  try {
    await Promise.all([fetchAgents(), fetchDashboardSummary()]);
    window.toast('데이터를 성공적으로 새로고침했습니다', true);
  } catch (error) {
    window.toast('데이터 새로고침 실패', false);
  } finally {
    isLoading.value = false;
  }
};

const correlateOperation = async () => {
  if (!correlationOperationId.value) return;

  isCorrelating.value = true;
  try {
    const response = await $api.post('/plugin/bastion/correlate', {
      operation_id: correlationOperationId.value
    });
    correlationResult.value = response.data;
    window.toast('상관관계 분석 완료', true);
  } catch (error) {
    window.toast('상관관계 분석 실패', false);
    console.error('Correlation failed:', error);
  } finally {
    isCorrelating.value = false;
  }
};

const selectAgent = (agentHost) => {
  if (selectedAgentHost.value === agentHost) {
    selectedAgentHost.value = null;
  } else {
    selectedAgentHost.value = agentHost;
  }
};

const clearAgentFilter = () => {
  selectedAgentHost.value = null;
};

// Computed Properties
const filteredDetections = computed(() => {
  let detections = dashboardData.detection_events;

  if (selectedAgentHost.value) {
    detections = detections.filter(d => d.agent_name === selectedAgentHost.value);
  }

  // Apply OS filter (detection의 agent_os 직접 사용)
  if (filters.os_filter !== 'all') {
    detections = detections.filter(d => {
      if (!d.agent_os) return false;

      const platform = d.agent_os.toLowerCase();
      const filter = filters.os_filter.toLowerCase();
      return platform === filter || platform.includes(filter);
    });
  }

  if (filters.search) {
    const search = filters.search.toLowerCase();
    detections = detections.filter(d =>
      d.description?.toLowerCase().includes(search) ||
      d.agent_name?.toLowerCase().includes(search) ||
      d.technique_id?.toLowerCase().includes(search)
    );
  }

  return detections;
});

const sortedAgents = computed(() => {
  let agents = [...agentsData.agents];

  // Apply OS filter
  if (filters.os_filter !== 'all') {
    agents = agents.filter(agent => {
      const platform = agent.platform.toLowerCase();
      const filter = filters.os_filter.toLowerCase();
      return platform === filter || platform.includes(filter);
    });
  }

  // Sort by alive status and host name
  return agents.sort((a, b) => {
    if (a.alive !== b.alive) {
      return b.alive ? 1 : -1;
    }
    return a.host.localeCompare(b.host);
  });
});

const filteredOperations = computed(() => {
  if (filters.operation_id === 'all') {
    return dashboardData.operations;
  }
  return dashboardData.operations.filter(op => op.id === filters.operation_id);
});

// Week 11: Security Score Color (Cymulate-style)
const securityScoreColor = computed(() => {
  const score = filteredKPI.value.security_score || 0;
  if (score >= 90) return 'has-text-success';  // Green
  if (score >= 80) return 'has-text-success-light';  // Light Green
  if (score >= 70) return 'has-text-warning';  // Yellow
  if (score >= 60) return 'has-text-warning-dark';  // Orange
  return 'has-text-danger';  // Red
});

const securityScoreProgressClass = computed(() => {
  const score = filteredKPI.value.security_score || 0;
  if (score >= 90) return 'is-success';
  if (score >= 80) return 'is-success';
  if (score >= 70) return 'is-warning';
  if (score >= 60) return 'is-warning';
  return 'is-danger';
});

// Week 11: Heat Map Summary Color (Detection Rate based)
const heatMapSummaryColor = computed(() => {
  const rate = heatMapData.summary.overall_detection_rate || 0;
  if (rate >= 80) return '#48c774';       // Green
  if (rate >= 60) return '#ffdd57';       // Yellow
  if (rate > 0) return '#ff9800';         // Orange
  return '#ff3860';                        // Red
});

const heatMapSummaryColorClass = computed(() => {
  const rate = heatMapData.summary.overall_detection_rate || 0;
  if (rate >= 80) return 'has-text-success';
  if (rate >= 60) return 'has-text-warning';
  if (rate > 0) return 'has-text-warning-dark';
  return 'has-text-danger';
});

// Utility Functions
const formatTimestamp = (timestamp) => {
  if (!timestamp) return 'N/A';
  const date = new Date(timestamp);
  return date.toLocaleString('ko-KR');
};

const getLevelClass = (level) => {
  if (level >= 12) return 'danger';
  if (level >= 10) return 'warning';
  if (level >= 7) return 'info';
  return 'light';
};

const formatCoverage = (coverage) => {
  return `${(coverage * 100).toFixed(1)}%`;
};

const getBarWidth = (value, max) => {
  if (!max) return 0;
  return Math.round((value / max) * 100);
};

const maxExecuted = computed(() => {
  return Math.max(...dashboardData.tactic_coverage.map(t => t.executed), 1);
});

const maxTimelineValue = computed(() => {
  if (!dashboardData.timeline || dashboardData.timeline.length === 0) return 100;
  return Math.max(
    ...dashboardData.timeline.map(d => Math.max(d.attacks, d.detections)),
    10
  );
});

// Filtered KPI values based on current filters
const filteredKPI = computed(() => {
  const filtered_agents = sortedAgents.value;
  const filtered_detections = filteredDetections.value;
  const filtered_operations = filteredOperations.value;

  // Calculate total attack steps from filtered operations
  const total_attack_steps = filtered_operations.reduce((sum, op) => {
    return sum + (op.attack_steps ? op.attack_steps.length : 0);
  }, 0);

  // Calculate coverage (detections / attack steps)
  const coverage = total_attack_steps > 0
    ? filtered_detections.length / total_attack_steps
    : 0;

  // Get last seen from filtered agents
  const last_seen = filtered_agents.length > 0
    ? filtered_agents.reduce((latest, agent) => {
        const agentTime = new Date(agent.last_seen);
        return agentTime > latest ? agentTime : latest;
      }, new Date(0)).toISOString()
    : null;

  // Week 11: Security metrics from backend API
  const kpi = dashboardData.kpi || {};

  return {
    total_operations: filtered_operations.length,
    total_agents: filtered_agents.length,
    total_attack_steps: total_attack_steps,
    total_detections: filtered_detections.length,
    coverage: coverage,
    last_seen: last_seen,
    // Week 11: BAS-style metrics from backend
    security_score: kpi.security_score || 0,
    security_grade: kpi.security_grade || 'N/A',
    detection_rate: kpi.detection_rate || 0,
    mttd_minutes: kpi.mttd_minutes || 0,
    critical_gaps: kpi.critical_gaps || 0,
    tactic_coverage: kpi.tactic_coverage || 0
  };
});

// Chart Data for Tactic Coverage (Bar Chart) - Color-coded by Detection Rate
const tacticChartData = computed(() => {
  // OS filter를 적용한 tactic 통계 재계산
  const tacticStats = {};

  // 1. Executed 통계 (filteredOperations의 attack_steps)
  for (const op of filteredOperations.value) {
    for (const step of (op.attack_steps || [])) {
      // OS filter 확인
      if (filters.os_filter !== 'all') {
        const agentPlatform = op.agent_platforms?.[step.paw];
        if (!agentPlatform) continue;

        const platform = agentPlatform.toLowerCase();
        const filterOs = filters.os_filter.toLowerCase();
        if (platform !== filterOs && !platform.includes(filterOs)) {
          continue; // OS가 맞지 않으면 스킵
        }
      }

      const tactic = step.tactic;
      if (tactic) {
        if (!tacticStats[tactic]) {
          tacticStats[tactic] = { executed: 0, detected: 0 };
        }
        tacticStats[tactic].executed += 1;
      }
    }
  }

  // 2. Detected 통계 (filteredDetections)
  for (const detection of filteredDetections.value) {
    const tactic = detection.tactic;
    if (tactic) {
      if (!tacticStats[tactic]) {
        tacticStats[tactic] = { executed: 0, detected: 0 };
      }
      tacticStats[tactic].detected += 1;
    }
  }

  // 3. Chart 데이터 생성 with BAS-style color coding
  const tactics = Object.keys(tacticStats).sort();
  if (tactics.length === 0) {
    return { labels: [], datasets: [] };
  }

  // Calculate detection rates and assign colors (AttackIQ/Cymulate style)
  const detectedColors = tactics.map(tactic => {
    const stats = tacticStats[tactic];
    const detectionRate = stats.executed > 0 ? (stats.detected / stats.executed) * 100 : 0;

    // Color coding: Red (GAP), Yellow (PARTIAL), Green (OK)
    if (detectionRate === 0) {
      return 'rgba(255, 56, 96, 0.8)';  // Red - Critical Gap
    } else if (detectionRate < 80) {
      return 'rgba(255, 221, 87, 0.8)';  // Yellow - Partial Detection
    } else {
      return 'rgba(72, 199, 116, 0.8)';  // Green - Good Coverage
    }
  });

  const detectedBorderColors = tactics.map(tactic => {
    const stats = tacticStats[tactic];
    const detectionRate = stats.executed > 0 ? (stats.detected / stats.executed) * 100 : 0;

    if (detectionRate === 0) {
      return '#ff3860';  // Red border
    } else if (detectionRate < 80) {
      return '#ffdd57';  // Yellow border
    } else {
      return '#48c774';  // Green border
    }
  });

  return {
    labels: tactics,
    datasets: [
      {
        label: 'Executed',
        backgroundColor: 'rgba(50, 115, 220, 0.6)',  // Blue for executed steps
        borderColor: '#3273dc',
        borderWidth: 1,
        data: tactics.map(t => tacticStats[t].executed)
      },
      {
        label: 'Detected',
        backgroundColor: detectedColors,  // Dynamic colors based on detection rate
        borderColor: detectedBorderColors,
        borderWidth: 1,
        data: tactics.map(t => tacticStats[t].detected)
      }
    ]
  };
});

const tacticChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      display: true,
      position: 'top',
      labels: {
        color: '#f5f5f5',
        font: { size: 11 }
      }
    },
    tooltip: {
      backgroundColor: 'rgba(0, 0, 0, 0.8)',
      titleColor: '#f5f5f5',
      bodyColor: '#f5f5f5',
      borderColor: '#363636',
      borderWidth: 1
    }
  },
  scales: {
    x: {
      ticks: {
        color: '#b5b5b5',
        font: { size: 10 },
        maxRotation: 45,
        minRotation: 0
      },
      grid: {
        color: 'rgba(255, 255, 255, 0.05)'
      }
    },
    y: {
      beginAtZero: true,
      ticks: {
        color: '#b5b5b5',
        font: { size: 10 },
        precision: 0
      },
      grid: {
        color: 'rgba(255, 255, 255, 0.05)'
      }
    }
  }
};

// Filtered Timeline based on selected operation and OS filter
const filteredTimeline = computed(() => {
  const timelineMap = {};

  // 1. Attack steps 집계 (Operation filter + OS filter)
  for (const op of filteredOperations.value) {
    for (const step of (op.attack_steps || [])) {
      // OS filter 확인
      if (filters.os_filter !== 'all') {
        const agentPlatform = op.agent_platforms?.[step.paw];
        if (!agentPlatform) continue;

        const platform = agentPlatform.toLowerCase();
        const filterOs = filters.os_filter.toLowerCase();
        if (platform !== filterOs && !platform.includes(filterOs)) {
          continue; // OS가 맞지 않으면 스킵
        }
      }

      if (step.timestamp) {
        const bucket = step.timestamp.substring(0, 16);
        if (!timelineMap[bucket]) {
          timelineMap[bucket] = { time: bucket, attacks: 0, detections: 0 };
        }
        timelineMap[bucket].attacks += 1;
      }
    }
  }

  // 2. Detections 집계 (이미 filteredDetections에서 OS filter 적용됨)
  filteredDetections.value.forEach(detection => {
    if (detection.timestamp) {
      const bucket = detection.timestamp.substring(0, 16);
      if (!timelineMap[bucket]) {
        timelineMap[bucket] = { time: bucket, attacks: 0, detections: 0 };
      }
      timelineMap[bucket].detections += 1;
    }
  });

  return Object.values(timelineMap).sort((a, b) => a.time.localeCompare(b.time));
});

// Chart Data for Timeline (Line Chart)
const timelineChartData = computed(() => {
  const timeline = filteredTimeline.value;

  if (!timeline || timeline.length === 0) {
    return {
      labels: [],
      datasets: []
    };
  }

  return {
    labels: timeline.map((d, i) => `T${i}`),
    datasets: [
      {
        label: 'Attacks',
        backgroundColor: 'rgba(241, 70, 104, 0.2)',
        borderColor: '#f14668',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 5,
        data: timeline.map(d => d.attacks)
      },
      {
        label: 'Detections',
        backgroundColor: 'rgba(72, 199, 116, 0.2)',
        borderColor: '#48c774',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 5,
        data: timeline.map(d => d.detections)
      }
    ]
  };
});

const timelineChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      display: true,
      position: 'top',
      labels: {
        color: '#f5f5f5',
        font: { size: 11 }
      }
    },
    tooltip: {
      backgroundColor: 'rgba(0, 0, 0, 0.8)',
      titleColor: '#f5f5f5',
      bodyColor: '#f5f5f5',
      borderColor: '#363636',
      borderWidth: 1
    }
  },
  scales: {
    x: {
      ticks: {
        color: '#b5b5b5',
        font: { size: 10 }
      },
      grid: {
        color: 'rgba(255, 255, 255, 0.05)'
      }
    },
    y: {
      beginAtZero: true,
      ticks: {
        color: '#b5b5b5',
        font: { size: 10 },
        precision: 0
      },
      grid: {
        color: 'rgba(255, 255, 255, 0.05)'
      }
    }
  }
};
</script>

<template>
  <div id="bastionPage">
    <!-- Header -->
    <div class="mb-5">
      <h1 class="title is-1">
        Bastion
      </h1>
      <p class="subtitle is-6 has-text-grey-light">공격 시뮬레이션과 탐지 이벤트를 연계하여 커버리지와 리스크를 한눈에.</p>
    </div>
    <hr>

    <!-- Global Filters Section -->
    <div class="section">
      <div class="is-flex is-justify-content-space-between is-align-items-center mb-4">
        <h3 class="title is-5">필터</h3>
        <button class="button is-primary is-small" @click="refreshData" :disabled="isLoading">
          <span class="icon is-small">
            <i :class="isLoading ? 'fas fa-spinner fa-pulse' : 'fas fa-sync-alt'"></i>
          </span>
          <span>{{ isLoading ? '로딩 중...' : '새로고침' }}</span>
        </button>
      </div>

      <div class="box has-background-dark">
        <div class="columns is-multiline">
          <div class="column is-6-mobile is-3-tablet">
            <div class="field">
              <label class="label has-text-grey-light">검색</label>
              <div class="control has-icons-left">
                <input class="input" type="text" v-model="filters.search" placeholder="Agent, Description, Technique...">
                <span class="icon is-small is-left">
                  <i class="fas fa-search"></i>
                </span>
              </div>
            </div>
          </div>

          <div class="column is-6-mobile is-3-tablet">
            <div class="field">
              <label class="label has-text-grey-light">Operation</label>
              <div class="control">
                <div class="select is-fullwidth">
                  <select v-model="filters.operation_id">
                    <option value="all">All Operations</option>
                    <option v-for="op in allOperations" :key="op.id" :value="op.id">
                      {{ op.name }}
                    </option>
                  </select>
                </div>
              </div>
            </div>
          </div>

          <div class="column is-6-mobile is-3-tablet">
            <div class="field">
              <label class="label has-text-grey-light">OS Filter</label>
              <div class="control">
                <div class="select is-fullwidth">
                  <select v-model="filters.os_filter">
                    <option value="all">Any OS</option>
                    <option value="Windows">Windows</option>
                    <option value="Linux">Linux</option>
                    <option value="macOS">macOS</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- KPI Cards Section -->
    <div class="section">
      <div class="columns is-multiline">
        <!-- Security Score Card (Feature) -->
        <div class="column is-12-mobile is-4-tablet is-3-desktop">
          <div class="box has-background-dark kpi-card" style="border-left: 4px solid" :style="{ borderColor: securityScoreColor }">
            <div class="has-text-centered">
              <p class="heading mb-2">
                <span class="icon">
                  <i class="fas fa-shield-alt"></i>
                </span>
                Security Posture Score
              </p>
              <p class="title is-1 has-text-weight-bold mb-2" :class="securityScoreColor">
                {{ filteredKPI.security_score || 0 }}
              </p>
              <p class="subtitle is-4 has-text-weight-bold" :class="securityScoreColor">
                Grade: {{ filteredKPI.security_grade || 'N/A' }}
              </p>
              <progress class="progress" :class="securityScoreProgressClass" :value="filteredKPI.security_score || 0" max="100"></progress>
            </div>
          </div>
        </div>

        <!-- Detection Rate -->
        <div class="column is-half-mobile is-one-third-tablet is-2-desktop">
          <div class="box has-background-dark kpi-card">
            <div class="has-text-centered">
              <div class="kpi-icon-wrapper mb-3">
                <span class="icon is-large has-text-success">
                  <i class="fas fa-check-circle fa-3x"></i>
                </span>
              </div>
              <p class="heading">Detection Rate</p>
              <p class="title is-3 has-text-weight-bold">{{ filteredKPI.detection_rate || 0 }}%</p>
            </div>
          </div>
        </div>

        <!-- MTTD -->
        <div class="column is-half-mobile is-one-third-tablet is-2-desktop">
          <div class="box has-background-dark kpi-card">
            <div class="has-text-centered">
              <div class="kpi-icon-wrapper mb-3">
                <span class="icon is-large has-text-warning">
                  <i class="fas fa-stopwatch fa-3x"></i>
                </span>
              </div>
              <p class="heading">MTTD</p>
              <p class="title is-3 has-text-weight-bold">{{ filteredKPI.mttd_minutes || 0 }}m</p>
            </div>
          </div>
        </div>

        <!-- Critical Gaps -->
        <div class="column is-half-mobile is-one-third-tablet is-2-desktop">
          <div class="box has-background-dark kpi-card">
            <div class="has-text-centered">
              <div class="kpi-icon-wrapper mb-3">
                <span class="icon is-large has-text-danger">
                  <i class="fas fa-exclamation-triangle fa-3x"></i>
                </span>
              </div>
              <p class="heading">Critical Gaps</p>
              <p class="title is-3 has-text-weight-bold">{{ filteredKPI.critical_gaps || 0 }}</p>
            </div>
          </div>
        </div>

        <!-- Tactic Coverage -->
        <div class="column is-half-mobile is-one-third-tablet is-2-desktop">
          <div class="box has-background-dark kpi-card">
            <div class="has-text-centered">
              <div class="kpi-icon-wrapper mb-3">
                <span class="icon is-large has-text-info">
                  <i class="fas fa-layer-group fa-3x"></i>
                </span>
              </div>
              <p class="heading">Tactic Coverage</p>
              <p class="title is-3 has-text-weight-bold">{{ filteredKPI.tactic_coverage || 0 }}/14</p>
            </div>
          </div>
        </div>

        <!-- Operations -->
        <div class="column is-half-mobile is-one-third-tablet is-2-desktop">
          <div class="box has-background-dark kpi-card">
            <div class="has-text-centered">
              <div class="kpi-icon-wrapper mb-3">
                <span class="icon is-large has-text-primary">
                  <i class="fas fa-play-circle fa-3x"></i>
                </span>
              </div>
              <p class="heading">Operations</p>
              <p class="title is-3 has-text-weight-bold">{{ filteredKPI.total_operations }}</p>
            </div>
          </div>
        </div>

        <!-- Attack Steps -->
        <div class="column is-half-mobile is-one-third-tablet is-2-desktop">
          <div class="box has-background-dark kpi-card">
            <div class="has-text-centered">
              <div class="kpi-icon-wrapper mb-3">
                <span class="icon is-large has-text-warning">
                  <i class="fas fa-crosshairs fa-3x"></i>
                </span>
              </div>
              <p class="heading">Attack Steps</p>
              <p class="title is-3 has-text-weight-bold">{{ filteredKPI.total_attack_steps }}</p>
            </div>
          </div>
        </div>

        <!-- Detections -->
        <div class="column is-half-mobile is-one-third-tablet is-2-desktop">
          <div class="box has-background-dark kpi-card">
            <div class="has-text-centered">
              <div class="kpi-icon-wrapper mb-3">
                <span class="icon is-large has-text-danger">
                  <i class="fas fa-bell fa-3x"></i>
                </span>
              </div>
              <p class="heading">Detections</p>
              <p class="title is-3 has-text-weight-bold">{{ filteredKPI.total_detections }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Charts Row: Tactic Coverage (Bar) + Timeline (Area) + Operations -->
    <div class="section">
      <div class="columns">
        <!-- Tactic Coverage Bar Chart -->
        <div class="column is-4">
          <div class="box has-background-dark chart-box">
            <h4 class="title is-5 mb-4">
              <span class="icon has-text-info">
                <i class="fas fa-shield-alt"></i>
              </span>
              Tactic Coverage
            </h4>
            <div class="chart-container" style="height: 280px;">
              <Bar v-if="tacticChartData.labels.length > 0" :data="tacticChartData" :options="tacticChartOptions" />
              <div v-else class="is-flex is-align-items-center is-justify-content-center" style="height: 100%;">
                <p class="has-text-grey-light">No tactic coverage data</p>
              </div>
            </div>
            <p class="is-size-7 has-text-grey-light mt-3">
              전술(Tactic)별 탐지 커버리지.
              <span class="has-text-danger">■ 빨강(0%)</span>,
              <span class="has-text-warning">■ 노랑(1-79%)</span>,
              <span class="has-text-success">■ 녹색(80-100%)</span>
            </p>
          </div>
        </div>

        <!-- Timeline Area Chart -->
        <div class="column is-4">
          <div class="box has-background-dark chart-box">
            <h4 class="title is-5 mb-4">
              <span class="icon has-text-warning">
                <i class="fas fa-clock"></i>
              </span>
              Attack vs Detection Timeline
            </h4>
            <div class="chart-container" style="height: 280px;">
              <Line v-if="timelineChartData.labels.length > 0" :data="timelineChartData" :options="timelineChartOptions" />
              <div v-else class="is-flex is-align-items-center is-justify-content-center" style="height: 100%;">
                <p class="has-text-grey-light">No timeline data</p>
              </div>
            </div>
            <p class="is-size-7 has-text-grey-light mt-2">분 단위 버킷. 공격 직후의 탐지 피크를 확인하세요.</p>
          </div>
        </div>

        <!-- Operations Summary -->
        <div class="column is-4">
          <div class="box has-background-dark chart-box">
            <h4 class="title is-5 mb-4">
              <span class="icon has-text-primary">
                <i class="fas fa-play-circle"></i>
              </span>
              Operations
            </h4>
            <div class="chart-container" style="height: 280px; overflow-y: auto;">
              <div v-if="filteredOperations.length === 0" class="notification is-info is-light">
                <p class="is-size-7">조회된 작전이 없습니다.</p>
              </div>
              <div v-else>
                <div v-for="op in filteredOperations" :key="op.id" class="box has-background-black-ter operation-card-small mb-3" style="padding: 1rem;">
                  <p class="has-text-weight-semibold mb-2" style="font-size: 0.95rem; line-height: 1.3;">
                    {{ op.name }}
                  </p>
                  <p class="is-size-7 has-text-grey-light mb-3 is-family-monospace" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; line-height: 1.2;">
                    {{ op.id }}
                  </p>
                  <p class="is-size-7 has-text-grey mb-3" style="line-height: 1.2;">
                    {{ formatTimestamp(op.started) }}
                    <span v-if="op.finished"> → {{ formatTimestamp(op.finished) }}</span>
                    <span v-else-if="op.state === 'running'" class="has-text-warning"> → running</span>
                    <span v-else-if="op.state === 'finished'" class="has-text-success"> → finished</span>
                    <span v-else class="has-text-info"> → {{ op.state }}</span>
                  </p>
                  <div class="tags are-small" style="display: flex; flex-wrap: wrap; gap: 0.25rem; margin-bottom: 0;">
                    <span class="tag is-info is-light">{{ op.agent_count }} agents</span>
                    <span class="tag is-warning is-light">{{ op.attack_steps.length }} steps</span>
                    <span class="tag is-success is-light">{{ op.techniques.length }} techniques</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Week 11: MITRE ATT&CK Heat Map -->
    <div class="section">
      <h3 class="title is-5">
        <span class="icon has-text-danger">
          <i class="fas fa-fire"></i>
        </span>
        MITRE ATT&CK Technique Coverage
      </h3>
      <div class="box has-background-dark">
        <!-- Summary Cards - Enhanced with BAS-style colors -->
        <div class="columns is-multiline mb-4">
          <div class="column is-3">
            <div class="box has-background-grey-darker" style="border-left: 3px solid #b5b5b5;">
              <p class="heading">
                <span class="icon is-small">
                  <i class="fas fa-crosshairs"></i>
                </span>
                Total Techniques
              </p>
              <p class="title is-4">{{ heatMapData.summary.total_techniques }}</p>
            </div>
          </div>
          <div class="column is-3">
            <div class="box has-background-grey-darker" style="border-left: 3px solid #3273dc;">
              <p class="heading">
                <span class="icon is-small has-text-info">
                  <i class="fas fa-play-circle"></i>
                </span>
                Simulated
              </p>
              <p class="title is-4 has-text-info">{{ heatMapData.summary.total_simulated }}</p>
            </div>
          </div>
          <div class="column is-3">
            <div class="box has-background-grey-darker" style="border-left: 3px solid #48c774;">
              <p class="heading">
                <span class="icon is-small has-text-success">
                  <i class="fas fa-check-circle"></i>
                </span>
                Detected
              </p>
              <p class="title is-4 has-text-success">{{ heatMapData.summary.total_detected }}</p>
            </div>
          </div>
          <div class="column is-3">
            <div class="box has-background-grey-darker" :style="{ borderLeft: '3px solid ' + heatMapSummaryColor }">
              <p class="heading">
                <span class="icon is-small" :class="heatMapSummaryColorClass">
                  <i class="fas fa-chart-line"></i>
                </span>
                Detection Rate
              </p>
              <p class="title is-4" :class="heatMapSummaryColorClass">
                {{ heatMapData.summary.overall_detection_rate }}%
              </p>
            </div>
          </div>
        </div>

        <!-- Techniques Table -->
        <table class="table is-fullwidth is-hoverable is-narrow">
          <thead>
            <tr>
              <th>Status</th>
              <th>Technique ID</th>
              <th>Name</th>
              <th>Tactic</th>
              <th>Simulated</th>
              <th>Detected</th>
              <th>Rate</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="heatMapData.techniques.length === 0">
              <td colspan="7" class="has-text-centered has-text-grey-light">No technique data available</td>
            </tr>
            <tr
              v-for="tech in heatMapData.techniques"
              :key="tech.id"
              :class="{ 'has-background-danger-dark': tech.status === 'gap' }"
              :style="tech.status === 'gap' ? { borderLeft: '3px solid #ff3860' } : {}"
            >
              <td>
                <span
                  class="tag is-medium"
                  :class="{
                    'is-danger': tech.status === 'gap',
                    'is-warning': tech.status === 'partial',
                    'is-success': tech.status === 'complete',
                    'is-light': tech.status === 'not_simulated'
                  }"
                >
                  <span class="icon is-small">
                    <i
                      class="fas"
                      :class="{
                        'fa-exclamation-triangle': tech.status === 'gap',
                        'fa-exclamation-circle': tech.status === 'partial',
                        'fa-check-circle': tech.status === 'complete',
                        'fa-minus-circle': tech.status === 'not_simulated'
                      }"
                    ></i>
                  </span>
                  <span v-if="tech.status === 'gap'">GAP</span>
                  <span v-else-if="tech.status === 'partial'">PARTIAL</span>
                  <span v-else-if="tech.status === 'complete'">OK</span>
                  <span v-else>-</span>
                </span>
              </td>
              <td>
                <strong :class="{ 'has-text-danger': tech.status === 'gap' }">
                  {{ tech.id }}
                </strong>
              </td>
              <td :class="{ 'has-text-weight-semibold': tech.status === 'gap' }">
                {{ tech.name }}
              </td>
              <td><span class="tag is-info is-light">{{ tech.tactic }}</span></td>
              <td class="has-text-centered">{{ tech.simulated }}</td>
              <td class="has-text-centered">
                <span :class="{ 'has-text-danger has-text-weight-bold': tech.detected === 0 }">
                  {{ tech.detected }}
                </span>
              </td>
              <td>
                <div class="is-flex is-align-items-center" style="gap: 0.5rem;">
                  <progress
                    class="progress is-small"
                    :class="{
                      'is-danger': tech.detection_rate === 0,
                      'is-warning': tech.detection_rate > 0 && tech.detection_rate < 80,
                      'is-success': tech.detection_rate >= 80
                    }"
                    :value="tech.detection_rate"
                    max="100"
                  >
                    {{ tech.detection_rate }}%
                  </progress>
                  <span class="is-size-7 has-text-weight-semibold" style="min-width: 3rem;">
                    {{ tech.detection_rate }}%
                  </span>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Agents Table -->
    <div class="section">
      <h3 class="title is-5">Agents</h3>
      <div class="box has-background-dark" style="overflow-x: auto;">
        <div v-if="agentsData.total_agents === 0" class="notification is-info is-light">
          <p>등록된 Agent가 없습니다.</p>
        </div>
        <table v-else class="table is-fullwidth is-hoverable is-narrow">
          <thead>
            <tr>
              <th>Agent</th>
              <th>Host</th>
              <th>OS</th>
              <th class="has-text-right">Attack Steps</th>
              <th class="has-text-right">Detections</th>
              <th class="has-text-right">Coverage</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="agent in sortedAgents.slice(0, 20)" :key="agent.paw">
              <td>
                <span :class="agent.alive ? 'has-text-success' : 'has-text-danger'">
                  <i :class="agent.alive ? 'fas fa-circle' : 'far fa-circle'"></i>
                </span>
                {{ agent.paw }}
              </td>
              <td>{{ agent.host }}</td>
              <td><span class="tag is-info is-light is-small">{{ agent.platform }}</span></td>
              <td class="has-text-right">{{ agent.attack_steps_count || 0 }}</td>
              <td class="has-text-right">{{ agent.detections_count || 0 }}</td>
              <td class="has-text-right has-text-weight-bold">
                <span :class="(agent.attack_steps_count > 0 && agent.detections_count > 0) ? 'has-text-success' : 'has-text-grey'">
                  {{ agent.attack_steps_count > 0 ? Math.round((agent.detections_count / agent.attack_steps_count) * 100) + '%' : '0%' }}
                </span>
              </td>
              <td class="is-size-7">{{ formatTimestamp(agent.last_seen) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Detection Events Table -->
    <div class="section">
      <div class="is-flex is-justify-content-space-between is-align-items-center mb-4">
        <h3 class="title is-5">
          Detections (Wazuh)
          <span v-if="selectedAgentHost" class="tag is-info is-light ml-2">
            필터: {{ selectedAgentHost }}
          </span>
        </h3>
        <button v-if="selectedAgentHost" class="button is-small is-danger is-light" @click="clearAgentFilter">
          <span class="icon is-small">
            <i class="fas fa-times"></i>
          </span>
          <span>필터 해제</span>
        </button>
      </div>

      <div class="box has-background-dark" style="overflow-x: auto;">
        <div v-if="filteredDetections.length === 0" class="notification is-info is-light">
          <p>탐지된 이벤트가 없습니다.</p>
        </div>
        <table v-else class="table is-fullwidth is-striped is-hoverable is-narrow">
          <thead>
            <tr>
              <th>Time</th>
              <th>Agent</th>
              <th>Rule</th>
              <th>Level</th>
              <th>Technique</th>
              <th>Operation</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(event, idx) in filteredDetections.slice(0, 400)" :key="idx">
              <td class="is-size-7">{{ formatTimestamp(event.timestamp) }}</td>
              <td class="is-size-7">{{ event.agent_name || '-' }}</td>
              <td class="is-size-7">{{ event.rule_id }}</td>
              <td>
                <span class="tag is-small" :class="'is-' + getLevelClass(event.rule_level)">
                  {{ event.rule_level }}
                </span>
              </td>
              <td>
                <span v-if="event.technique_id" class="tag is-warning is-light is-small">
                  {{ event.technique_id }}
                </span>
                <span v-else class="has-text-grey">-</span>
              </td>
              <td class="is-size-7">{{ event.opId || '-' }}</td>
              <td class="is-size-7" style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;">
                {{ event.description }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Operation Correlation Section -->
    <div class="section">
      <h3 class="title is-5">작전 상관관계 분석</h3>
      <div class="box has-background-dark">
        <div class="field has-addons">
          <div class="control is-expanded">
            <input
              class="input"
              type="text"
              v-model="correlationOperationId"
              placeholder="Caldera 작전 ID"
            >
          </div>
          <div class="control">
            <button
              class="button is-primary"
              @click="correlateOperation"
              :disabled="!correlationOperationId || isCorrelating"
            >
              <span class="icon">
                <i :class="isCorrelating ? 'fas fa-spinner fa-pulse' : 'fas fa-search'"></i>
              </span>
              <span>{{ isCorrelating ? '분석 중...' : '분석' }}</span>
            </button>
          </div>
        </div>

        <div v-if="correlationResult" class="notification is-info is-light mt-4">
          <p class="title is-6">분석 결과</p>
          <div class="content is-small">
            <p><strong>작전:</strong> {{ correlationResult.operation_name }}</p>
            <p><strong>탐지율:</strong> {{ formatCoverage(correlationResult.correlation.detection_rate) }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
#bastionPage {
  padding: 1rem;
}

#bastionPage .section {
  padding: 1rem 0;
}

#bastionPage .box {
  border-radius: 8px;
}

#bastionPage .chart-box {
  height: 100%;
  min-height: 380px;
}

#bastionPage .table {
  background-color: transparent;
  color: #f5f5f5;
}

#bastionPage .table th {
  color: #b5b5b5;
  border-color: #363636;
  font-weight: 600;
}

#bastionPage .table td {
  border-color: #363636;
  color: #f5f5f5;
}

#bastionPage .table.is-striped tbody tr:nth-child(even) {
  background-color: rgba(255, 255, 255, 0.02);
}

#bastionPage .table.is-hoverable tbody tr:hover {
  background-color: rgba(72, 199, 116, 0.1);
}

#bastionPage .heading {
  color: #b5b5b5;
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-weight: 600;
}

#bastionPage .kpi-card {
  transition: transform 0.2s;
  padding: 1.5rem;
}

#bastionPage .kpi-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
}

#bastionPage .kpi-icon-wrapper {
  display: inline-block;
  width: 90px;
  height: 90px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.08);
  border: 2px solid rgba(255, 255, 255, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto;
  transition: all 0.3s ease;
}

#bastionPage .kpi-card:hover .kpi-icon-wrapper {
  background: rgba(255, 255, 255, 0.12);
  border-color: rgba(255, 255, 255, 0.2);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
}

#bastionPage .kpi-icon-wrapper .icon {
  margin: 0;
}

/* 아이콘 색상 강조 with Gradient Backgrounds */
#bastionPage .kpi-card:has(.has-text-info) .kpi-icon-wrapper {
  background: radial-gradient(circle, rgba(50, 152, 220, 0.2) 0%, rgba(50, 152, 220, 0.05) 100%);
  border-color: rgba(50, 152, 220, 0.4);
}

#bastionPage .kpi-icon-wrapper .has-text-info {
  color: #3298dc !important;
  text-shadow: 0 0 12px rgba(50, 152, 220, 0.6);
}

#bastionPage .kpi-card:has(.has-text-success) .kpi-icon-wrapper {
  background: radial-gradient(circle, rgba(72, 199, 116, 0.2) 0%, rgba(72, 199, 116, 0.05) 100%);
  border-color: rgba(72, 199, 116, 0.4);
}

#bastionPage .kpi-icon-wrapper .has-text-success {
  color: #48c774 !important;
  text-shadow: 0 0 12px rgba(72, 199, 116, 0.6);
}

#bastionPage .kpi-card:has(.has-text-warning) .kpi-icon-wrapper {
  background: radial-gradient(circle, rgba(255, 221, 87, 0.2) 0%, rgba(255, 221, 87, 0.05) 100%);
  border-color: rgba(255, 221, 87, 0.4);
}

#bastionPage .kpi-icon-wrapper .has-text-warning {
  color: #ffdd57 !important;
  text-shadow: 0 0 12px rgba(255, 221, 87, 0.6);
}

#bastionPage .kpi-card:has(.has-text-danger) .kpi-icon-wrapper {
  background: radial-gradient(circle, rgba(241, 70, 104, 0.2) 0%, rgba(241, 70, 104, 0.05) 100%);
  border-color: rgba(241, 70, 104, 0.4);
}

#bastionPage .kpi-icon-wrapper .has-text-danger {
  color: #f14668 !important;
  text-shadow: 0 0 12px rgba(241, 70, 104, 0.6);
}

#bastionPage .kpi-card:has(.has-text-primary) .kpi-icon-wrapper {
  background: radial-gradient(circle, rgba(121, 87, 213, 0.2) 0%, rgba(121, 87, 213, 0.05) 100%);
  border-color: rgba(121, 87, 213, 0.4);
}

#bastionPage .kpi-icon-wrapper .has-text-primary {
  color: #7957d5 !important;
  text-shadow: 0 0 12px rgba(121, 87, 213, 0.6);
}

#bastionPage .kpi-card:has(.has-text-grey) .kpi-icon-wrapper {
  background: radial-gradient(circle, rgba(181, 181, 181, 0.15) 0%, rgba(181, 181, 181, 0.05) 100%);
  border-color: rgba(181, 181, 181, 0.3);
}

#bastionPage .kpi-icon-wrapper .has-text-grey {
  color: #b5b5b5 !important;
  text-shadow: 0 0 12px rgba(181, 181, 181, 0.4);
}

#bastionPage .operation-card-small {
  transition: all 0.2s;
  border-left: 3px solid transparent;
}

#bastionPage .operation-card-small:hover {
  transform: translateY(-2px);
  border-left-color: #3273dc;
}

/* Bar Chart Styles */
.bar-container {
  margin-bottom: 8px;
}

.bar-background {
  position: relative;
  height: 24px;
  background-color: rgba(255, 255, 255, 0.05);
  border-radius: 4px;
  overflow: hidden;
}

.bar-executed {
  position: absolute;
  top: 0;
  left: 0;
  height: 100%;
  background-color: #ffe08a;
  transition: width 0.3s ease;
  opacity: 0.6;
}

.bar-detected {
  position: absolute;
  top: 0;
  left: 0;
  height: 100%;
  background-color: #48c774;
  transition: width 0.3s ease;
  opacity: 0.8;
}

/* Scrollbar styling */
.chart-container::-webkit-scrollbar {
  width: 6px;
}

.chart-container::-webkit-scrollbar-track {
  background: rgba(255, 255, 255, 0.05);
  border-radius: 3px;
}

.chart-container::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.2);
  border-radius: 3px;
}

.chart-container::-webkit-scrollbar-thumb:hover {
  background: rgba(255, 255, 255, 0.3);
}
</style>

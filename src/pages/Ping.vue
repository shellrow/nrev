<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { ElMessage } from 'element-plus';
import {PROTOCOL_ICMPv4, PROTOCOL_TCP, PROTOCOL_UDP}  from '../config/define';
import {isIpv4NetworkAddress, isIpv6NetworkAddress, isValidHostname, isValidIPaddress} from '../logic/shared';
import { useRoute } from 'vue-router';

const pinging = ref(false);
const route = useRoute();

interface PingOption {
  target_host: string;
  protocol: string;
  port: number;
  count: number;
  os_detection_flag: boolean;
  save_flag: boolean;
}

const option = reactive({
  target_host: "",
  protocol: PROTOCOL_ICMPv4,
  port: 0,
  count: 4,
  os_detection_flag: true,
  save_flag: false,
});

const result: PingStat = reactive({
  ping_results: [],
  probe_time: 0,
  transmitted_count: 0,
  received_count: 0,
  min: 0,
  avg: 0, 
  max: 0,
});

const protocol_options = [
  {
    value: PROTOCOL_ICMPv4,
    label: 'ICMP',
  },
  {
    value: PROTOCOL_TCP,
    label: 'TCP',
  },
  {
    value: PROTOCOL_UDP,
    label: 'UDP',
  },
];

type PingProgress = {
  content: string;
  timestamp: string;
}

const ping_progress = ref<PingProgress[]>([]);

const initResult = () => {
  result.ping_results = [];
  result.probe_time = 0;
  result.transmitted_count = 0;
  result.received_count = 0;
  result.min = 0;
  result.avg = 0; 
  result.max = 0;
}

type PingResult = {
  protocol: string;
  seq: number;
  ip_addr: string;
  host_name: string;
  port_number: number;
  ttl: number;
  hop: number;
  rtt: number;
  status: string;
}

type PingStat = {
  ping_results: PingResult[];
  probe_time: number;
  transmitted_count: number;
  received_count: number;
  min: number;
  avg: number;
  max: number;
}

const runPing = async() => {
  const unlisten = await listen<string>('ping_progress', (event) => {
    ping_progress.value.push(
      {
        content: event.payload,
        timestamp: (new Date).toString(),
      }
    );
  });
  initResult();
  pinging.value = true;
  const opt = {
    target_host: option.target_host,
    protocol: option.protocol,
    port: Number(option.port),
    count: option.count,
    os_detection_flag: option.os_detection_flag,
    save_flag: option.save_flag,
  };
  invoke<PingStat>('exec_ping', { "opt": opt }).then((ping_stat) => {
    ping_stat.ping_results.forEach(ping_result => {
      result.ping_results.push({
        protocol: ping_result.protocol,
        seq: ping_result.seq,
        ip_addr: ping_result.ip_addr,
        host_name: ping_result.host_name,
        port_number: ping_result.port_number,
        ttl: ping_result.ttl,
        hop: ping_result.hop,
        rtt: ping_result.rtt / 1000,
        status: ping_result.status,
      });
    });
    //result.ping_results = ping_stat.ping_results;
    result.transmitted_count = ping_stat.transmitted_count;
    result.received_count = ping_stat.received_count;
    result.probe_time = ping_stat.probe_time / 1000;
    result.min = ping_stat.min / 1000;
    result.avg = ping_stat.avg / 1000;
    result.max = ping_stat.max / 1000;
    pinging.value = false;
    ping_progress.value = [];
  });
};

const validateInput = () => {
  if (!option.target_host) {
    return "TargetHost is required";
  }
  if (isValidIPaddress(option.target_host) || isValidHostname(option.target_host)) {
    if (isIpv4NetworkAddress(option.target_host) || isIpv6NetworkAddress(option.target_host)) {
      return "Invalid host (network address)";
    }
    return "OK";
  }else {
    return "Invalid host";
  }
}

const clickScan = () => {
  const inputStatus = validateInput();
  if (inputStatus != "OK") {
    ElMessage({
      message: inputStatus,
      type: 'warning',
    })
    return;
  }
  runPing();
};

onMounted(() => {
  if (route.params.host) {
    option.target_host = route.params.host.toString();
  }
});

onUnmounted(() => {

});

</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.item {
  margin-bottom: 18px;
}

</style>

<template>
    <el-card class="box-card">
      <!-- Header -->
      <template #header>
          <div class="card-header">
              <span>Ping</span>
              <el-button type="primary" plain @click="clickScan" :loading="pinging" >Ping</el-button>
          </div>
      </template>
      <!-- Header -->
      <!-- Options -->
      <el-row>
        <el-form :inline="true" label-position="top">
          <el-form-item label="TargetHost">
            <el-input v-model="option.target_host" placeholder="IP Address or HostName" style="max-width: 300px;" />
          </el-form-item>
          <el-form-item label="Protocol">
            <el-select v-model="option.protocol" placeholder="Select" style="max-width: 100px;">
                <el-option v-for="item in protocol_options"
                    :key="item.value"
                    :label="item.label"
                    :value="item.value"
                />
            </el-select>
          </el-form-item>
          <el-form-item label="Port No">
            <el-input type="number" min="0" max="65535" v-model="option.port" placeholder="80" style="max-width: fit-content;" />
          </el-form-item>
          <el-form-item label="Count">
            <el-input type="number" min="0" max="64" v-model="option.count" placeholder="80" style="max-width: fit-content;"/>
          </el-form-item>
        </el-form>
      </el-row>
      <!-- Options -->
    </el-card>
    <!-- Results -->
    <div v-loading="pinging" element-loading-text="Pinging..." class="mt-2">
      <div v-if="result.ping_results.length > 0">
        <el-descriptions
            title="Ping Result"
            direction="vertical"
            :column="4"
            border
        >
        </el-descriptions>
        <el-table :data="result.ping_results" style="width: 100%" class="mt-2">
            <el-table-column prop="protocol" label="Protocol" width="100" />
            <el-table-column prop="seq" label="SEQ" width="80" />
            <el-table-column prop="ip_addr" label="IP Address" width="200" />
            <el-table-column prop="host_name" label="Host Name" />
            <el-table-column prop="port_number" label="Port" width="100" />
            <el-table-column prop="ttl" label="TTL" width="100" />
            <el-table-column prop="hop" label="HOP" width="100" />
            <el-table-column prop="rtt" label="RTT(ms)" width="100" />
            <el-table-column prop="status" label="Status" width="100" />
        </el-table>
      </div>
      <div v-else>
          <el-descriptions
              title="Ping Result"
              direction="vertical"
              :column="4"
              border
          >
          </el-descriptions>
          <el-result icon="info" title="No Data">
              <template #sub-title>
              </template>
              <template #extra>
              </template>
          </el-result>
      </div>
    </div>
    <el-timeline>
      <el-timeline-item
        v-for="(res, index) in ping_progress"
        :key="index"
        :timestamp="res.timestamp"
      >
        {{ res.content }}
      </el-timeline-item>
  </el-timeline>
    <!-- Results -->
</template>
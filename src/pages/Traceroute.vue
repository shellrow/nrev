<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { debounce } from 'lodash';
import { ElMessage } from 'element-plus';
import {sleep} from '../logic/shared.js';
import {isIpv4NetworkAddress, isIpv6NetworkAddress, isValidHostname, isValidIPaddress} from '../logic/shared';

const tracing = ref(false);

const option = reactive({
    target_host: "",
    max_hop: 64,
    timeout: 30000,
    os_detection_flag: true,
    save_flag: false,
});

const result = reactive({
    nodes: [],
    status: "",
    probe_time: "",
});

const trace_progress = ref([]);

const initResult = () => {
  result.nodes = [];
  result.status = "";
  result.probe_time = "";
}

const runTraceroute = async() => {
  const unlisten = await listen('trace_progress', (event) => {
    console.log(event);
    trace_progress.value.push(
      {
        content: event.payload,
        timestamp: (new Date).toString(),
      }
    );
  });
  initResult();
  tracing.value = true;
  const opt = {
    target_host: option.target_host,
    max_hop: option.max_hop,
    timeout: option.timeout,
    os_detection_flag: option.os_detection_flag,
    save_flag: option.save_flag,
  };
  invoke('exec_traceroute', { "opt": opt }).then((trace_result) => {
    console.log(trace_result);
    trace_result.nodes.forEach(node => {
      result.nodes.push({
        seq: node.seq,
        ip_addr: node.ip_addr,
        host_name: node.host_name,
        ttl: node.ttl,
        hop: node.hop,
        rtt: node.rtt / 1000,
        node_type: node.node_type,
      });
    });
    result.status = "";
    result.probe_time = trace_result.probe_time / 1000;
    console.log(result);
    tracing.value = false;
    trace_progress.value = [];
  });
}

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

const clickScan = (event) => {
  const inputStatus = validateInput();
  if (inputStatus != "OK") {
    ElMessage({
      message: inputStatus,
      type: 'warning',
    })
    return;
  }
  runTraceroute();
};

onMounted(() => {
  
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
              <span>Traceroute</span>
              <el-button type="primary" plain @click="clickScan" :loading="tracing" >Trace</el-button>
          </div>
      </template>
      <!-- Header -->
      <!-- Options -->
      <el-row :gutter="20">
        <el-col :span="6">
          <p style="font-size: var(--el-font-size-small)">TargetHost</p>
          <el-input v-model="option.target_host" placeholder="IP Address or HostName" />
        </el-col>
        <el-col :span="3">
            <p style="font-size: var(--el-font-size-small)">Max Hop</p>
            <el-input type="number" min="0" max="64" v-model="option.max_hop" placeholder="80" />
        </el-col>
        <el-col :span="3">
            <p style="font-size: var(--el-font-size-small)">Timeout</p>
            <el-input type="number" min="0" max="60000" v-model="option.timeout" placeholder="30000" />
        </el-col>
      </el-row>
      <!-- Options -->
    </el-card>
    <!-- Results -->
    <div v-loading="tracing" element-loading-text="Tracing..." class="mt-2">
      <div v-if="result.nodes.length > 0">
        <el-descriptions
            title="Trace Result"
            direction="vertical"
            :column="4"
            border
        >
        </el-descriptions>
        <el-table :data="result.nodes" style="width: 100%" class="mt-2">
            <el-table-column prop="seq" label="SEQ" width="80" />
            <el-table-column prop="ip_addr" label="IP Address" width="200" />
            <el-table-column prop="host_name" label="Host Name" />
            <el-table-column prop="ttl" label="TTL" width="80" />
            <el-table-column prop="hop" label="HOP" width="80" />
            <el-table-column prop="rtt" label="RTT(ms)" width="90" />
            <el-table-column prop="node_type" label="Node Type" width="120"/>
        </el-table>
      </div>
      <div v-else>
          <el-descriptions
              title="Trace Result"
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
            v-for="(res, index) in trace_progress"
            :key="index"
            :timestamp="res.timestamp"
        >
            {{ res.content }}
        </el-timeline-item>
    </el-timeline>
    <!-- Results -->
</template>

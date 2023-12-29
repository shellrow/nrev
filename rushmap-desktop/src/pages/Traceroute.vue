<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { ElMessage } from 'element-plus';
import { isIpv4NetworkAddress, isIpv6NetworkAddress, isValidHostname, isValidIPaddress } from '../logic/shared';
import { useRoute } from 'vue-router';
import { Duration, as_millis } from '../types/time';

interface TraceProgress {
  content: string;
  timestamp: string;
}

type PingResponseRust = {
  seq: number;
  ip_addr: string;
  host_name: string;
  ttl: number;
  hop: number;
  rtt: Duration;
  status: string;
  protocol: string;
  node_type: string;
}

type TracerouteResultRust = {
  probe_id: string;
  nodes: PingResponseRust[];
  probe_status: string;
  start_time: string;
  end_time: string;
  elapsed_time: Duration;
  protocol: string;
  command_type: string;
}

type PingResponse = {
  seq: number;
  ip_addr: string;
  host_name: string;
  ttl: number;
  hop: number;
  rtt: number;
  status: string;
  protocol: string;
  node_type: string;
}

type TracerouteResult = {
  probe_id: string;
  nodes: PingResponse[];
  probe_status: string;
  start_time: string;
  end_time: string;
  elapsed_time: Duration;
  protocol: string;
  command_type: string;
}

const route = useRoute();
const tracing = ref(false);

const option = reactive({
    target_host: "",
    max_hop: 64,
    timeout: 30000,
    os_detection_flag: true,
    save_flag: false,
});

const result: TracerouteResult = reactive({
  probe_id: "",
  nodes: [],
  probe_status: "",
  start_time: "",
  end_time: "",
  elapsed_time: new Duration(0, 0),
  protocol: "",
  command_type: "",
});

const trace_progress = ref<TraceProgress[]>([]);

const initResult = () => {
  result.probe_id = "";
  result.nodes = [];
  result.probe_status = "";
  result.start_time = "";
  result.end_time = "";
  result.elapsed_time = new Duration(0, 0);
  result.protocol = "";
  result.command_type = "";
}

const runTraceroute = async() => {
  const unlisten = await listen<string>('trace_progress', (event) => {
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
  invoke<TracerouteResultRust>('exec_traceroute', { "opt": opt }).then((trace_result) => {
    trace_result.nodes.forEach(node => {
      result.nodes.push({
        seq: node.seq,
        ip_addr: node.ip_addr,
        host_name: node.host_name,
        ttl: node.ttl,
        hop: node.hop,
        rtt: as_millis(node.rtt),
        status: node.status,
        protocol: node.protocol,
        node_type: node.node_type,
      });
    });
    result.probe_status = "";
    result.elapsed_time = trace_result.elapsed_time;
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

const clickScan = () => {
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
  max-height: 20px;
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
      <el-row>
        <el-form :inline="true" label-position="top">
          <el-form-item label="TargetHost">
            <el-input v-model="option.target_host" placeholder="IP Address or HostName" style="max-width: 300px;" />
          </el-form-item>
          <el-form-item label="Max Hop">
            <el-input type="number" min="0" max="64" v-model="option.max_hop" placeholder="80" style="max-width: fit-content;" />
          </el-form-item>
          <el-form-item label="Timeout">
            <el-input type="number" min="0" max="60000" v-model="option.timeout" placeholder="30000" style="max-width: fit-content;" />
          </el-form-item>
        </el-form>
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
            <el-table-column prop="rtt" label="RTT(ms)" width="100" />
            <el-table-column prop="node_type" label="Node Type" width="130"/>
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

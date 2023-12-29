<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { ElMessage } from 'element-plus';
import { PROTOCOL_ICMPv4, PROTOCOL_TCP, PROTOCOL_UDP }  from '../config/define';
import { isIpv4NetworkAddress, isIpv6NetworkAddress, isValidHostname, isValidIPaddress } from '../logic/shared';
import { useRoute } from 'vue-router';
import { Duration, as_millis } from '../types/time';

interface PingOption {
  target_host: string;
  protocol: string;
  port: number;
  count: number;
  os_detection_flag: boolean;
  save_flag: boolean;
}

type PingProgress = {
  content: string;
  timestamp: string;
}

type PingResponseRust = {
  seq: number;
  ip_addr: string;
  host_name: string;
  port_number: number;
  ttl: number;
  hop: number;
  rtt: Duration;
  status: string;
  protocol: string;
  node_type: string;
}

type PingStatRust = {
    responses: PingResponseRust[];
    probe_time: Duration;
    transmitted_count: number;
    received_count: number;
    min: Duration;
    avg: Duration;
    max: Duration;
}

type PingResultRust = {
  probe_id: string;
  stat: PingStatRust;
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
  port_number: number;
  ttl: number;
  hop: number;
  rtt: number;
  status: string;
  protocol: string;
  node_type: string;
}

type PingStat = {
    responses: PingResponse[];
    probe_time: Duration;
    transmitted_count: number;
    received_count: number;
    min: Duration;
    avg: Duration;
    max: Duration;
}

type PingResult = {
  probe_id: string;
  stat: PingStat;
  probe_status: string;
  start_time: string;
  end_time: string;
  elapsed_time: Duration;
  protocol: string;
  command_type: string;
}

const route = useRoute();

const pinging = ref(false);
const ping_progress = ref<PingProgress[]>([]);

const option = reactive({
  target_host: "",
  protocol: PROTOCOL_ICMPv4,
  port: 0,
  count: 4,
  os_detection_flag: true,
  save_flag: false,
});

const result: PingResult = reactive({
  probe_id: "",
  stat: {
    responses: [],
    probe_time: new Duration(0, 0),
    transmitted_count: 0,
    received_count: 0,
    min: new Duration(0, 0),
    avg: new Duration(0, 0),
    max: new Duration(0, 0),
  },
  probe_status: "",
  start_time: "",
  end_time: "",
  elapsed_time: new Duration(0, 0),
  protocol: "",
  command_type: "",
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

const initResult = () => {
  result.probe_id = "";
  result.stat.responses = [];
  result.probe_status = "";
  result.start_time = "";
  result.end_time = "";
  result.elapsed_time = new Duration(0, 0);
  result.protocol = "";
  result.command_type = "";
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
  invoke<PingResultRust>('exec_ping', { "opt": opt }).then((ping_result) => {
    ping_result.stat.responses.forEach(ping_res => {
      result.stat.responses.push({
        seq: ping_res.seq,
        ip_addr: ping_res.ip_addr,
        host_name: ping_res.host_name,
        port_number: ping_res.port_number,
        ttl: ping_res.ttl,
        hop: ping_res.hop,
        rtt: as_millis(ping_res.rtt),
        status: ping_res.status,
        protocol: ping_res.protocol,
        node_type: ping_res.node_type,
      });
    });
    //result.ping_results = ping_stat.ping_results;
    result.stat.transmitted_count = ping_result.stat.transmitted_count;
    result.stat.received_count = ping_result.stat.received_count;
    result.stat.probe_time = ping_result.stat.probe_time;
    result.stat.min = ping_result.stat.min;
    result.stat.avg = ping_result.stat.avg;
    result.stat.max = ping_result.stat.max;
    result.elapsed_time = ping_result.elapsed_time;
    result.probe_status = ping_result.probe_status;
    result.start_time = ping_result.start_time;
    result.end_time = ping_result.end_time;
    result.protocol = ping_result.protocol;
    result.command_type = ping_result.command_type;
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
      <div v-if="result.stat.responses.length > 0">
        <el-descriptions
            title="Ping Result"
            direction="vertical"
            :column="4"
            border
        >
        </el-descriptions>
        <el-table :data="result.stat.responses" style="width: 100%" class="mt-2">
            <el-table-column prop="protocol" label="Protocol" width="100" />
            <el-table-column prop="seq" label="SEQ" width="80" />
            <el-table-column prop="ip_addr" label="IP Address" width="120" />
            <el-table-column prop="host_name" label="Host Name" />
            <el-table-column prop="port_number" label="Port" width="80" />
            <el-table-column prop="ttl" label="TTL" width="80" />
            <el-table-column prop="hop" label="HOP" width="80" />
            <el-table-column prop="rtt" label="RTT(ms)" width="100" />
            <el-table-column prop="status" label="Status" width="80" />
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
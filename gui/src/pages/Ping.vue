<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { debounce } from 'lodash';
import {sleep} from '../logic/shared.js';
import {PROTOCOL_ICMPv4, PROTOCOL_TCP, PROTOCOL_UDP}  from '../define.js';

const pinging = ref(false);

const option = reactive({
  target_host: "",
  protocol: PROTOCOL_ICMPv4,
  port: 0,
  count: 4,
  os_detection_flag: true,
  save_flag: false,
});

const result = reactive({
  ping_results: [],
  probe_time: "",
  transmitted_count: 0,
  received_count: 0,
  min: "",
  avg: "", 
  max: "",
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

const ping_progress = ref([]);

const initResult = () => {
  result.ping_results = [];
  result.probe_time = "";
  result.transmitted_count = 0;
  result.received_count = 0;
  result.min = "";
  result.avg = ""; 
  result.max = "";
}

const runPing = async() => {
  const unlisten = await listen('ping_progress', (event) => {
    console.log(event);
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
    port: option.port,
    count: option.count,
    os_detection_flag: option.os_detection_flag,
    save_flag: option.save_flag,
  };
  invoke('exec_ping', { "opt": opt }).then((ping_stat) => {
    console.log(ping_stat);
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
    console.log(result);
    pinging.value = false;
    ping_progress.value = [];
  });
};

const clickScan = (event) => {
  runPing();
};

onMounted(() => {
    invoke('test_command_arg', { invokeMessage: 'Ping' });
    invoke('test_command_return').then((message) => console.log(message));
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
      <el-row :gutter="20">
        <el-col :span="6">
          <p style="font-size: var(--el-font-size-small)">IP Address</p>
          <el-input v-model="option.target_host" placeholder="IP Address" />
        </el-col>
        <el-col :span="4">
            <p style="font-size: var(--el-font-size-small)">Protocol</p>
            <el-select v-model="option.protocol" placeholder="Select">
                <el-option v-for="item in protocol_options"
                    :key="item.value"
                    :label="item.label"
                    :value="item.value"
                />
            </el-select>
        </el-col>
        <el-col :span="3">
            <p style="font-size: var(--el-font-size-small)">Port No</p>
            <el-input type="number" min="0" max="65535" v-model="option.port" placeholder="80" />
        </el-col>
        <el-col :span="3">
            <p style="font-size: var(--el-font-size-small)">Count</p>
            <el-input type="number" min="0" max="64" v-model="option.count" placeholder="80" />
        </el-col>
      </el-row>
      <el-row :gutter="20">
        <el-col :span="4">
            <el-checkbox v-model="option.os_detection_flag" label="OS Detection" />
        </el-col>
        <el-col :span="4">
            <el-checkbox v-model="option.save_flag" label="Save" />
        </el-col>
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
            <el-table-column prop="protocol" label="Protocol" />
            <el-table-column prop="seq" label="SEQ" />
            <el-table-column prop="ip_addr" label="IP Address"  />
            <el-table-column prop="host_name" label="Host Name" />
            <el-table-column prop="port_number" label="Port" />
            <el-table-column prop="ttl" label="TTL" />
            <el-table-column prop="hop" label="HOP" />
            <el-table-column prop="rtt" label="RTT(ms)" />
            <el-table-column prop="status" label="Status" />
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
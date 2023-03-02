<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { debounce } from 'lodash';
import {sleep} from '../logic/shared.js';

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
    result.nodes = trace_result.nodes;
    result.status = "";
    result.probe_time = trace_result.probe_time / 1000;
    console.log(result);
    tracing.value = false;
    trace_progress.value = [];
  });
}

const clickScan = (event) => {
  runTraceroute();
};

onMounted(() => {
    invoke('test_command_arg', { invokeMessage: 'Traceroute' });
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
              <span>Traceroute</span>
              <el-button type="primary" plain @click="clickScan" :loading="tracing" >Trace</el-button>
          </div>
      </template>
      <!-- Header -->
      <!-- Options -->
      <el-row :gutter="20">
        <el-col :span="6">
          <p style="font-size: var(--el-font-size-small)">Target</p>
          <el-input v-model="option.target_host" placeholder="IP Address or Host Name" />
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
            <el-table-column prop="seq" label="SEQ" />
            <el-table-column prop="ip_addr" label="IP Address"  />
            <el-table-column prop="host_name" label="Host Name" />
            <el-table-column prop="ttl" label="TTL" />
            <el-table-column prop="hop" label="HOP" />
            <el-table-column prop="rtt" label="RTT" />
            <el-table-column prop="node_type" label="Node Type" />
            <el-table-column prop="status" label="Status" />
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

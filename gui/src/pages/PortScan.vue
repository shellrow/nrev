<script setup>
import { ref, reactive, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { ElMessage } from 'element-plus'
//import { debounce } from 'lodash';
//import {sleep} from '../logic/shared.js';
import {PORT_OPTION_DEFAULT,PORT_OPTION_WELL_KNOWN,PORT_OPTION_CUSTOM_LIST,PORTSCAN_TYPE_TCP_SYN,PORTSCAN_TYPE_TCP_CONNECT} from '../define.js';
import { isValidHostname, isValidIPaddress } from '../logic/shared';

const scanning = ref(false);
const dialog_list_visible = ref(false);

//Port Tags
const tag_input_value = ref('');
const port_tags = ref([]);
const tag_input_visible = ref(false);
const tag_input_ref = ref(null);

const handleTagClose = (tag) => {
  port_tags.value.splice(port_tags.value.indexOf(tag), 1);
};

const showTagInput = () => {
  tag_input_visible.value = true;
  nextTick(() => {
    tag_input_ref.value.input.focus();
  });
};

const handleInputConfirm = () => {
  if (tag_input_value.value) {
    if (!port_tags.value.includes(tag_input_value.value)){
      port_tags.value.push(tag_input_value.value);
    }
  }
  tag_input_visible.value = false;
  tag_input_value.value = '';
};

const option = reactive({
    target_host: "",
    port_option: PORT_OPTION_DEFAULT,
    ports:[],
    scan_type: PORTSCAN_TYPE_TCP_SYN,
    async_flag: true,
    service_detection_flag: true,
    os_detection_flag: true,
    save_flag: false,
});

const result = reactive({
    ip_addr: "",
    host_name: "",
    ports: [],
    mac_addr: "",
    vendor_name: "",
    os_name: "",
    os_version: "",
    cpe: "",
    cpe_detail: "",
});

const port_options = [
  {
    value: PORT_OPTION_DEFAULT,
    label: 'Default(1005 ports)',
  },
  {
    value: PORT_OPTION_WELL_KNOWN,
    label: 'Well Known(685 ports)',
  },
  {
    value: PORT_OPTION_CUSTOM_LIST,
    label: 'Custom List',
  },
];

const scanTypeOptions = [
  {
    value: PORTSCAN_TYPE_TCP_SYN,
    label: 'TCP SYN Scan',
  },
  {
    value: PORTSCAN_TYPE_TCP_CONNECT,
    label: 'TCP Connect Scan',
  },
];

const runPortScan = async() => {
  scanning.value = true;
  if (option.port_option === PORT_OPTION_CUSTOM_LIST) {
    port_tags.value.forEach(port => {
      if (!option.ports.includes(parseInt(port))) {
        option.ports.push(parseInt(port));
      }
    });
  }
  const opt = {
    target_host: option.target_host,
    port_option: option.port_option,
    ports: option.ports,
    scan_type: option.scan_type,
    async_flag: option.async_flag,
    service_detection_flag: option.service_detection_flag,
    os_detection_flag: option.os_detection_flag,
    save_flag: option.save_flag,
  };
  invoke('exec_portscan', { "opt": opt }).then((scan_result) => {
    scanning.value = false;
    let open_ports = [];
    scan_result.ports.forEach(port => {
      if (port.port_status === "Open"){
        open_ports.push(port);
      }
    });
    console.log(scan_result);
    result.ip_addr = scan_result.host.ip_addr;
    result.host_name = scan_result.host.host_name;
    result.mac_addr = scan_result.host.mac_addr;
    result.vendor_name = scan_result.host.vendor_info;
    result.os_name = scan_result.host.os_name;
    result.os_version = scan_result.host.os_name;
    result.cpe = scan_result.host.cpe;
    result.cpe_detail = scan_result.host.cpe;
    result.ports = open_ports;
  });
};

const validateInput = () => {
  if (!option.target_host) {
    return "Invalid host";
  }
  if (isValidIPaddress(option.target_host) || isValidHostname(option.target_host)) {
    return "OK";
  }else{
    return "Invalid host";
  }  
}

const clearResult = () => {
  result.ip_addr = "";
  result.host_name = "";
  result.ports = [];
  result.mac_addr = "";
  result.vendor_name = "";
  result.os_name = "";
  result.os_version = "";
  result.cpe = "";
  result.cpe_detail = "";  
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
  clearResult();
  runPortScan();
};

onMounted(() => {
    invoke('test_command_arg', { invokeMessage: 'PortScan' });
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
                <span>Port Scan</span>
                <el-button type="primary" plain @click="clickScan" :loading="scanning" >Scan</el-button>
            </div>
        </template>
        <!-- Header -->
        <!-- Options -->
        <el-row :gutter="20">
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Target</p>
                <el-input v-model="option.target_host" placeholder="Address or Name" />
            </el-col>
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Port</p>
                <el-select v-model="option.port_option" placeholder="Select">
                    <el-option v-for="item in port_options"
                        :key="item.value"
                        :label="item.label"
                        :value="item.value"
                    />
                </el-select>
            </el-col>
            <el-col :span="3">
                <p style="font-size: var(--el-font-size-small)">Port List</p>
                <el-button type="info" plain @click="dialog_list_visible = true">List</el-button>
            </el-col>
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Scan Type</p>
                <el-select v-model="option.scan_type" placeholder="Select">
                    <el-option v-for="item in scanTypeOptions"
                        :key="item.value"
                        :label="item.label"
                        :value="item.value"
                    />
                </el-select>
            </el-col>
        </el-row>
        <el-row :gutter="20">
            <el-col :span="4">
                <el-checkbox v-model="option.async_flag" label="Async" />
            </el-col>
            <el-col :span="4">
                <el-checkbox v-model="option.service_detection_flag" label="Service Detection" />
            </el-col>
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
    <div v-loading="scanning" element-loading-text="Scanning..." class="mt-2">
      <div v-if="result.ip_addr">
        <el-descriptions
            title="Scan Result"
            direction="vertical"
            :column="4"
            border
          >
          <el-descriptions-item label="IP Address">{{ result.ip_addr }}</el-descriptions-item>
          <el-descriptions-item label="Host Name">{{ result.host_name }}</el-descriptions-item>
          <el-descriptions-item label="MAC Address" :span="2">{{ result.mac_addr }}</el-descriptions-item>
          <el-descriptions-item label="OS Name">{{ result.os_name }}</el-descriptions-item>
          <el-descriptions-item label="CPE">{{ result.cpe }}</el-descriptions-item>
        </el-descriptions>

        <el-table :data="result.ports" style="width: 100%" class="mt-2">
          <el-table-column prop="port_number" label="Port No" />
          <el-table-column prop="port_status" label="Status"  />
          <el-table-column prop="service_name" label="Service Name" />
          <el-table-column prop="service_version" label="Service Version" />
        </el-table>
      </div>
      <div v-else>
        <el-descriptions
            title="Scan Result"
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
    <!-- Results -->

    <!-- Dialog -->
    <el-dialog v-model="dialog_list_visible" title="Custom Port List">
      <el-tag
        v-for="tag in port_tags"
        :key="tag"
        class="mx-1"
        closable
        :disable-transitions="false"
        @close="handleTagClose(tag)"
      >
        {{ tag }}
      </el-tag>
      <el-input 
        type="number" 
        min="1" 
        max="65535"
        v-if="tag_input_visible"
        ref="tag_input_ref"
        v-model="tag_input_value"
        class="ml-1 w-20"
        size="small"
        @keyup.enter="handleInputConfirm"
        @blur="handleInputConfirm"
      />
      <el-button v-else class="button-new-tag ml-1" size="small" @click="showTagInput">
        + New Port
      </el-button>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="dialog_list_visible = false">Close</el-button>
        </span>
      </template>
    </el-dialog>
    <!-- Dialog -->
</template>

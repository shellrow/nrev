<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { ElMessage, ElInput } from 'element-plus';
import { PORT_OPTION_DEFAULT, PORT_OPTION_WELL_KNOWN, PORT_OPTION_CUSTOM_LIST, PORTSCAN_TYPE_TCP_SYN, PORTSCAN_TYPE_TCP_CONNECT, OS_TYPE_WINDOWS } from '../config/define';
import { isIpv4NetworkAddress, isIpv6NetworkAddress, isValidHostname, isValidIPaddress } from '../logic/shared';
import { useRoute } from 'vue-router';

type ServiceInfo = {
  port_number: number,
  port_status: string,
  service_name: string,
  service_version: string,
  cpe: string,
  remark: string,
};

type NodeInfo = {
  ip_addr: string,
  host_name: string,
  ttl: number,
  mac_addr: string,
  vendor_info: string,
  os_name: string,
  cpe: string,
  services: ServiceInfo[],
  node_type: string,
};

type PortScanResult = {
  probe_id: string,
  nodes: NodeInfo[],
  probe_status: string,
  start_time: string,
  end_time: string,
  elapsed_time: number,
  protocol: string,
  command_type: string,
  scan_type: string,
}

interface Option {
  target_host: string;
  port_option: string;
  ports: number[];
  scan_type: string;
  async_flag: boolean;
  service_detection_flag: boolean;
  os_detection_flag: boolean;
  randomize_flag: boolean;
  save_flag: boolean;
}

interface UiResult {
  ip_addr: string;
  host_name: string;
  ports: ServiceInfo[];
  mac_addr: string;
  vendor_name: string;
  os_name: string;
  os_version: string;
  cpe: string;
  cpe_detail: string;
}

const scanning = ref(false);
const dialog_list_visible = ref(false);
const route = useRoute();

//Port Tags
const tag_input_value = ref<string>('');
const port_tags = ref<string[]>([]);
const tag_input_visible = ref(false);
const tag_input_ref = ref<InstanceType<typeof ElInput>>();

const handleTagClose = (tag: any) => {
  port_tags.value.splice(port_tags.value.indexOf(tag), 1);
};

const showTagInput = () => {
  tag_input_visible.value = true;
  nextTick(() => {
    tag_input_ref.value!.input!.focus();
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

const option: Option = reactive({
    target_host: "",
    port_option: PORT_OPTION_DEFAULT,
    ports:[],
    scan_type: PORTSCAN_TYPE_TCP_SYN,
    async_flag: true,
    service_detection_flag: true,
    os_detection_flag: true,
    randomize_flag: true,
    save_flag: false,
});

const result: UiResult = reactive({
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
    label: 'Default 1000 ports',
  },
  {
    value: PORT_OPTION_WELL_KNOWN,
    label: 'Well-Known 685 ports',
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

const getOsType = async() => {
  const os_type = await invoke('get_os_type');
  return os_type;
};

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
    randomize_flag: option.randomize_flag,
    save_flag: option.save_flag,
  };
  invoke<PortScanResult>('exec_portscan', { "opt": opt }).then((scan_result) => {
    scanning.value = false;
    let open_ports: ServiceInfo[] = [];
    let node = scan_result.nodes[0];
    node.services.forEach(service => {
      if (service.port_status === "Open"){
        open_ports.push(service);
      }
    });
    result.ip_addr = node.ip_addr;
    result.host_name = node.host_name;
    result.mac_addr = node.mac_addr;
    result.vendor_name = node.vendor_info;
    result.os_name = node.os_name;
    result.os_version = node.os_name;
    result.cpe = node.cpe;
    result.cpe_detail =node.cpe;
    result.ports = open_ports;
  });
};

const validateInput = async() => {
  if (!option.target_host) {
    return "TargetHost is required";
  }
  const os_type = await getOsType();
  if (os_type === OS_TYPE_WINDOWS) {
    if (option.async_flag && option.scan_type === PORTSCAN_TYPE_TCP_SYN) {
      return "Async TCP SYN Scan is not supported on Windows";
    }
  }
  if (isValidIPaddress(option.target_host) || isValidHostname(option.target_host)) {
    if (isIpv4NetworkAddress(option.target_host)) {
      return "Invalid host (network address)";
    }
    if (isIpv6NetworkAddress(option.target_host)) {
      return "Invalid host (network address)";
    }
    return "OK";
  }else {
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

const clickScan = (event: any) => {
  validateInput().then((inputStatus) => {
    if (inputStatus != "OK") {
      ElMessage({
        message: inputStatus,
        type: 'warning',
      })
      return;
    }
    clearResult();
    runPortScan();
  });
};

onMounted(() => {
  if (route.params.host) {
    option.target_host = route.params.host.toString();
  }
  getOsType().then((os_type) => {
    if (os_type === OS_TYPE_WINDOWS) {
      option.async_flag = false;
    }
  });
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
                <span>Port Scan</span>
                <el-button type="primary" plain @click="clickScan" :loading="scanning" >Scan</el-button>
            </div>
        </template>
        <!-- Header -->
        <!-- Options -->
        <el-row>
          <el-form :inline="true" label-position="top">
            <el-form-item label="TargetHost">
              <el-input v-model="option.target_host" placeholder="IP Address or HostName" style="max-width: 300px;" />
            </el-form-item>
            <el-form-item label="Port">
              <el-select v-model="option.port_option" placeholder="Select" style="max-width: 200px;">
                  <el-option v-for="item in port_options"
                      :key="item.value"
                      :label="item.label"
                      :value="item.value"
                  />
              </el-select>
            </el-form-item>
            <el-form-item label="Port List">
              <el-button type="info" plain @click="dialog_list_visible = true">List</el-button>
            </el-form-item>
            <el-form-item label="Scan Type">
              <el-select v-model="option.scan_type" placeholder="Select" style="max-width: 180px;">
                  <el-option v-for="item in scanTypeOptions"
                      :key="item.value"
                      :label="item.label"
                      :value="item.value"
                  />
              </el-select>
            </el-form-item>
          </el-form>
        </el-row>
        <el-row :gutter="20">
            <el-col :span="16">
              <el-checkbox v-model="option.async_flag" label="Async" />
              <el-checkbox v-model="option.service_detection_flag" label="Service Detection" />
              <el-checkbox v-model="option.os_detection_flag" label="OS Detection" />
              <el-checkbox v-model="option.randomize_flag" label="Randomize Order" />
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
          <el-table-column prop="port_number" label="Port No" width="100" />
          <el-table-column prop="port_status" label="Status" width="120" />
          <el-table-column prop="service_name" label="Service Name" width="200" />
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

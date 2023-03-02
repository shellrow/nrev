<script setup>
import { ref, reactive, onMounted, onUnmounted, nextTick } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';
import {sleep, isValidIPaddress, isValidHostname} from '../logic/shared.js';
import {PROTOCOL_ICMPv4, PROTOCOL_TCP, HOSTSCAN_TYPE_NETWORK, HOSTSCAN_TYPE_CUSTOM_HOSTS} from '../define.js';

const scanning = ref(false);
const dialog_list_visible = ref(false);
const target_host = ref("");
const target_hosts = ref([]);

const option = reactive({
  network_address: "",
  prefix_len: 24,
  protocol: "ICMPv4",
  port: 0,
  target_hosts:[],
  scan_type: "network",
  async_flag: true,
  dsn_lookup_flag: true,
  os_detection_flag: true,
  save_flag: false,
});

const result = reactive({
  hosts: [],
  host_scan_time: "",
  lookup_time: "",
  total_scan_time: "",
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
];

const scan_type_options = [
  {
    value: HOSTSCAN_TYPE_NETWORK,
    label: 'Network',
  },
  {
    value: HOSTSCAN_TYPE_CUSTOM_HOSTS,
    label: 'Custom List',
  },
];

const addTargetHost = () => {
    if (target_host.value) {
        let target = {ip_addr: target_host.value, host_name: target_host.value};
        if (isValidIPaddress(target_host.value)) {
            invoke('lookup_ipaddr',{ipaddr:target_host.value}).then((hostname) => {
                target.host_name = hostname; 
                if (!target_hosts.value.includes(target)){
                    target_hosts.value.push(target);
                }
            });
        }else{
            if (isValidHostname(target_host.value)){
                invoke('lookup_hostname',{hostname:target_host.value}).then((ip_addr) => {
                    target.ip_addr = ip_addr;
                    if (!target_hosts.value.includes(target)){
                        target_hosts.value.push(target);
                    }
                });
            }
        }
        option.target_hosts.push(target.ip_addr);
    }
    target_host.value = "";
};

const deleteRow = (index) => {
    target_hosts.value.splice(index, 1);
    option.target_hosts.splice(index, 1);
}

const runHostScan = async() => {
    scanning.value = true;
    const opt = {
        network_address: option.network_address,
        prefix_len: option.prefix_len,
        protocol: option.protocol,
        port: option.port,
        target_hosts: option.target_hosts,
        scan_type: option.scan_type,
        async_flag: option.async_flag,
        dsn_lookup_flag: option.dsn_lookup_flag,
        os_detection_flag: option.os_detection_flag,
        save_flag: option.save_flag,
    };
    invoke('exec_hostscan', { "opt": opt }).then((scan_result) => {
        scanning.value = false;
        console.log(scan_result);
        result.hosts = scan_result.hosts;
        const host_scan_time = parseFloat(`${scan_result.host_scan_time.secs}.${scan_result.host_scan_time.nanos}`);
        const lookup_time = parseFloat(`${scan_result.lookup_time.secs}.${scan_result.lookup_time.nanos}`);
        result.host_scan_time = host_scan_time.toFixed(4);
        result.lookup_time = lookup_time.toFixed(4);
        result.total_scan_time = (host_scan_time + lookup_time).toFixed(4);
        console.log(result);
    });
};

const clickScan = (event) => {
  runHostScan();
};

onMounted(() => {
    invoke('test_command_arg', { invokeMessage: 'HostScan' });
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
                <span>Host Scan</span>
                <el-button type="primary" plain @click="clickScan" :loading="scanning" >Scan</el-button>
            </div>
        </template>
        <!-- Header -->
        <!-- Options -->
        <el-row :gutter="20">
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Network Address</p>
                <el-input v-model="option.network_address" placeholder="IP Address" />
            </el-col>
            <el-col :span="3">
                <p style="font-size: var(--el-font-size-small)">Prefix</p>
                <el-input type="number" min="8" max="30" v-model="option.prefix_len" placeholder="24" />
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
            <el-col :span="4">
                <p style="font-size: var(--el-font-size-small)">Scan Type</p>
                <el-select v-model="option.scan_type" placeholder="Select">
                    <el-option v-for="item in scan_type_options"
                        :key="item.value"
                        :label="item.label"
                        :value="item.value"
                    />
                </el-select>
            </el-col>
            <el-col :span="4">
                <p style="font-size: var(--el-font-size-small)">Host List</p>
                <el-button type="info" plain @click="dialog_list_visible = true">List</el-button>
            </el-col>
        </el-row>
        <el-row :gutter="20">
            <el-col :span="4">
                <el-checkbox v-model="option.async_flag" label="Async" />
            </el-col>
            <el-col :span="4">
                <el-checkbox v-model="option.dsn_lookup_flag" label="DNS Lookup" />
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
        <div v-if="result.hosts.length > 0">
            <el-descriptions
                title="Scan Result"
                direction="vertical"
                :column="4"
                border
            >
            </el-descriptions>
            <el-table :data="result.hosts" style="width: 100%" class="mt-2">
                <el-table-column prop="ip_addr" label="IP Address" />
                <el-table-column prop="host_name" label="Host Name"  />
                <el-table-column prop="os_name" label="OS Name" />
                <el-table-column prop="mac_addr" label="MAC Address" />
                <el-table-column prop="vendor_info" label="Vendor Info" />
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
    <el-dialog v-model="dialog_list_visible" title="Custom Host List">
        <el-row :gutter="20">
            <el-col :span="6">
                <el-input v-model="target_host" placeholder="IP Address or Host Name" @keyup.enter="addTargetHost" @blur="addTargetHost" />
            </el-col>
            <el-col :span="6">
                <el-button type="info" plain @click="addTargetHost">Add</el-button>
            </el-col>
        </el-row>
        <el-table :data="target_hosts">
            <el-table-column property="ip_addr" label="IP Address" />
            <el-table-column property="host_name" label="Host Name" />
            <el-table-column fixed="right" label="Operations" width="120">
                <template #default="scope">
                    <el-button type="danger" size="small" @click.prevent="deleteRow(scope.$index)">
                        Remove
                    </el-button>
                </template>
            </el-table-column>
        </el-table>
        <template #footer>
            <span class="dialog-footer">
                <el-button @click="dialog_list_visible = false">Close</el-button>
            </span>
        </template>
    </el-dialog>
    <!-- Dialog -->
</template>
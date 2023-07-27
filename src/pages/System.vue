<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import {Refresh} from '@element-plus/icons-vue';

interface NetworkInterface {
    index: number;
    name: string;
    friendly_name: string;
    description: string;
    if_type: string;
    mac_addr: string;
    ipv4: string[];
    ipv4_csv: string;
    ipv6: string[];
    ipv6_csv: string;
    gateway_mac_addr: string;
    gateway_ip_addr: string;
}

const network_interface: NetworkInterface = reactive({
    index: 0,
    name: '',
    friendly_name: '',
    description: '',
    if_type: '',
    mac_addr: '',
    ipv4: [],
    ipv4_csv: '',
    ipv6: [],
    ipv6_csv: '',
    gateway_mac_addr: '',
    gateway_ip_addr: '',
});

const getIpv4Csv = () => {
    return network_interface.ipv4.join(',\n');
}

const getIpv6Csv = () => {
    return network_interface.ipv6.join(',\n');
}

function reloadSysInfo() {
    getNetworkInfo();
}

type NetworkInterfaceModel = {
    index: number;
    name: string;
    friendly_name: string;
    description: string;
    if_type: string;
    mac_addr: string;
    ipv4: string[];
    ipv6: string[];
    gateway_mac_addr: string;
    gateway_ip_addr: string;
}

function getNetworkInfo() {
    invoke<NetworkInterfaceModel>('get_default_interface').then((res) => {
        network_interface.index = res.index;
        network_interface.name = res.name;
        network_interface.friendly_name = res.friendly_name;
        network_interface.description = res.description;
        network_interface.if_type = res.if_type;
        network_interface.mac_addr = res.mac_addr;
        network_interface.ipv4 = res.ipv4;
        network_interface.ipv6 = res.ipv6;
        network_interface.gateway_mac_addr = res.gateway_mac_addr;
        network_interface.gateway_ip_addr = res.gateway_ip_addr;
        console.log(network_interface);
    }).catch((err) => {
        console.log(err);
    }).finally(() => {
        
    });
}

onMounted(() => {
    reloadSysInfo();
});

onUnmounted(() => {

});

</script>

<style scoped>
.el-row {
  margin-bottom: 20px;
}

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
                <span>Network Interface</span>
                <div>
                    <el-button type="primary" plain @click="reloadSysInfo"><el-icon><Refresh /></el-icon></el-button>
                </div>
            </div>
        </template>
        <!-- Header -->
        <!-- Content -->
        <el-descriptions
        class="margin-top"
        title=""
        :column="1"
        size="small"
        border
        >
            <el-descriptions-item width="120px">
                <template #label>
                    <div class="cell-item">
                    Index
                    </div>
                </template>
                {{ network_interface.index }}
            </el-descriptions-item>
            <el-descriptions-item>
                <template #label>
                    <div class="cell-item">
                    Name
                    </div>
                </template>
                {{ network_interface.name }}
            </el-descriptions-item>
            <el-descriptions-item>
                <template #label>
                    <div class="cell-item">
                    Friendly Name
                    </div>
                </template>
                {{ network_interface.friendly_name }}
            </el-descriptions-item>
            <el-descriptions-item>
                <template #label>
                    <div class="cell-item">
                    Interface Type
                    </div>
                </template>
                {{ network_interface.if_type }}
            </el-descriptions-item>
            <el-descriptions-item>
                <template #label>
                    <div class="cell-item">
                    MAC Address
                    </div>
                </template>
                {{ network_interface.mac_addr }}
            </el-descriptions-item>
            <el-descriptions-item>
                <template #label>
                    <div class="cell-item">
                    IPv4 Address
                    </div>
                </template>
                {{ getIpv4Csv() }}
            </el-descriptions-item>
            <el-descriptions-item>
                <template #label>
                    <div class="cell-item">
                    IPv6 Address
                    </div>
                </template>
                {{ getIpv6Csv() }}
            </el-descriptions-item>
            <el-descriptions-item>
                <template #label>
                    <div class="cell-item">
                    Gateway MAC Address
                    </div>
                </template>
                {{ network_interface.gateway_mac_addr }}
            </el-descriptions-item>
            <el-descriptions-item>
                <template #label>
                    <div class="cell-item">
                    Gateway IP Address
                    </div>
                </template>
                {{ network_interface.gateway_ip_addr }}
            </el-descriptions-item>
        </el-descriptions>
        <!-- Content -->
    </el-card>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { Refresh } from '@element-plus/icons-vue';

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
    gateway_ipv4: string;
    gateway_ipv6: string;
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
    gateway_ipv4: string;
    gateway_ipv6: string;
}

type UserSetting = {
    setting_id: string;
    setting_value: string;
}

const defaultInterfaceIndex = ref<number>(0);
const selectedInterfaceIndex = ref<number>(0);
const interfaceOptions = ref<NetworkInterfaceModel[]>([]);

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
    gateway_ipv4: '',
    gateway_ipv6: '',
});

const getIpv4Csv = () => {
    return network_interface.ipv4.join(',\n');
}

const getIpv6Csv = () => {
    return network_interface.ipv6.join(',\n');
}

function reloadSysInfo() {
    getNetworkInfo();
    setNetworkInterfaces();
}

function setNetworkInterfaces() {
    invoke<NetworkInterfaceModel[]>('get_interfaces').then((res) => {
        interfaceOptions.value = res;
        // if default interface, set interface name to <if_name>(Default) 
        interfaceOptions.value.forEach((item) => {
            if (item.index === defaultInterfaceIndex.value) {
                item.name = item.name + ' (Default)';
            }
        });
        if (selectedInterfaceIndex.value === 0) {
            selectedInterfaceIndex.value = network_interface.index;
        }
    }).catch((e) => {
        console.log(e);
    }).finally(() => {
        
    });
}

function saveNetworkInterfaceSetting() {
    const setting: UserSetting = {
        setting_id: 'network_interface_index',
        setting_value: selectedInterfaceIndex.value.toString(),
    };
    invoke<NetworkInterfaceModel>('set_user_setting', { setting }).then((res) => {
        //console.log(res);
    }).catch((e) => {
        console.log(e);
    }).finally(() => {
        
    });
}

function selectNetworkInterface(interface_index: number) {
    invoke<NetworkInterfaceModel>('get_interface_by_index', { ifIndex: interface_index }).then((res) => {
        network_interface.index = res.index;
        network_interface.name = res.name;
        network_interface.friendly_name = res.friendly_name;
        network_interface.description = res.description;
        network_interface.if_type = res.if_type;
        network_interface.mac_addr = res.mac_addr;
        network_interface.ipv4 = res.ipv4;
        network_interface.ipv6 = res.ipv6;
        network_interface.gateway_mac_addr = res.gateway_mac_addr;
        network_interface.gateway_ipv4 = res.gateway_ipv4;

        //selectedInterfaceIndex.value = network_interface.index;
        saveNetworkInterfaceSetting();

    }).catch((e) => {
        console.log(e);
    }).finally(() => {
        
    });
}

function setDefaultInterfaceIndex() {
    invoke<NetworkInterfaceModel>('get_default_interface').then((res) => {
        defaultInterfaceIndex.value = res.index;
    }).catch((e) => {
        console.log(e);
    }).finally(() => {
    });
}

function selectDefaultNetworkInterface() {
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
        network_interface.gateway_ipv4 = res.gateway_ipv4;

        selectedInterfaceIndex.value = network_interface.index;
        saveNetworkInterfaceSetting();

    }).catch((e) => {
        console.log(e);
    }).finally(() => {

    });
}

function getNetworkInfo() {
    setDefaultInterfaceIndex();
    const setting_id = 'network_interface_index';
    invoke<UserSetting>('get_user_setting', { settingId: setting_id }).then((res) => {
        if (res.setting_value === '' || res.setting_value === '0') {
            selectDefaultNetworkInterface();
        } else {
            selectedInterfaceIndex.value = parseInt(res.setting_value);
            selectNetworkInterface(selectedInterfaceIndex.value);
        }
    }).catch((e) => {
        console.log(e);
    }).finally(() => {
        
    });
}

const setNetworkInterface = () => {
    selectNetworkInterface(selectedInterfaceIndex.value);
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
                <span>Network</span>
                <div>
                    <el-button type="primary" plain @click="reloadSysInfo" size="small"><el-icon><Refresh /></el-icon></el-button>
                </div>
            </div>
        </template>
        <!-- Header -->
        <!-- Content -->
        <div class="card-header mb-1">
            <span>Interface</span>
            <el-select v-model="selectedInterfaceIndex" placeholder="Select" size="small" @change="setNetworkInterface">
                <el-option v-for="item in interfaceOptions"
                    :key="item.index"
                    :label="item.name"
                    :value="item.index"
                />
            </el-select>
        </div>
        <el-descriptions
        class="margin-top"
        title=""
        :column="1"
        size="small"
        border
        >
            <el-descriptions-item width="150px">
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
            <el-descriptions-item v-if="network_interface.friendly_name">
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
                    Gateway IPv4 Address
                    </div>
                </template>
                {{ network_interface.gateway_ipv4 }}
            </el-descriptions-item>
            <el-descriptions-item v-if="network_interface.gateway_ipv6">
                <template #label>
                    <div class="cell-item">
                    Gateway IPv6 Address
                    </div>
                </template>
                {{ network_interface.gateway_ipv6 }}
            </el-descriptions-item>
        </el-descriptions>
        <!-- Content -->
    </el-card>
</template>

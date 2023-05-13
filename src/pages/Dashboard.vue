<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';
import {Refresh, ElementPlus} from '@element-plus/icons-vue';

const activities = ref([]);
const probe_stat = reactive({
    portscan_count: 0,
    hostscan_count: 0,
    ping_count: 0,
    traceroute_count: 0,
});

function setProbeStat() {
    invoke('get_probe_stat').then((res) => {
        probe_stat.portscan_count = res.portscan_count;
        probe_stat.hostscan_count = res.hostscan_count;
        probe_stat.ping_count = res.ping_count;
        probe_stat.traceroute_count = res.traceroute_count;
    }).catch((err) => {
        console.log(err);
    }).finally(() => {
        
    });
}

function setRecentActivities() {
    activities.value = [];
    invoke('get_top_probe_hist').then((res) => {
        res.forEach((log) => {
            activities.value.push({
                content: `[${log.probe_id}] [${log.probe_type_name}] ${log.probe_target_name} ${log.probe_target_addr}` ,
                timestamp: log.issued_at,
            });
        });
    }).catch((err) => {
        console.log(err);
    }).finally(() => {
        
    });
}

function reloadDashboard() {
    setRecentActivities();
    setProbeStat();
}

onMounted(() => {
    reloadDashboard();
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
    <!-- Header -->
    <el-card class="box-card" style="margin-bottom: 20px;">
        <div class="card-header">
            <span>Dashboard</span>
            <div>
            <el-button type="primary" plain @click="reloadDashboard"><el-icon><Refresh /></el-icon></el-button>
            </div>
        </div>
    </el-card>
    <!-- Header -->
    <!-- Contents-->
    <el-row :gutter="10">
        <el-col :span="24">
            <el-card class="box-card">
                <template #header>
                <div class="card-header">
                    <span>Probe</span>
                    <el-button class="button" text><router-link to="/map">Go to map</router-link></el-button>
                </div>
                </template>
                <el-row :gutter="10">
                    <el-col :span="6">
                        <el-card class="box-card">
                            <el-result title="PortScan" :sub-title="`Count: ${probe_stat.portscan_count}`">
                                <template #icon>
                                    <span></span>
                                </template>
                                <template #extra>
                                <el-button type="primary" plain><router-link to="/port">Start</router-link></el-button>
                                </template>
                            </el-result>
                        </el-card>
                    </el-col>
                    <el-col :span="6">
                        <el-card class="box-card">
                            <el-result title="HostScan" :sub-title="`Count: ${probe_stat.hostscan_count}`">
                                <template #icon>
                                    <span></span>
                                </template>
                                <template #extra>
                                <el-button type="primary" plain><router-link to="/host">Start</router-link></el-button>
                                </template>
                            </el-result>
                        </el-card>
                    </el-col>
                    <el-col :span="6">
                        <el-card class="box-card">
                            <el-result title="Ping" :sub-title="`Count: ${probe_stat.ping_count}`">
                                <template #icon>
                                    <span></span>
                                </template>
                                <template #extra>
                                <el-button type="primary" plain><router-link to="/ping">Start</router-link></el-button>
                                </template>
                            </el-result>
                        </el-card>
                    </el-col>
                    <el-col :span="6">
                        <el-card class="box-card">
                            <el-result title="Traceroute" :sub-title="`Count: ${probe_stat.traceroute_count}`">
                                <template #icon>
                                    <span></span>
                                </template>
                                <template #extra>
                                <el-button type="primary" plain><router-link to="/trace">Start</router-link></el-button>
                                </template>
                            </el-result>
                        </el-card>
                    </el-col>
                </el-row>
            </el-card>
        </el-col>
    </el-row>
    <el-row :gutter="10">
        <el-col :span="24">
            <el-card class="box-card">
                <template #header>
                <div class="card-header">
                    <span>Timeline - Recent activities</span>
                    <el-button class="button" text><router-link to="/log">View full log</router-link></el-button>
                </div>
                </template>
                <el-timeline>
                    <el-timeline-item
                    v-for="(activity, index) in activities"
                    :key="index"
                    :timestamp="activity.timestamp"
                    >
                    {{ activity.content }}
                    </el-timeline-item>
                </el-timeline>
            </el-card>
        </el-col>
    </el-row>
    <!-- Contents-->
</template>

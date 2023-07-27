<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { Refresh, View, RefreshRight, Position, Share } from '@element-plus/icons-vue';

const innerWidth = ref(window.innerWidth);
const innerHeight = ref(window.innerHeight);
const checkWindowSize = () => {
    innerWidth.value = window.innerWidth;
    innerHeight.value = window.innerHeight;
};

type ProbeLog = {
    id: number,
    probe_id: string,
    probe_type_id: string,
    probe_type_name: string,
    probe_target_addr: string,
    probe_target_name: string,
    protocol_id: string,
    probe_option: string,
    issued_at: string,
};

type Activity = {
    content: string,
    timestamp: string,
};

const activities = ref<Activity[]>([]);

function setRecentActivities() {
    activities.value = [];
    invoke<Array<ProbeLog>>('get_top_probe_hist').then((res) => {
        res.forEach((log) => {
            activities.value.push({
                content: `[${log.id}] ${log.probe_type_name} ${log.probe_target_name} ${log.probe_target_addr}` ,
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
}

onMounted(() => {
    reloadDashboard();
    window.addEventListener('resize', checkWindowSize);
});

onUnmounted(() => {
    window.removeEventListener('resize', checkWindowSize);
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

.shortcut-container {
    max-height: 150px;
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
                            <el-result title="PortScan" sub-title="" class="shortcut-container">
                                <template #icon>
                                    <el-icon size="30"><View /></el-icon>
                                </template>
                                <template #extra>
                                <el-button type="primary" plain><router-link to="/port">Start</router-link></el-button>
                                </template>
                            </el-result>
                        </el-card>
                    </el-col>
                    <el-col :span="6">
                        <el-card class="box-card">
                            <el-result title="HostScan" sub-title="" class="shortcut-container">
                                <template #icon>
                                    <el-icon size="30"><RefreshRight /></el-icon>
                                </template>
                                <template #extra>
                                <el-button type="primary" plain><router-link to="/host">Start</router-link></el-button>
                                </template>
                            </el-result>
                        </el-card>
                    </el-col>
                    <el-col :span="6">
                        <el-card class="box-card">
                            <el-result title="Ping" sub-title="" class="shortcut-container">
                                <template #icon>
                                    <el-icon size="30"><Position /></el-icon>
                                </template>
                                <template #extra>
                                <el-button type="primary" plain><router-link to="/ping">Start</router-link></el-button>
                                </template>
                            </el-result>
                        </el-card>
                    </el-col>
                    <el-col :span="6">
                        <el-card class="box-card">
                            <el-result title="Traceroute" sub-title="" class="shortcut-container">
                                <template #icon>
                                    <el-icon size="30"><Share /></el-icon>
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
                <el-scrollbar :height="innerHeight-500+'px'" >
                    <el-timeline>
                        <el-timeline-item
                        v-for="(activity, index) in activities"
                        :key="index"
                        :timestamp="activity.timestamp"
                        >
                        {{ activity.content }}
                        </el-timeline-item>
                    </el-timeline>
                </el-scrollbar>
            </el-card>
        </el-col>
    </el-row>
    <!-- Contents-->
</template>

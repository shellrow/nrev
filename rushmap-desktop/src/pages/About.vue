<script setup lang="ts">
import { reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';

const about_app = reactive({
    name: 'RushMap Desktop',
    version: 'v0.9.0',
    release_date: '2023-12-29',
    author: 'shellrow <shellrow@intsigma.com>',
    description: 'The Simple and High-Performance Network Mapper for discovery and management.',
    repository: 'https://github.com/shellrow/rushmap',
});

type AppInfo = {
    name: string;
    description: string;
    version: string;
    release_date: string;
    repository: string;
}

const getAppInfo = () => {
    invoke<AppInfo>('get_app_info').then((res) => {
        //about_app.name = res.name;
        about_app.description = res.description;
        about_app.version = `v${res.version}`;
        about_app.release_date = res.release_date;
        about_app.repository = res.repository;
    }).catch((err) => {
        console.log(err);
    }).finally(() => {
        
    });
}

onMounted(() => {
    getAppInfo();
});

onUnmounted(() => {

});

</script>

<template>
<el-descriptions :title="about_app.name" :column="1" size="small" border>
    <template #extra>
        <!-- <el-button type="primary">Check for Update</el-button> -->
    </template>
    <el-descriptions-item label="Version" label-class-name="field-label" width="80px">
        <el-tag size="small">{{ about_app.version }}</el-tag>
    </el-descriptions-item>
    <el-descriptions-item label="Release Date">{{ about_app.release_date }}</el-descriptions-item>
    <el-descriptions-item label="Author">{{ about_app.author }}</el-descriptions-item>
    <el-descriptions-item label="Description">{{ about_app.description }}</el-descriptions-item>
    <el-descriptions-item label="Repository">{{ about_app.repository }}</el-descriptions-item>
</el-descriptions> 
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';

const about_app = reactive({
    name: 'NetProbe',
    version: 'v0.1.0',
    release_date: '2023-07-24',
    author: 'shellrow <shellrow@protonmail.com>',
    description: 'The Simple and High-Performance Network Mapper. Optimized for efficient network discovery and management.',
    repository: 'https://github.com/shellrow/netprobe',
});

onMounted(() => {

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

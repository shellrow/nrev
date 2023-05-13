<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';

const about_app = reactive({
    name: 'NesMap',
    version: 'v0.1.0',
    release_date: '2023-04-28',
    author: 'shellrow <shellrow@protonmail.com>',
    description: 'Cross-platform network mapper',
    repository: 'https://github.com/shellrow/nesmap',
});

onMounted(() => {

});

onUnmounted(() => {

});

</script>

<template>
<el-descriptions :title="about_app.name" :column="1" border>
    <template #extra>
        <el-button type="primary">Check for Update</el-button>
    </template>
    <el-descriptions-item label="Version">
        <el-tag size="small">{{ about_app.version }}</el-tag>
    </el-descriptions-item>
    <el-descriptions-item label="Release Date">{{ about_app.release_date }}</el-descriptions-item>
    <el-descriptions-item label="Author">{{ about_app.author }}</el-descriptions-item>
    <el-descriptions-item label="Description">{{ about_app.description }}</el-descriptions-item>
    <el-descriptions-item label="Repository">{{ about_app.repository }}</el-descriptions-item>
</el-descriptions> 
</template>

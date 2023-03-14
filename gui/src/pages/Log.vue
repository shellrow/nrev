<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';

const searching = ref(false);

const searchResult = ref([]);

const searchLog = async () => {
    searching.value = true;
    invoke('get_probe_log').then((results) => {
        searchResult.value = results;
        searching.value = false;
    });
}

const clickSearch = (event) => {
    searchLog();
}

onMounted(() => {
    invoke('test_command_arg', { invokeMessage: 'Log' });
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
                <span>Log</span>
                <el-button type="primary" plain @click="clickSearch" :loading="searching" >Search</el-button>
            </div>
        </template>
        <!-- Header -->
    </el-card>
    <div v-loading="searching" element-loading-text="Searching..." class="mt-2">
        <div v-if="searchResult.length > 0">
            <el-descriptions
                title="Search Result"
                direction="vertical"
                :column="4"
                border
            >
            </el-descriptions>
            <el-table :data="searchResult" style="width: 100%" class="mt-2">
                <el-table-column prop="id" label="ID">
                    <template #default="scope">
                        <el-popover effect="light" trigger="hover" placement="top" width="auto">
                            <template #default>
                                <div>{{ scope.row.probe_id }}</div>
                            </template>
                            <template #reference>
                                <el-tag>{{ scope.row.id }}</el-tag>
                            </template>
                        </el-popover>
                    </template>
                </el-table-column>
                <el-table-column prop="probe_type" label="Probe Type"  />
                <el-table-column prop="probe_target_addr" label="Target Addr" />
                <el-table-column prop="probe_target_name" label="Target Name" />
                <el-table-column prop="protocol_id" label="Protocol" />
                <el-table-column prop="issued_at" label="Issued At" />
            </el-table>
        </div>
        <div v-else>
            <el-descriptions
              title="Search Result"
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
</template>

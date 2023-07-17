<script lang="ts" setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { save, open } from "@tauri-apps/api/dialog";
import { writeTextFile, readTextFile } from "@tauri-apps/api/fs";
import { debounce } from 'lodash';
import { ElMessage, ElTable } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';

const innerWidth = ref(window.innerWidth);
const innerHeight = ref(window.innerHeight);
const checkWindowSize = () => {
    innerWidth.value = window.innerWidth;
    innerHeight.value = window.innerHeight;
};

const dialogVisible = ref(false);
const tableRef = ref<InstanceType<typeof ElTable>>();
const multipleTableRef = ref<InstanceType<typeof ElTable>>();
const multipleSelection = ref<Host[]>([]);
const toggleSelection = (rows?: Host[]) => {
  if (rows) {
    rows.forEach((row) => {
      multipleTableRef.value!.toggleRowSelection(row, true)
    })
  } else {
    multipleTableRef.value!.clearSelection()
  }
}
const handleSelectionChange = (val: Host[]) => {
  multipleSelection.value = val
}

type Service = {
  host_id: string
  port: number
  protocol: string
  name: string
  version: string,
  cpe: string
}

type Host = {
  host_id: string
  ip_addr: string
  host_name: string
  mac_addr: string
  vendor_name: string
  os_cpe: string
  os_name: string
  services?: Service[]
}

type UserHost = {
  host_id: string
  ip_addr: string
  host_name: string
  mac_addr: string
  vendor_name: string
  os_cpe: string
  os_name: string
}

const tdHosts = ref<Host[]>([]);
const tdSelectedHosts = ref<Host[]>([]);

const targetHost = ref("");

const clickTemp = () => {
  console.log("click temp");
}

const loadHosts = () => {
  tdHosts.value.splice(0, tdHosts.value.length);
  invoke<Array<UserHost>>("get_user_hosts").then((res) => {
    res.forEach((user_host) => {
      tdHosts.value.push({
        host_id: user_host.host_id,
        ip_addr: user_host.ip_addr,
        host_name: user_host.host_name,
        mac_addr: user_host.mac_addr,
        vendor_name: user_host.vendor_name,
        os_cpe: user_host.os_cpe,
        os_name: user_host.os_name,
        services: []
      });
    });
  });
}

const loadSelectedHosts = () => {
  tdSelectedHosts.value.splice(0, tdSelectedHosts.value.length);
  invoke<Array<UserHost>>("get_user_hosts").then((res) => {
    res.forEach((user_host) => {
      tdSelectedHosts.value.push({
        host_id: user_host.host_id,
        ip_addr: user_host.ip_addr,
        host_name: user_host.host_name,
        mac_addr: user_host.mac_addr,
        vendor_name: user_host.vendor_name,
        os_cpe: user_host.os_cpe,
        os_name: user_host.os_name,
        services: []
      });
      console.log(user_host.host_id);
    });
  });
}

onMounted(() => {
  loadSelectedHosts();
  loadHosts();
  window.addEventListener('resize', checkWindowSize);
});

onUnmounted(() => {
  window.removeEventListener('resize', checkWindowSize);
});

</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>

<template>
    <el-card class="box-card">
    <!-- Header -->
    <template #header>
        <div class="card-header">
            <span>Map</span>
            <div>
              <el-button type="primary" plain @click="clickTemp"><el-icon><Refresh /></el-icon></el-button>
              <el-button type="primary" plain @click="clickTemp">Save</el-button>
            </div>
        </div>
    </template>
    <!-- Header -->
    <el-row :gutter="10">
      <el-col :span="16">
        <p style="font-size: var(--el-font-size-small)">Host</p>
        <el-row :gutter="10">
          <el-col :span="10">
            <el-input v-model="targetHost" placeholder="Address or Name" @keyup.enter="clickTemp"></el-input>
          </el-col>
          <el-col :span="3">
            <el-button type="primary" plain @click="clickTemp">Add</el-button>
          </el-col>
          <el-col :span="3">
            <el-button type="primary" plain @click="dialogVisible = true">Select</el-button>
          </el-col>
        </el-row>
      </el-col>
    </el-row>
  </el-card>
  <el-table ref="tableRef" :data="tdSelectedHosts" style="width: 100%" class="mt-2" :max-height="innerHeight - 300">
    <el-table-column type="expand">
      <template #default="props">
        <div m="4">
          <el-table :data="props.row.services">
            <el-table-column label="Port" prop="port" />
            <el-table-column label="Protocol" prop="protocol" />
            <el-table-column label="Name" prop="name" />
            <el-table-column label="Version" prop="version" />
            <el-table-column label="CPE" prop="cpe" />
          </el-table>
        </div>
      </template>
    </el-table-column>
    <el-table-column label="IP Address" prop="ip_addr" />
    <el-table-column label="Host Name" prop="host_name" />
    <el-table-column label="OS Name" prop="os_name" />
    <el-table-column label="Actions">
      <template #default="props">
        <el-button size="small" type="primary" plain @click="clickTemp">Probe</el-button>
        <el-button size="small" type="primary" plain @click="clickTemp">Edit</el-button>
        <el-button size="small" type="danger" plain @click="clickTemp">Delete</el-button>
      </template>
    </el-table-column>
  </el-table>
  <!-- Dialog -->
  <el-dialog v-model="dialogVisible" title="Select hosts to display">
    <el-table ref="multipleTableRef" :data="tdHosts" size="small" style="width: 100%" class="mt-2" max-height="250">
      <el-table-column type="selection" width="55" />
      <el-table-column label="IP Address" prop="ip_addr" />
      <el-table-column label="Host Name" prop="host_name" />
      <el-table-column label="Actions">
        <template #default="props">
          <el-button size="small" type="danger" plain @click="clickTemp">Delete</el-button>
        </template>
      </el-table-column>
    </el-table>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="dialogVisible = false">Close</el-button>
      </span>
    </template>
  </el-dialog>
  <!-- Dialog -->
</template>

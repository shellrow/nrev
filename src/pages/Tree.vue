<script lang="ts" setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { save, open } from "@tauri-apps/api/dialog";
import { writeTextFile, readTextFile } from "@tauri-apps/api/fs";
import { debounce } from 'lodash';
import { ElMessage } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';

type Service = {
  host_id: number
  port: number
  protocol: string
  name: string
  version: string,
  cpe: string
}

type Host = {
  host_id: number
  ip_addr: string
  host_name: string
  mac_addr: string
  vendor: string
  os_name: string
  os_cpe: string
  services?: Service[]
}

const tableData: Host[] = [
  {
    host_id: 1,
    ip_addr: "1.1.1.1",
    host_name: "one.one.one.one",
    mac_addr: "",
    vendor: "",
    os_name: "Linux",
    os_cpe: "",
  },
  {
    host_id: 2,
    ip_addr: "8.8.8.8",
    host_name: "dns.google",
    mac_addr: "",
    vendor: "",
    os_name: "Windows",
    os_cpe: "",
  },
  {
    host_id: 3,
    ip_addr: "45.33.32.156",
    host_name: "scanme.nmap.org",
    mac_addr: "",
    vendor: "",
    os_name: "Linux",
    os_cpe: "",
  },
]

const targetHost = ref("");

const clickTemp = () => {
  console.log("click temp");
}

onMounted(() => {
  
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
      <el-col :span="14">
        <p style="font-size: var(--el-font-size-small)">Host</p>
        <el-row :gutter="10">
          <el-col :span="12">
            <el-input v-model="targetHost" placeholder="Address or Name" @keyup.enter="clickTemp"></el-input>
          </el-col>
          <el-col :span="4">
            <el-button type="primary" plain @click="clickTemp">Add Host</el-button>
          </el-col>
        </el-row>
      </el-col>
    </el-row>
  </el-card>
  <el-table :data="tableData" style="width: 100%" class="mt-2">
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
</template>

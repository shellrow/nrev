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

const hostDialogVisible = ref(false);
const selectDialogVisible = ref(false);
const removeDialogVisible = ref(false);
const deleteDialogVisible = ref(false);
const checkDelete = ref(false);
const currentRemoveHostId = ref("");
const currentDeleteHostId = ref("");
const tableRef = ref<InstanceType<typeof ElTable>>();
const multipleTableRef = ref<InstanceType<typeof ElTable>>();
const serviceTableRef = ref<InstanceType<typeof ElTable>>();
const multipleSelection = ref<Host[]>([]);
const toggleSelection = (rows?: Host[]) => {
  if (rows) {
    rows.forEach((row) => {
      multipleTableRef.value!.toggleRowSelection(row, true);
    })
  } else {
    multipleTableRef.value!.clearSelection()
  }
}
const handleSelectionChange = (val: Host[]) => {
  multipleSelection.value = val;
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
  valid_flag: string
}

type UserService = {
  host_id: string
  port: number
  protocol: string
  service_name: string
  service_description: string
  service_cpe: string
}

type UserProbeData = {
  host_id: string,
  host: UserHost,
  services: UserService[],
  groups: string[],
  tags: string[]
}

const tdHosts = ref<Host[]>([]);
const tdSelectedHosts = ref<UserProbeData[]>([]);

const targetHost = ref("");

const currentHost = reactive({
    ip_addr: "",
    host_name: "",
    os_name: "",
    services: [],
});

const clickTemp = () => {
  console.log("click temp");
}

const syncSelection = () => {
  let selectedIds: string[] = [];
  tdSelectedHosts.value.forEach((host) => {
    selectedIds.push(host.host_id);
  });
  tdHosts.value.forEach((host) => {
    if (selectedIds.includes(host.host_id)) {
      toggleSelection([host]);
    }
  });
}

const loadHosts = async () => {
  tdHosts.value.splice(0, tdHosts.value.length);
  await invoke<Array<UserHost>>("get_user_hosts").then((res) => {
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

const loadSelectedHosts = async () => {
  tdSelectedHosts.value.splice(0, tdSelectedHosts.value.length);
  await invoke<Array<UserProbeData>>("get_all_user_probe_data").then((res) => {
    res.forEach((user_host) => {
      tdSelectedHosts.value.push(user_host);
    });
  });
}

const openSelectDialog = () => {
  selectDialogVisible.value = true;
}

const openHostDialog = (event) => {
  hostDialogVisible.value = true;
}

const addUserHost = (event) => {
  console.log(currentHost);
}

const editUserHost = (event) => {

}

const openRemoveDialog = (row) => {
  checkDelete.value = false;
  removeDialogVisible.value = true;
  currentRemoveHostId.value = row.host_id;
}

const openDeleteDialog = (row) => {
  deleteDialogVisible.value = true;
  currentDeleteHostId.value = row.host_id;
}
const closeRemoveDialog = (event) => {
  checkDelete.value = false;
  removeDialogVisible.value = false;
}

const removeUserHost = (event) => {
  if (currentRemoveHostId.value === "") {
    ElMessage.error("Failed to delete host");
    return;
  }
  if (checkDelete.value === true) {
    invoke<number>("delete_user_host", { ids: [currentRemoveHostId.value] }).then((res) => {
      if (res === 0) {
        ElMessage.success("Host deleted successfully");
        loadHosts();
        loadSelectedHosts();
      } else {
        ElMessage.error("Failed to delete host");
      }
    });
  } else {
    invoke<number>("disable_user_host", { ids: [currentRemoveHostId.value] }).then((res) => {
      if (res === 0) {
        ElMessage.success("Host deleted successfully");
        loadHosts();
        loadSelectedHosts();
      } else {
        ElMessage.error("Failed to delete host");
      }
    });
  }
  checkDelete.value = false;
  removeDialogVisible.value = false;
}

const closeDeleteDialog = (event) => {
  deleteDialogVisible.value = false;
}

const deleteUserHost = (event) => {
  invoke<number>("delete_user_host", { ids: [currentDeleteHostId.value] }).then((res) => {
      if (res === 0) {
        ElMessage.success("Host deleted successfully");
        loadHosts();
        loadSelectedHosts();
      } else {
        ElMessage.error("Failed to delete host");
      }
    });
  deleteDialogVisible.value = false;
}

const enableUserHosts = () => {
  //enable_user_host
  let validIds: string[] = [];
  let invalidIds: string[] = [];
  multipleSelection.value.forEach((host) => {
    validIds.push(host.host_id);
  });
  tdHosts.value.forEach((host) => {
    if (!validIds.includes(host.host_id)) {
      invalidIds.push(host.host_id);
    }
  });
  invoke<number>("enable_user_host", { ids: validIds }).then((res) => {
    if (res === 0) {
      invoke<number>("disable_user_host", {ids: invalidIds}).then((res) => {
        if (res === 0) {
          ElMessage.success("Hosts updated successfully");
          loadSelectedHosts();
        } else {
          ElMessage.error("Failed to update hosts");
        }
      });
    } else {
      ElMessage.error("Failed to update hosts");
    }
  }); 
  selectDialogVisible.value = false;
}

const getRowKey = (row: Host) => {
  return row.host_id;
}

const onDialogOpened = () => {
  syncSelection();
}

onMounted(() => {
  loadHosts();
  loadSelectedHosts();
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
            <el-button type="primary" plain @click="openHostDialog">Add</el-button>
          </el-col>
          <el-col :span="3">
            <el-button type="primary" plain @click="openSelectDialog">Select</el-button>
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
            <el-table-column width="50" />
            <el-table-column label="Port" width="80" prop="port" />
            <el-table-column label="Protocol" width="120" prop="protocol" />
            <el-table-column label="Name" width="120" prop="service_name" />
            <el-table-column label="Version" prop="service_description" />
          </el-table>
        </div>
      </template>
    </el-table-column>
    <el-table-column label="IP Address" prop="host.ip_addr" />
    <el-table-column label="Host Name" prop="host.host_name" />
    <el-table-column label="OS Name" prop="host.os_name" />
    <el-table-column label="Actions">
      <template #default="props">
        <el-button size="small" type="primary" plain @click="clickTemp">Edit</el-button>
        <el-button size="small" type="danger" plain @click="openRemoveDialog(props.row)">Remove</el-button>
      </template>
    </el-table-column>
  </el-table>

  <!-- Select Dialog -->
  <el-dialog v-model="selectDialogVisible" title="Select hosts to display" @opened="onDialogOpened">
    <el-table ref="multipleTableRef" :data="tdHosts" size="small" style="width: 100%" class="mt-2" max-height="250" @selection-change="handleSelectionChange" :row-key="getRowKey">
      <el-table-column type="selection" width="55" :reserve-selection="true" />
      <el-table-column label="IP Address" prop="ip_addr" />
      <el-table-column label="Host Name" prop="host_name" />
      <el-table-column label="Actions">
        <template #default="props">
          <el-button size="small" type="danger" plain @click="openDeleteDialog(props.row)">Delete</el-button>
        </template>
      </el-table-column>
    </el-table>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="selectDialogVisible = false">Close</el-button>
        <el-button @click="enableUserHosts" type="primary">Save</el-button>
      </span>
    </template>
  </el-dialog>
  <!-- Select Dialog -->

  <!-- Host Dialog -->
  <el-dialog v-model="hostDialogVisible" title="Add Host" width="30%" center>
    <el-form label-position="top" size="small">
      <el-form-item label="Host Name">
        <el-input placeholder="Host Name" v-model="currentHost.host_name"/>
      </el-form-item>
      <el-form-item label="IP Address">
        <el-input placeholder="IP Address" v-model="currentHost.ip_addr" />
      </el-form-item>
      <el-form-item label="OS Name">
        <el-input placeholder="OS Name" v-model="currentHost.os_name" />
      </el-form-item>
    </el-form>
    <el-row :gutter="10">
      <el-col :span="6">
        <el-input placeholder="Port" size="small"></el-input>
      </el-col>
      <el-col :span="14">
        <el-input placeholder="Service" size="small"></el-input>
      </el-col>
      <el-col :span="3">
        <el-button type="primary" plain @click="clickTemp" size="small">Add</el-button>
      </el-col>
    </el-row>
    <el-table ref="serviceTableRef" :data="currentHost.services" size="small" style="width: 100%" class="mt-2" max-height="200">
      <el-table-column label="Port" prop="port" />
      <el-table-column label="Service Name" prop="service_name" />
      <el-table-column label="Actions">
        <template #default="props">
          <el-button size="small" type="danger" plain @click="openDeleteDialog(props.row)">Delete</el-button>
        </template>
      </el-table-column>
    </el-table>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="hostDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="addUserHost">Add</el-button>
      </span>
    </template>
  </el-dialog>
  <!-- Host Dialog -->

  <!-- Delete Dialog -->
  <el-dialog v-model="removeDialogVisible" title="Warning" width="30%" center>
    <span>
      Are you sure you want to remove the selected host?
    </span>
    <el-checkbox v-model="checkDelete" label="Delete completely" size="large" />
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="closeRemoveDialog">Cancel</el-button>
        <el-button type="danger" @click="removeUserHost">
          Remove
        </el-button>
      </span>
    </template>
  </el-dialog>
  <!-- Delete Dialog -->

  <!-- Delete Dialog -->
  <el-dialog v-model="deleteDialogVisible" title="Warning" width="30%" center>
    <span>
      Are you sure you want to delete the selected host?
    </span>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="closeDeleteDialog">Cancel</el-button>
        <el-button type="danger" @click="deleteUserHost">
          Delete
        </el-button>
      </span>
    </template>
  </el-dialog>
  <!-- Delete Dialog -->

</template>

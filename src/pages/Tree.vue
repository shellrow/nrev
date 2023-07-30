<script lang="ts" setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { ElMessage, ElTable } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';

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
  valid_flag: number
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

const innerWidth = ref(window.innerWidth);
const innerHeight = ref(window.innerHeight);
const checkWindowSize = () => {
    innerWidth.value = window.innerWidth;
    innerHeight.value = window.innerHeight;
};

const hostDialogVisible = ref(false);
const selectDialogVisible = ref(false);
const serviceDialogVisible = ref(false);
const removeDialogVisible = ref(false);
const deleteDialogVisible = ref(false);
const deleteServiceDialogVisible = ref(false);
const checkDelete = ref(false);
const currentRemoveHostId = ref("");
const currentDeleteHostId = ref("");
const currentDeleteServiceIndex = ref(0);
const currentHostDialogAction = ref("Add");
const prevHostId = ref("");
const tableRef = ref<InstanceType<typeof ElTable>>();
const multipleTableRef = ref<InstanceType<typeof ElTable>>();
const serviceTableRef = ref<InstanceType<typeof ElTable>>();
const multipleSelection = ref<Host[]>([]);
const tdHosts = ref<Host[]>([]);
const tdSelectedHosts = ref<UserProbeData[]>([]);

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

const newService = reactive({
  host_id: "",
  port: 0,
  protocol: "",
  service_name: "",
  service_description: "",
  service_cpe: ""
});

const currentHost: UserProbeData = reactive({
  host_id: "",
  host: {
    host_id: "",
    ip_addr: "",
    host_name: "",
    mac_addr: "",
    vendor_name: "",
    os_cpe: "",
    os_name: "",
    valid_flag: 1
  },
  services: [],
  groups: [],
  tags: []
});

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

// @ts-ignore
const openHostDialog = (actionId, row) => {
  if (actionId === "add") {
    currentHostDialogAction.value = "Add";
    prevHostId.value = "";
  }else{
    currentHostDialogAction.value = "Update";
    if (row) {
      prevHostId.value = row.host_id;
      currentHost.host_id = row.host_id;
      currentHost.host.host_id = row.host.host_id;
      currentHost.host.host_name = row.host.host_name;
      currentHost.host.ip_addr = row.host.ip_addr;
      currentHost.host.mac_addr = row.host.mac_addr;
      currentHost.host.vendor_name = row.host.vendor_name;
      currentHost.host.os_cpe = row.host.os_cpe;
      currentHost.host.os_name = row.host.os_name;
      currentHost.services.splice(0, currentHost.services.length);
      row.services.forEach((service: { host_id: any; port: any; protocol: any; service_name: any; service_description: any; service_cpe: any; }) => {
        currentHost.services.push({
          host_id: service.host_id,
          port: service.port,
          protocol: service.protocol,
          service_name: service.service_name,
          service_description: service.service_description,
          service_cpe: service.service_cpe
        });
      });
    }
  }
  hostDialogVisible.value = true;
}

const saveHosts = async (hosts: Array<UserProbeData>) => {
  invoke<number>("save_user_probe_data", {probeData: hosts}).then((res) => {
    if (res === 0) {
      ElMessage.success("Host added successfully");
      loadHosts();
      loadSelectedHosts();
    } else {
      ElMessage.error("Failed to add host");
    }
  });
}

const addService = (event: any) => {
  if (newService.port === 0) {
    ElMessage.error("Port is required");
    return;
  }
  currentHost.services.push({
    host_id: currentHost.host_id,
    port: newService.port,
    protocol: "TCP",
    service_name: newService.service_name,
    service_description: newService.service_description,
    service_cpe: ""
  });
  newService.port = 0;
  newService.service_name = "";
  newService.service_description = "";
  serviceDialogVisible.value = false;
}

const saveUserHost = (event: any) => {
  if (currentHost.host.host_name === "" || currentHost.host.ip_addr === "") {
    ElMessage.error("Host Name and IP Address are required");
    return;
  }
  invoke<string>("get_new_host_id", {hostname: currentHost.host.host_name}).then((host_id) => {
    currentHost.host_id = host_id;
    currentHost.host.host_id = host_id;
    currentHost.services.forEach((service) => {
      service.host_id = host_id;
    });
    invoke<number>("save_user_probe_data", {probeData: [currentHost]}).then((res) => {
      //Init currentHost
      currentHost.host_id = "";
      currentHost.host.host_id = "";
      currentHost.host.host_name = "";
      currentHost.host.ip_addr = "";
      currentHost.host.mac_addr = "";
      currentHost.host.vendor_name = "";
      currentHost.host.os_cpe = "";
      currentHost.host.os_name = "";
      currentHost.services.splice(0, currentHost.services.length);
      if (res !== 0) {
        ElMessage.error("Failed to add host");
        return;
      }
    });
    // Delete previous host
    if (prevHostId.value !== "" && prevHostId.value !== host_id) {
      invoke<number>("delete_user_host", { ids: [prevHostId.value] }).then((res) => {
        if (res !== 0) {
          ElMessage.error("Failed to save host");
          return;
        }
      });
    }
    ElMessage.success("Host saved successfully");
    loadHosts();
    loadSelectedHosts();
    hostDialogVisible.value = false;
  }).catch((err) => {
    ElMessage.error("Failed to save host");
  });
}

const openRemoveDialog = (row: { host_id: string; }) => {
  checkDelete.value = false;
  removeDialogVisible.value = true;
  currentRemoveHostId.value = row.host_id;
}

const openDeleteDialog = (row: { host_id: string; }) => {
  deleteDialogVisible.value = true;
  currentDeleteHostId.value = row.host_id;
}

const openDeleteServiceDialog = (index: number) => {
  deleteServiceDialogVisible.value = true;
  currentDeleteServiceIndex.value = index;
}

const closeRemoveDialog = (event: any) => {
  checkDelete.value = false;
  removeDialogVisible.value = false;
}

const removeUserHost = (event: any) => {
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

const closeDeleteDialog = (event: any) => {
  deleteDialogVisible.value = false;
}

const deleteUserHost = (event: any) => {
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

const closeDeleteServiceDialog = (event: any) => {
  deleteServiceDialogVisible.value = false;
}

const deleteUserServiceRow = () => {
  currentHost.services.splice(currentDeleteServiceIndex.value, 1);
  deleteServiceDialogVisible.value = false;
}

const openServiceDialog = () => {
  serviceDialogVisible.value = true;
}

const closeServiceDialog = () => {
  serviceDialogVisible.value = false;
}

const getRowKey = (row: Host) => {
  return row.host_id;
}

const onDialogOpened = () => {
  syncSelection();
}

const reloadHosts = () => {
  loadHosts();
  loadSelectedHosts();
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
  max-height: 20px;
}
</style>

<template>
  <el-card class="box-card" style="margin-bottom: 20px;">
    <!-- Header -->
    <div class="card-header">
        <span>Map</span>
        <div>
          <el-button type="primary" plain @click="openHostDialog('add', null)">Add</el-button>
          <el-button type="primary" plain @click="openSelectDialog">Select</el-button>
          <el-button type="primary" plain @click="reloadHosts"><el-icon><Refresh /></el-icon></el-button>
        </div>
    </div>
    <!-- Header -->
  </el-card>
  <el-table ref="tableRef" :data="tdSelectedHosts" size="small" style="width: 100%" class="mt-2" :max-height="innerHeight - 200">
    <el-table-column type="expand">
      <template #default="props">
        <div m="4">
          <el-table :data="props.row.services" size="small" style="width: 100%">
            <el-table-column width="50" />
            <el-table-column label="Port" width="80" prop="port" />
            <el-table-column label="Protocol" width="120" prop="protocol" />
            <el-table-column label="Name" width="120" prop="service_name" />
            <el-table-column label="Version" prop="service_description" />
          </el-table>
        </div>
      </template>
    </el-table-column>
    <el-table-column label="IP Address" prop="host.ip_addr" width="140" />
    <el-table-column label="Host Name" prop="host.host_name" />
    <el-table-column label="OS Name" prop="host.os_name" width="180"/>
    <el-table-column label="Actions">
      <template #default="props">
        <el-button size="small" type="primary" plain @click="openHostDialog('edit', props.row)">Edit</el-button>
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

  <!-- Service Dialog -->
  <el-dialog v-model="serviceDialogVisible" title="Service" width="30%" center>
    <el-form label-position="top" size="small">
      <el-row :gutter="10">
        <el-col :span="10">
          <el-form-item label="Port">
            <el-input-number v-model="newService.port" :min="0" :max="65535" size="small" />
          </el-form-item>
        </el-col>
        <el-col :span="14">
          <el-form-item label="Service">
            <el-input v-model="newService.service_name" placeholder="Service" size="small"></el-input>
          </el-form-item>
        </el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="24">
          <el-form-item label="Service Version">
            <el-input v-model="newService.service_description" placeholder="Service Version" size="small"></el-input>
          </el-form-item>
        </el-col>
      </el-row>
    </el-form>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="closeServiceDialog">Cancel</el-button>
        <el-button type="primary" @click="addService">Add</el-button>
      </span>
    </template>
  </el-dialog>
  <!-- Service Dialog -->

  <!-- Host Dialog -->
  <el-dialog v-model="hostDialogVisible" :title="`${currentHostDialogAction} Host`" width="40%" center>
    <el-form label-position="top" size="small">
      <el-row :gutter="10">
        <el-col :span="14">
          <el-form-item label="Host Name">
            <el-input placeholder="Host Name" v-model="currentHost.host.host_name"/>
          </el-form-item>
        </el-col>
        <el-col :span="10">
          <el-form-item label="IP Address">
            <el-input placeholder="IP Address" v-model="currentHost.host.ip_addr" />
          </el-form-item>
        </el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="12">
          <el-form-item label="OS Name">
            <el-input placeholder="OS Name" v-model="currentHost.host.os_name" />
          </el-form-item>
        </el-col>
      </el-row>
      <el-row :gutter="10">
        <el-col :span="12">
          <el-form-item label="MAC Address">
            <el-input placeholder="MAC Address" v-model="currentHost.host.mac_addr" />
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="Vendor">
            <el-input placeholder="Vendor" v-model="currentHost.host.vendor_name" />
          </el-form-item>
        </el-col>
      </el-row>
    </el-form>
    <el-divider>Services</el-divider>
    <el-row :gutter="10">
      <el-button type="primary" plain @click="openServiceDialog" size="small">Add</el-button>
    </el-row>
    <el-table ref="serviceTableRef" :data="currentHost.services" size="small" style="width: 100%" class="mt-2" max-height="200">
      <el-table-column label="Port" prop="port" />
      <el-table-column label="Service Name" prop="service_name" />
      <el-table-column label="Actions">
        <template #default="props">
          <el-button size="small" type="danger" plain @click="openDeleteServiceDialog(props.$index)">Delete</el-button>
        </template>
      </el-table-column>
    </el-table>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="hostDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveUserHost">{{ currentHostDialogAction }}</el-button>
      </span>
    </template>
  </el-dialog>
  <!-- Host Dialog -->

  <!-- Remove Dialog -->
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

  <!-- Delete Service Dialog -->
  <el-dialog v-model="deleteServiceDialogVisible" title="Warning" width="30%" center>
    <span>
      Are you sure you want to delete the selected service?
    </span>
    <template #footer>
      <span class="dialog-footer">
        <el-button @click="closeDeleteServiceDialog">Cancel</el-button>
        <el-button type="danger" @click="deleteUserServiceRow">
          Delete
        </el-button>
      </span>
    </template>
  </el-dialog>
  <!-- Delete Service Dialog -->

</template>

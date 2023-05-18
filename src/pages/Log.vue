<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';
import { ElMessage } from 'element-plus';

const log_detail_visible = ref(false);
const searching = ref(false);

const probeTypes = [
  {
    value: 'port_scan',
    label: 'Port Scan',
  },
  {
    value: 'host_scan',
    label: 'Host Scan',
  },
  {
    value: 'ping',
    label: 'Ping',
  },
  {
    value: 'traceroute',
    label: 'Traceroute',
  },
];

const log_detail = reactive({
  id: 0,
  probe_id: "",
  probe_type_id: "",
  probe_type_name: "",
  probe_target_addr: "",
  probe_target_name: "",
  protocol_id: "",
  probe_option: "",
  issued_at: "", 
  save_file_path: "",
});

const json_text_area = ref('');

const getLocalTime = (date) => {
    const d = new Date(date);
    const offset = d.getTimezoneOffset() * 60000;
    return new Date(d.getTime() - offset);
}

const getLastWeekDateTime = () => {
    const d = new Date();
    d.setTime(d.getTime() - 3600 * 1000 * 24 * 7);
    return d;
}

const defaultDateRange = [
  getLocalTime(getLastWeekDateTime()),  
  getLocalTime(new Date())
];

const optionDateRange = ref('');

const shortcuts = [
  {
    text: 'Last week',
    value: () => {
      const end = new Date()
      const start = new Date()
      start.setTime(start.getTime() - 3600 * 1000 * 24 * 7)
      return [start, end]
    },
  },
  {
    text: 'Last month',
    value: () => {
      const end = new Date()
      const start = new Date()
      start.setTime(start.getTime() - 3600 * 1000 * 24 * 30)
      return [start, end]
    },
  },
  {
    text: 'Last 3 months',
    value: () => {
      const end = new Date()
      const start = new Date()
      start.setTime(start.getTime() - 3600 * 1000 * 24 * 90)
      return [start, end]
    },
  },
];

const searchOption = reactive({
    target_host: "",
    probe_types: ["port_scan","host_scan","ping","traceroute"],
    start_date: "",
    end_date: ""
});

const searchResult = ref([]);

const searchLog = async () => {
    searching.value = true;
    invoke('get_probe_log', { "opt": searchOption }).then((results) => {
      searchResult.value = results;
      searching.value = false;
    });
}

const getResult = async (probeId, probeTypeId) => {
  console.log(`Result ${probeId} ${probeTypeId}}`);
  switch (probeTypeId){
    case 'port_scan':
      invoke('get_port_scan_result', { "probeId": probeId }).then((results) => {
        console.log(results);
        json_text_area.value = JSON.stringify(results, null, 2);
      });
      break;
    case 'host_scan':
      invoke('get_host_scan_result', { "probeId": probeId }).then((results) => {
        console.log(results);
        json_text_area.value = JSON.stringify(results, null, 2);
      });
      break;
    case 'ping':
      invoke('get_ping_stat', { "probeId": probeId }).then((results) => {
        console.log(results);
        json_text_area.value = JSON.stringify(results, null, 2);
      });
      break;
    case 'traceroute':
      invoke('get_trace_result', { "probeId": probeId }).then((results) => {
        console.log(results);
        json_text_area.value = JSON.stringify(results, null, 2);
      });
      break;
    default:
      console.log('Undefined probe type.');
  }
}

const clickSearch = (event) => {
    if (optionDateRange.value) {
      if (optionDateRange.value.length > 0 && (optionDateRange.value[0] && optionDateRange.value[1])) {
        searchOption.start_date = getLocalTime(optionDateRange.value[0]).toISOString();
        searchOption.end_date = getLocalTime(optionDateRange.value[1]).toISOString();
      }else {
        searchOption.start_date = defaultDateRange[0].toISOString();
        searchOption.end_date = defaultDateRange[1].toISOString();
      }
    }else{
      searchOption.start_date = defaultDateRange[0].toISOString();
      searchOption.end_date = defaultDateRange[1].toISOString();
    }
    console.log(searchOption);
    searchLog();
}

const handleOpen = (index, row) => {
  console.log(index, row);
  log_detail.id = row.id;
  log_detail.probe_id = row.probe_id;
  log_detail.probe_type_id = row.probe_type_id;
  log_detail.probe_type_name = row.probe_type_name;
  log_detail.save_file_path = `${row.id}-${row.probe_id}.json`;
  getResult(row.probe_id, row.probe_type_id);
  log_detail_visible.value = true;
}

const clickExport = (event) => {
  console.log('Export');
}

const clickCopy = (event) => {
  console.log('Copy');
  navigator.clipboard.writeText(json_text_area.value).then(() => {
      ElMessage({
        message: "JSON Data copied!",
        type: 'success',
      });
  })
  .catch(e => {
      console.error(e);
  });
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

.item {
  margin-bottom: 18px;
}

.opt-date-picker {
  display: flex;
  width: 100%;
  padding: 0;
  flex-wrap: wrap;
}

.opt-date-picker .block {
  padding: 30px 0;
  text-align: center;
  border-right: solid 1px var(--el-border-color);
  flex: 1;
}

.opt-date-picker .block:last-child {
  border-right: none;
}

.opt-date-picker .opt-date-picker-title {
  display: block;
  color: var(--el-text-color-secondary);
  font-size: 14px;
  margin-bottom: 20px;
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
        <!-- Option -->
        <el-row :gutter="20">
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Probe Type</p>
                <el-select
                v-model="searchOption.probe_types"
                multiple 
                collapse-tags 
                placeholder="Select"
                style="width: 240px"
                >
                <el-option
                    v-for="item in probeTypes"
                    :key="item.value"
                    :label="item.label"
                    :value="item.value"
                />
                </el-select>
            </el-col>
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Target</p>
                <el-input v-model="searchOption.target_host" placeholder="IP Address or HostName" />
            </el-col>
            <el-col :span="6">
                <p style="font-size: var(--el-font-size-small)">Probe date range</p>
                <el-date-picker
                    v-model="optionDateRange"
                    type="daterange"
                    unlink-panels
                    range-separator="To"
                    start-placeholder="Start date"
                    end-placeholder="End date" 
                    :default-time="defaultDateRange"
                    :shortcuts="shortcuts"
                    size="default"
                />
            </el-col>
        </el-row>
        <!-- Option -->
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
                <el-table-column prop="id" label="ID" width="80">
                    <template #default="scope">
                        <el-popover effect="light" trigger="hover" placement="top" width="auto">
                            <template #default>
                                <div>{{ scope.row.probe_id }}</div>
                            </template>
                            <template #reference>
                                <el-button size="small" @click="handleOpen(scope.$index, scope.row)">
                                    {{ scope.row.id }}
                                </el-button>
                            </template>
                        </el-popover>
                    </template>
                </el-table-column>
                <el-table-column prop="probe_type_name" label="Probe Type"  />
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
    <!-- Dialog -->
    <el-dialog v-model="log_detail_visible" :title="`${log_detail.probe_type_name} Result: ${log_detail.probe_id}`">
        <el-row :gutter="20">
            <el-col :span="14">
                <el-input v-model="log_detail.save_file_path" placeholder="Save FilePath" />
            </el-col>
            <el-col :span="4">
                <el-button type="primary" plain @click="clickExport">Export</el-button>
            </el-col>
            <el-col :span="4">
                <el-button type="primary" plain @click="clickCopy">Copy</el-button>
            </el-col>
        </el-row>
        <div style="margin: 20px 0" />
        <el-row :gutter="20">
          <el-input
            v-model="json_text_area"
            :autosize="{ minRows: 8, maxRows: 16 }"
            type="textarea"
            placeholder="JSON Result" 
            readonly
          />
        </el-row>
        <template #footer>
            <span class="dialog-footer">
                <el-button @click="log_detail_visible = false">Close</el-button>
            </span>
        </template>
    </el-dialog>
    <!-- Dialog -->
</template>

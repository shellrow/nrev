<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';
import { Nodes, Edges, Layouts, defineConfigs} from "v-network-graph";

const nodeLabelColor = ref("#ffffff");
const darkBgThemes = ["","dark", "night", "dracula", "halloween"];

type DataSetItem = {
  id: string;
  name: string;
}

type MapInfo = {
  map_id: number,
  map_name: string,
  display_order: Number,
  created_at: string,
}

type MapNode = {
  map_id: number,
  node_id: string,
  node_name: string,
  ip_addr: string,
  host_name: string,
}

type MapEdge = {
  map_id: number,
  edge_id: string,
  source_node_id: string,
  target_node_id: string,
  edge_label: string,
}

type MapLayout = {
  map_id: number,
  node_id: string,
  x_value: number,
  y_value: number,
}

type MapData = {
  map_info: MapInfo,
  nodes: Array<MapNode>,
  edges: Array<MapEdge>,
  layouts: Array<MapLayout>,
}

function invoke_get_probed_hosts(): Promise<Array<DataSetItem>>{
  return invoke('get_probed_hosts');
}

if (localStorage.theme === 'dark') {
  nodeLabelColor.value = "#ffffff";
} else {
  nodeLabelColor.value = "#000000";
}

const probedHosts = ref([
  {
    id: "",
    name: "",
  },
]);

const targetHost = ref("");
const targetHosts = ref([]);

function setProbedHosts() {
  return new Promise(
    (resolve, reject) => {
      resolve(
        invoke_get_probed_hosts().then(results => {
          probedHosts.value.splice(0, probedHosts.value.length);
          results.forEach(result => {
            probedHosts.value.push({
              id: result.id.toString(),
              name: result.name.toString(),
            });
          });
        })
      );
    }
  );
}

function initMap() {
  setProbedHosts().then(() => {
      probedHosts.value.forEach(host => {
      //const id = `node${Object.keys(nodes).length + 1}`;
      //nodes[id] = { name: host.id, ip_addr: "", host_name: "" };
      //layouts.nodes[id] = getNewPosition();
      //console.log("Node added: " + id + ", " + nodes[id].name);
    });
  });
  loadMapData();
}

const mapInfo: MapInfo = reactive(
  {
    map_id: 1,
    map_name: "default",
    display_order: 1,
    created_at: "",
  }
);

const nodes: Nodes = reactive({});

const edges: Edges = reactive({});

const configs = reactive(defineConfigs({
  node: {
    selectable: true,
    label: {
      visible: true,
      color: nodeLabelColor.value,
    },
  },
  edge: {
    selectable: true,
    label: {
      visible: true,
      color: nodeLabelColor.value,
    },
  },
}));

const layouts: Layouts = reactive(
  {
    nodes: {},
  }
); 

const selectedNodes = ref<string[]>([]);
const selectedEdges = ref<string[]>([]);

const getNewPosition = () => {
  let x = 0;
  let y = 0;
  Object.keys(layouts.nodes).forEach(key => {
    if ( (x > layouts.nodes[key].x - 100 && x <= layouts.nodes[key].x + 100) 
    && (y > layouts.nodes[key].y - 60 && y <= layouts.nodes[key].y + 60) ){
      x += 100;
    }
    if (x > 600){
      x = 100;
      y += 60;
    }
  });
  return { x, y };
};

const getNewNodeId = () => {
  let seq = Object.keys(nodes).length + 1;
  let newId = `node${seq}`;
  while (Object.keys(nodes).includes(newId)){
    seq += 1;
    newId = `node${seq}`;
  }
  return newId;
};

const getNewEdgeId = () => {
  let seq = Object.keys(nodes).length + 1;
  let newId = `edge${seq}`;
  while (Object.keys(edges).includes(newId)){
    seq += 1;
    newId = `edge${seq}`;
  }
  return newId;
};

const addNode = () => {
  if (!targetHost.value) {
    return;
  }
  const id = getNewNodeId();
  nodes[id] = { name: targetHost.value, ip_addr: "", host_name: "" };
  layouts.nodes[id] = getNewPosition();
  console.log("Node added: " + id + ", " + nodes[id].name);
  targetHost.value = "";
}

const removeNodes = () => {
  for (const nodeId of selectedNodes.value) {
    delete nodes[nodeId]
  }
}

const connectNodes = () => {
  if (selectedNodes.value.length !== 2) return;
  const [source, target] = selectedNodes.value;
  const label = "Edge";
  const edgeId = getNewEdgeId();
  console.log("Edge added: " + edgeId + ", " + label);
  console.log(nodes[source].name + " -> " + nodes[target].name);
  edges[edgeId] = { source, target, label };
}

const removeEdges = () => {
  for (const edgeId of selectedEdges.value) {
    delete edges[edgeId]
  }
}

const saveMap = () => {
  let node_array: Array<MapNode> = [];
  let edge_array: Array<MapEdge> = [];
  let layout_array: Array<MapLayout> = [];
  Object.keys(nodes).forEach(key => {
    node_array.push({
        map_id: mapInfo.map_id,
        node_id: key,
        node_name: `${nodes[key].name}`,
        ip_addr: nodes[key].ip_addr,
        host_name: nodes[key].host_name,
    });
  });
  Object.keys(edges).forEach(key => {
    edge_array.push({
      map_id: mapInfo.map_id,
      edge_id: key,
      source_node_id: edges[key].source,
      target_node_id: edges[key].target,
      edge_label: edges[key].label,
    });
  });
  Object.keys(layouts.nodes).forEach(key => {
    layout_array.push({
      map_id: mapInfo.map_id,
      node_id: key,
      x_value: layouts.nodes[key].x,
      y_value: layouts.nodes[key].y,
    });
  });
  const mapData: MapData = {
    map_info: mapInfo,
    nodes: node_array,
    edges: edge_array,
    layouts: layout_array,
  };
  console.log(mapData);
  invoke('save_map_data', { "mapData": mapData }).then((code) => {
    if (code === 0) {
      console.log("Map saved");
    } else {
      console.log("Map save failed");
    }
  });
}

const loadMapData = () => {
  invoke<MapData>('get_map_data', { "mapId": 1 }).then((mapData) => {
    console.log(mapData);
    // Map Info
    mapInfo.map_id = mapData.map_info.map_id;
    mapInfo.map_name = mapData.map_info.map_name;
    mapInfo.display_order = mapData.map_info.display_order;
    mapInfo.created_at = mapData.map_info.created_at;
    // Nodes
    mapData.nodes.forEach(node => {
      nodes[node.node_id] = { name: node.node_name, ip_addr: node.ip_addr, host_name: node.host_name };
    });
    // Edges
    mapData.edges.forEach(edge => {
      edges[edge.edge_id] = { source: edge.source_node_id, target: edge.target_node_id, label: edge.edge_label };
    });
    // Layouts
    mapData.layouts.forEach(layout => {
      layouts.nodes[layout.node_id] = { x: layout.x_value, y: layout.y_value };
    });

  });
}

const onTargetHostsChange = (event) => {
  console.log(event);
  console.log(targetHosts.value);
}

const onTargetHostRemoved = (event) => {
  console.log(event);
  console.log(targetHosts.value);
}

onMounted(() => {
    if (localStorage.theme === 'dark') {
        nodeLabelColor.value = "#ffffff";
    } else {
        nodeLabelColor.value = "#000000";
    }
    //invoke('test_command_arg', { invokeMessage: 'Map' });
    //invoke('test_command_return').then((message) => console.log(message));
    initMap();
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
            <span>Map</span>
            <el-button type="primary" plain @click="saveMap">Save</el-button>
        </div>
    </template>
    <!-- Header -->
    <el-row :gutter="10">
      <el-col :span="14">
        <p style="font-size: var(--el-font-size-small)">Target</p>
        <el-row :gutter="10">
          <el-col :span="12">
            <el-input v-model="targetHost" placeholder="Address or Name" @keyup.enter="addNode"></el-input>
          </el-col>
          <el-col :span="4">
            <el-button type="primary" plain @click="addNode">Add Node</el-button>
          </el-col>
        </el-row>
      </el-col>
      <el-col :span="6">
          <p style="font-size: var(--el-font-size-small)">Hosts</p>
          <el-select
          v-model="targetHosts"
          multiple 
          collapse-tags 
          placeholder="Select" 
          @change="onTargetHostsChange" 
          @remove-tag="onTargetHostRemoved"
          >
            <el-option
                v-for="item in probedHosts"
                :key="item.id"
                :label="item.name"
                :value="item.id"
            />
          </el-select>
      </el-col>
    </el-row>
    <el-row :gutter="10">
      <el-col :span="14">
        <p style="font-size: var(--el-font-size-small)">Selected Nodes</p>
        <el-row :gutter="10">
          <el-col :span="4">
            <el-button type="primary" plain @click="connectNodes">Connect</el-button>
          </el-col>
          <el-col :span="4">
            <el-button type="primary" plain @click="removeNodes">Remove</el-button>
          </el-col>
        </el-row>
      </el-col>
      <el-col :span="10">
        <p style="font-size: var(--el-font-size-small)">Selected Edges</p>
        <el-row :gutter="10">
          <el-col :span="4">
            <el-button type="primary" plain @click="removeEdges">Remove</el-button>
          </el-col>
        </el-row>
      </el-col>
    </el-row>
  </el-card>
    <v-network-graph
        v-model:selected-nodes="selectedNodes"
        v-model:selected-edges="selectedEdges"
        :nodes="nodes"
        :edges="edges"
        :layouts="layouts"
        :configs="configs"
        style="height: 600px;"
    >
    </v-network-graph>
</template>

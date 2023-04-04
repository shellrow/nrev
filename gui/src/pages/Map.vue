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
      const id = `node${Object.keys(nodes).length + 1}`;
      nodes[id] = { name: host.id, ip_addr: "", host_name: "" };
      layouts.nodes[id] = getNewPosition();
      console.log("Node added: " + id + ", " + nodes[id].name);
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

const nodes: Nodes = reactive(
    {
      /* node1: { name: "192.168.1.8", ip_addr: "", host_name: "" },
      node2: { name: "192.168.1.4", ip_addr: "", host_name: "" },
      node3: { name: "192.168.1.1", ip_addr: "", host_name: "" },
      node4: { name: "192.168.1.92", ip_addr: "", host_name: "" },
      node5: { name: "179.48.249.196", ip_addr: "", host_name: "" },
      node6: { name: "45.33.32.156", ip_addr: "", host_name: "" },
      node7: { name: "45.33.34.74", ip_addr: "", host_name: "" },
      node8: { name: "45.33.34.76", ip_addr: "", host_name: "" },
      node9: { name: "45.33.35.67", ip_addr: "", host_name: "" },
      node10: { name: "45.33.40.103", ip_addr: "", host_name: "" }, */
    }
  );

const edges: Edges = reactive(
  {
    /* edge1: { source: "node1", target: "node2", label: "1 Gbps" },
    edge2: { source: "node2", target: "node3", label: "1 Gbps" },
    edge3: { source: "node2", target: "node4", label: "1 Gbps" },
    edge4: { source: "node3", target: "node5", label: "1 Gbps" },
    edge5: { source: "node5", target: "node6", label: "1 Gbps" },
    edge6: { source: "node5", target: "node7", label: "1 Gbps" },
    edge7: { source: "node5", target: "node8", label: "1 Gbps" },
    edge8: { source: "node5", target: "node9", label: "1 Gbps" },
    edge9: { source: "node5", target: "node10", label: "1 Gbps" }, */
  }
);

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
    nodes: {
      /* node1: { x: 0, y: 140 },
      node2: { x: 160, y: 140 },
      node3: { x: 280, y: 140 },
      node4: { x: 60, y: 220 },
      node5: { x: 400, y: 140 },
      node6: { x: 500, y: 40 },
      node7: { x: 540, y: 100 },
      node8: { x: 580, y: 200 },
      node9: { x: 540, y: 280 },
      node10: { x: 500, y: 340 }, */
    },
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

const addNode = () => {
  if (!targetHost.value) {
    return;
  }
  const id = `node${Object.keys(nodes).length + 1}`;
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
  const edgeId = `edge${Object.keys(edges).length + 1}`;
  edges[edgeId] = { source, target };
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

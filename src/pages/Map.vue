<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted, computed, watch } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';
import * as vNG from "v-network-graph"
import {Refresh} from '@element-plus/icons-vue';

const innerWidth = ref(window.innerWidth);
const innerHeight = ref(window.innerHeight);
const nodeLabelColor = ref("#ffffff");
const darkBgThemes = ["","dark", "night", "dracula", "halloween"];
const graph = ref<vNG.Instance>();

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
const targetHosts = ref<string[]>([]);
const prevTargetHosts = ref<string[]>([]);

const checkWindowSize = () => {
    innerWidth.value = window.innerWidth;
    innerHeight.value = window.innerHeight;
};

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

function initMapView() {
  if (!graph.value) return;
  graph.value.panTo({
      x: 40,
      y: 40,
  });
  graph.value.setViewBox({
    left: -20,
    top: -20,
    right: 540,
    bottom: 540,
  });
}

function initMap() {
  targetHost.value =  "";
  targetHosts.value = [];
  prevTargetHosts.value = [];
  if (localStorage.theme === 'dark') {
      nodeLabelColor.value = "#ffffff";
  } else {
      nodeLabelColor.value = "#000000";
  }
  setProbedHosts().then(() => {
      probedHosts.value.forEach(host => {
        prevTargetHosts.value.push(host.id);
    });
  });
  loadMapData();
  //selectMappedHosts();
  initMapView();
}

function reloadMap() {
  initMap();
}

const mapInfo: MapInfo = reactive(
  {
    map_id: 0,
    map_name: "default",
    display_order: 1,
    created_at: "",
  }
);

const nodes: vNG.Nodes = reactive({});

const edges: vNG.Edges = reactive({});

const configs = reactive(vNG.defineConfigs({
  view: {
    autoPanAndZoomOnLoad: false,
    grid: {
      visible: true,
      interval: 100,
      thickIncrements: 1,
      line: {
        color: "#e0e0e0",
        width: 1,
        dasharray: 0,
      },
      thick: {
        color: "#cccccc",
        width: 1,
        dasharray: 0,
      },
    },
  },
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
      //visible: true,
      color: nodeLabelColor.value,
    },
  },
}));

const layouts: vNG.Layouts = reactive(
  {
    nodes: {},
  }
); 

const selectedNodes = ref<string[]>([]);
const selectedEdges = ref<string[]>([]);

const getNewPosition = () => {
  let x = 40;
  let y = 40;
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

const getNodeId = (targetName) => {
  let nodeId = "";
  probedHosts.value.forEach(host => {
    if (host.id === targetName || host.name === targetName) {
      Object.keys(nodes).forEach(key => {
        if (nodes[key].name === host.id || nodes[key].name === host.name) {
          nodeId = key;
        }
      });
    }
  });
  return nodeId;
}

const addNode = () => {
  if (!targetHost.value) {
    return;
  }
  const id = getNewNodeId();
  // TODO: Lookup host name / ip address
  nodes[id] = { name: targetHost.value, ip_addr: "", host_name: "" };
  layouts.nodes[id] = getNewPosition();
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
    if (layouts.nodes[key].x < 0) {
      layouts.nodes[key].x = 0;
    }
    if (layouts.nodes[key].x > 540) {
      layouts.nodes[key].x = 540;
    }
    if (layouts.nodes[key].y < 0) {
      layouts.nodes[key].y = 0;
    }
    if (layouts.nodes[key].y > 540) {
      layouts.nodes[key].y = 540;
    }
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
  invoke('save_map_data', { "mapData": mapData }).then((code) => {

  });
}

const loadMapData = () => {
  invoke<MapData>('get_map_data', { "mapId": 0 }).then((mapData) => {
    // Map Info
    mapInfo.map_id = mapData.map_info.map_id;
    mapInfo.map_name = mapData.map_info.map_name;
    mapInfo.display_order = mapData.map_info.display_order;
    mapInfo.created_at = mapData.map_info.created_at;
    // Nodes
    mapData.nodes.forEach(node => {
      let node_name = node.node_name;
      if (node.host_name !== "" && node.host_name != node.ip_addr) {
        node_name = `${node.host_name} (${node.ip_addr})`;
      }
      nodes[node.node_id] = { name: node_name, ip_addr: node.ip_addr, host_name: node.host_name };
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

function getAddedHosts() {
  let addedHosts: Array<string> = targetHosts.value.filter(x => !prevTargetHosts.value.includes(x));
  return addedHosts;
}

function getRemovedHosts() {
  let removedHosts: Array<string> = prevTargetHosts.value.filter(x => !targetHosts.value.includes(x));
  return removedHosts;
}

const addCheckedNodes = () => {
  const checkedHosts = getAddedHosts();
  if (checkedHosts.length > 0) {
    checkedHosts.forEach(host => {
      const nodeId = getNodeId(host);
      if (nodeId === "") {
        const id = getNewNodeId();
        nodes[id] = { name: host, ip_addr: host, host_name: getHostName(host) };
        layouts.nodes[id] = getNewPosition();
      }
    });
  }
  prevTargetHosts.value = targetHosts.value;
}

const removeUncheckedNodes = () => {
  const removedHosts = getRemovedHosts();
  if (removedHosts.length > 0) {
    removedHosts.forEach(host => {
      const nodeId = getNodeId(host);
      if (nodeId !== "") {
        delete nodes[nodeId];
      }
    });
  }
  prevTargetHosts.value = targetHosts.value;
}

const selectMappedHosts = () => {
  targetHosts.value.splice(0, targetHosts.value.length);
  probedHosts.value.forEach(host => {
    const nodeId = getNodeId(host);
    if (nodeId !== "") {
      if (!targetHosts.value.includes(nodes[nodeId].ip_addr)) {
        targetHosts.value.push(nodes[nodeId].ip_addr);
      }
    }
  });
  prevTargetHosts.value = targetHosts.value;
}

const getHostName = (ipAddr) => {
  let hostName = ipAddr;
  probedHosts.value.forEach(host => {
    if (host.id === ipAddr || host.name === ipAddr) {
      hostName = host.name;
    }
  });
  return hostName;
}

const onTargetHostsChange = (event) => {
  if (event.length > prevTargetHosts.value.length) {
    addCheckedNodes();
  } else if (event.length < prevTargetHosts.value.length) {
    removeUncheckedNodes();
  }
}

const onTargetHostRemoved = (event) => {
  const removedHost = event;
  const nodeId = getNodeId(removedHost);
  if (nodeId !== "") {
    delete nodes[nodeId];
  }
}

const tooltip = ref<HTMLDivElement>();
const targetNodeId = ref<string>("");
const tooltipOpacity = ref(0); // 0 or 1
const tooltipPos = ref({ left: "0px", top: "0px" });
const NODE_RADIUS = 16;
const targetNodePos = computed(() => {
  const nodePos = layouts.nodes[targetNodeId.value]
  return nodePos || { x: 0, y: 0 }
});

// Update `tooltipPos`
watch(
  () => [targetNodePos.value, tooltipOpacity.value],
  () => {
    if (!graph.value || !tooltip.value) return

    // translate coordinates: SVG -> DOM
    const domPoint = graph.value.translateFromSvgToDomCoordinates(targetNodePos.value)
    // calculates top-left position of the tooltip.
    tooltipPos.value = {
      left: domPoint.x - tooltip.value.offsetWidth / 2 + "px",
      top: domPoint.y - NODE_RADIUS - tooltip.value.offsetHeight - 10 + "px",
    }
  },
  { deep: true }
);

// Context Menu Event Handler
function showContextMenu(element: HTMLElement, event: MouseEvent) {
  element.style.left = event.x + "px"
  element.style.top = event.y + "px"
  element.style.visibility = "visible"
  const handler = (event: PointerEvent) => {
    if (!event.target || !element.contains(event.target as HTMLElement)) {
      element.style.visibility = "hidden"
      document.removeEventListener("pointerdown", handler, { capture: true })
    }
  }
  document.addEventListener("pointerdown", handler, { passive: true, capture: true })
}

const viewMenu = ref<HTMLDivElement>()
function showViewContextMenu(params: vNG.ViewEvent<MouseEvent>) {
  const { event } = params
  // Disable browser's default context menu
  event.stopPropagation()
  event.preventDefault()
  if (viewMenu.value) {
    showContextMenu(viewMenu.value, event)
  }
}

const nodeMenu = ref<HTMLDivElement>()
const menuTargetNode = ref("")
function showNodeContextMenu(params: vNG.NodeEvent<MouseEvent>) {
  const { node, event } = params
  // Disable browser's default context menu
  event.stopPropagation()
  event.preventDefault()
  if (nodeMenu.value) {
    menuTargetNode.value = nodes[node].name ?? ""
    showContextMenu(nodeMenu.value, event)
  }
}

const edgeMenu = ref<HTMLDivElement>()
const menuTargetEdges = ref<string[]>([])
function showEdgeContextMenu(params: vNG.EdgeEvent<MouseEvent>) {
  const { event } = params
  // Disable browser's default context menu
  event.stopPropagation()
  event.preventDefault()
  if (edgeMenu.value) {
    menuTargetEdges.value = params.summarized ? params.edges : [params.edge]
    showContextMenu(edgeMenu.value, event)
  }
}

const eventHandlers: vNG.EventHandlers = {
  "node:pointerover": ({ node }) => {
    targetNodeId.value = node
    tooltipOpacity.value = 1 // show
  },
  "node:pointerout": _ => {
    tooltipOpacity.value = 0 // hide
  },
  "view:contextmenu": showViewContextMenu,
  "node:contextmenu": showNodeContextMenu,
  "edge:contextmenu": showEdgeContextMenu,
}


onMounted(() => {
  window.addEventListener('resize', debounce(checkWindowSize, 100));
  initMap();
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

.item {
  margin-bottom: 18px;
}
.tooltip-wrapper {
  position: relative;
}
.tooltip {
  top: 0;
  left: 0;
  opacity: 0;
  position: absolute;
  width: 100px;
  height: 36px;
  display: grid;
  place-content: center;
  text-align: center;
  font-size: 12px;
  background-color: #343331a8;
  border: 1px solid #000000;
  box-shadow: 2px 2px 2px #555555;
  transition: opacity 0.2s linear;
  pointer-events: none;
}

.context-menu {
  width: 180px;
  background-color: #343331a8;
  padding: 10px;
  position: fixed;
  visibility: hidden;
  font-size: 12px;
  border: 1px solid #000000;
  box-shadow: 2px 2px 2px #555555;
  > div {
    border: 1px dashed #aaa;
    padding: 4px;
    margin-top: 8px;
  }
}

</style>

<template>
  <el-card class="box-card">
    <!-- Header -->
    <template #header>
        <div class="card-header">
            <span>Map</span>
            <div>
              <el-button type="primary" plain @click="reloadMap"><el-icon><Refresh /></el-icon></el-button>
              <el-button type="primary" plain @click="saveMap">Save</el-button>
            </div>
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
          <p style="font-size: var(--el-font-size-small)">Probed Hosts</p>
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
                :label="`${item.name} (${item.id})`"
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
            <el-button type="danger" plain @click="removeNodes">Remove</el-button>
          </el-col>
        </el-row>
      </el-col>
      <el-col :span="10">
        <p style="font-size: var(--el-font-size-small)">Selected Edges</p>
        <el-row :gutter="10">
          <el-col :span="4">
            <el-button type="danger" plain @click="removeEdges">Remove</el-button>
          </el-col>
        </el-row>
      </el-col>
    </el-row>
  </el-card>
  <el-divider />
    <div class="tooltip-wrapper">
      <v-network-graph
          ref="graph"
          v-model:selected-nodes="selectedNodes"
          v-model:selected-edges="selectedEdges"
          :nodes="nodes"
          :edges="edges"
          :layouts="layouts"
          :configs="configs"
          :event-handlers="eventHandlers"
          :style="'height:'+ (innerHeight - 100).toString() + 'px'"
      >
      </v-network-graph>
      <!-- Tooltip -->
      <div
        ref="tooltip"
        class="tooltip"
        :style="{ ...tooltipPos, opacity: tooltipOpacity }"
      >
        <div>{{ nodes[targetNodeId]?.ip_addr ?? "" }}</div>
      </div>
      <!-- Context Menu -->
      <div ref="viewMenu" class="context-menu">View Manu</div>
      <div ref="nodeMenu" class="context-menu">
        Node Menu
        <div>{{ menuTargetNode }}</div>
      </div>
      <div ref="edgeMenu" class="context-menu">
        Edge Menu
        <div>{{ menuTargetEdges.join(", ") }}</div>
      </div>
    </div>
</template>

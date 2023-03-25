<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';
import { Nodes, Edges, Layouts, defineConfigs} from "v-network-graph";

const nodeLabelColor = ref("#ffffff");
const darkBgThemes = ["","dark", "night", "dracula", "halloween"];

if (localStorage.theme === 'dark') {
  nodeLabelColor.value = "#ffffff";
} else {
  nodeLabelColor.value = "#000000";
}

const nodes: Nodes = reactive(
  {
    node1: { name: "192.168.1.8" },
    node2: { name: "192.168.1.4" },
    node3: { name: "192.168.1.1" },
    node4: { name: "192.168.1.92" },
    node5: { name: "179.48.249.196" },
    node6: { name: "45.33.32.156" },
    node7: { name: "45.33.34.74" },
    node8: { name: "45.33.34.76" },
    node9: { name: "45.33.35.67" },
    node10: { name: "45.33.40.103" },
  }
  );

const edges: Edges = reactive(
  {
    edge1: { source: "node1", target: "node2", label: "1 Gbps" },
    edge2: { source: "node2", target: "node3", label: "1 Gbps" },
    edge3: { source: "node2", target: "node4", label: "1 Gbps" },
    edge4: { source: "node3", target: "node5", label: "1 Gbps" },
    edge5: { source: "node5", target: "node6", label: "1 Gbps" },
    edge6: { source: "node5", target: "node7", label: "1 Gbps" },
    edge7: { source: "node5", target: "node8", label: "1 Gbps" },
    edge8: { source: "node5", target: "node9", label: "1 Gbps" },
    edge9: { source: "node5", target: "node10", label: "1 Gbps" },
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
}));

const layouts: Layouts = reactive(
  {
    nodes: {
      node1: { x: 0, y: 140 },
      node2: { x: 160, y: 140 },
      node3: { x: 280, y: 140 },
      node4: { x: 60, y: 220 },
      node5: { x: 400, y: 140 },
      node6: { x: 500, y: 40 },
      node7: { x: 540, y: 100 },
      node8: { x: 580, y: 200 },
      node9: { x: 540, y: 280 },
      node10: { x: 500, y: 340 },
    },
  }
); 

const selectedNodes = ref<string[]>(["node2"]);

const addNode = () => {
  const id = `node${Object.keys(nodes).length + 1}`;
  nodes[id] = { name: id };
  layouts.nodes[id] = { x: 0, y: 0 };
  console.log(id);
  //selectedNodes.value = [id];
}

onMounted(() => {
    if (localStorage.theme === 'dark') {
        nodeLabelColor.value = "#ffffff";
    } else {
        nodeLabelColor.value = "#000000";
    }
    invoke('test_command_arg', { invokeMessage: 'Map' });
    invoke('test_command_return').then((message) => console.log(message));
    addNode();
});

onUnmounted(() => {

});

</script>

<template>
    <v-network-graph
        :nodes="nodes"
        :edges="edges"
        :layouts="layouts"
        :selected-nodes="selectedNodes"
        :configs="configs"
        style="height: 600px;"
    >
    </v-network-graph>
</template>

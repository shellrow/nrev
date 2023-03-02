<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue';
import { invoke } from '@tauri-apps/api/tauri';
import { debounce } from 'lodash';

onMounted(() => {
    invoke('test_command_arg', { invokeMessage: 'Map' });
    invoke('test_command_return').then((message) => console.log(message));
});

onUnmounted(() => {

});

</script>

<template>
    Map
</template>

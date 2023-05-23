<script setup>
import {ref ,onMounted, onUnmounted} from 'vue';
import {debounce} from 'lodash';
import {Document, Menu as IconMenu, Setting, Sunny, Moon, Expand, Fold, View, Histogram} from '@element-plus/icons-vue';
import SystemPage from '../pages/System.vue';
import AboutPage from '../pages/About.vue';
//import EnMapLogo from "../assets/enmap_icon.png";

const innerWidth = ref(window.innerWidth);
const innerHeight = ref(window.innerHeight);
const theme = ref('light');
const activeIndex = ref('0');
const mode = ref(true);
const isCollapse = ref(innerWidth.value < 1200 ? true : false);

const dialogSystemVisible = ref(false);
const dialogAboutVisible = ref(false);

if (localStorage.theme === 'dark') {
    document.documentElement.classList.add('dark');
    theme.value = 'dark';
    mode.value = false;
} else {
    document.documentElement.classList.remove('dark');
    theme.value = 'light';
    mode.value = true;
}

const changeMode = (event) => {
    if (mode.value) {
        theme.value = 'light';
    }else{
        theme.value = 'dark'; 
    }
    theme.value === 'light' 
        ? document.documentElement.classList.remove('dark')
        : document.documentElement.classList.add('dark');
    localStorage.theme = theme.value;
};

const handleSelect = (key, keyPath) => {
    // Omit!
    console.log(key, keyPath);
};
const handleOpen = (key, keyPath) => {
    // Omit!
    console.log(key, keyPath);
};
const handleClose = (key, keyPath) => {
    // Omit!
    console.log(key, keyPath);
};
const handleCollapse = (event) => {
    isCollapse.value = !isCollapse.value;
};

const checkWindowSize = () => {
    if (window.innerWidth < 1280) {
        if (isCollapse.value === false && innerWidth.value >= 1280) isCollapse.value = true;
    }else{
        if (isCollapse.value === true) isCollapse.value = false;
    }
    innerWidth.value = window.innerWidth;
    innerHeight.value = window.innerHeight;
};

onMounted(() => {
    window.addEventListener('resize', debounce(checkWindowSize, 100));
});

onUnmounted(() => {
    window.removeEventListener('resize', checkWindowSize);
});
</script>

<style>
.flex-grow {
    flex-grow: 1;
}
</style>

<template>
    <div class="common-layout">
        <el-container>
            <el-header>
                <el-menu :default-active="activeIndex" mode="horizontal" :ellipsis="false" @select="handleSelect">
                    <el-button type="primary" plain size="large" style="margin-left: 4px; margin-top: 10px" @click="handleCollapse">
                        <el-icon v-if="isCollapse"><Expand /></el-icon>
                        <el-icon v-else><Fold /></el-icon>
                    </el-button>
                    <!-- <router-link to="/">
                        <img class="img" :src="EnMapLogo" width="40" style="margin-left: 4px; margin-top: 10px" />
                    </router-link> -->
                    <div class="flex-grow" />
                    <el-menu-item index="0" @click="dialogSystemVisible = true">System</el-menu-item>
                    <el-menu-item index="1" @click="dialogAboutVisible = true">About</el-menu-item>
                    <el-switch v-model="mode" @click="changeMode" style="margin-left: 24px; margin-top: 12px;" inline-prompt :active-icon="Sunny" :inactive-icon="Moon" />
                </el-menu>
            </el-header>
            <el-container>
                <el-aside id="side-menu" :width="isCollapse ? '80px' : '200px'" class="duration-300" >
                    <el-menu :default-active="activeIndex" :collapse="isCollapse" :style="'min-height:'+ innerHeight + 'px'" @open="handleOpen" @close="handleClose">
                        <el-menu-item index="0">
                            <el-icon><Histogram /></el-icon>
                            <template #title><router-link to="/">Dashboard</router-link></template>
                        </el-menu-item>
                        <el-menu-item index="1">
                            <el-icon><IconMenu /></el-icon>
                            <template #title><router-link to="/map">Map</router-link></template>
                        </el-menu-item>
                        <el-sub-menu index="2">
                            <template #title>
                                <el-icon><View /></el-icon>
                                <span>Probe</span>
                            </template>
                            <el-menu-item index="2-1"><router-link to="/port">PortScan</router-link></el-menu-item>
                            <el-menu-item index="2-2"><router-link to="/host">HostScan</router-link></el-menu-item>
                            <el-menu-item index="2-3"><router-link to="/ping">Ping</router-link></el-menu-item>
                            <el-menu-item index="2-4"><router-link to="/trace">Traceroute</router-link></el-menu-item>
                        </el-sub-menu>
                        <el-menu-item index="3">
                            <el-icon><Document /></el-icon>
                            <template #title><router-link to="/log">Log</router-link></template>
                        </el-menu-item>
                        <!-- <el-menu-item index="4">
                            <el-icon><Setting /></el-icon>
                            <template #title><router-link to="/setting">Setting</router-link></template>
                        </el-menu-item> -->
                    </el-menu>
                </el-aside>
                <el-main>
                    <el-scrollbar :height="innerHeight-100+'px'" >
                        <div>
                            <slot />
                        </div>
                    </el-scrollbar>
                </el-main>
            </el-container>
        </el-container>
    </div>

    <!-- Dialog -->
    <el-dialog v-model="dialogSystemVisible" title="System">
        <SystemPage></SystemPage>
        <template #footer>
            <span class="dialog-footer">
                <el-button @click="dialogSystemVisible = false">Close</el-button>
            </span>
        </template>
    </el-dialog>
    <el-dialog v-model="dialogAboutVisible" title="About Enmap">
        <AboutPage></AboutPage>
        <template #footer>
            <span class="dialog-footer">
                <el-button @click="dialogAboutVisible = false">Close</el-button>
            </span>
        </template>
    </el-dialog>
    <!-- Dialog -->

</template>

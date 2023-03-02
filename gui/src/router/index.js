import { createRouter, createWebHistory } from 'vue-router';
import Map from '../pages/Map.vue';
import PortScan from '../pages/PortScan.vue';
import HostScan from '../pages/HostScan.vue';
import Ping from '../pages/Ping.vue';
import Traceroute from '../pages/Traceroute.vue';
import Log from '../pages/Log.vue';
import Setting from '../pages/Setting.vue';
import System from '../pages/System.vue';
import Login from '../pages/Login.vue';
import Profile from '../pages/Profile.vue';
import About from '../pages/About.vue';

const routes = [
  {
    path: '/',
    name: 'Map',
    component: Map,
  },
  {
    path: '/port',
    name: 'PortScan',
    component: PortScan,
  },
  {
    path: '/host',
    name: 'HostScan',
    component: HostScan,
  },
  {
    path: '/ping',
    name: 'Ping',
    component: Ping,
  },
  {
    path: '/trace',
    name: 'Traceroute',
    component: Traceroute,
  },
  {
    path: '/log',
    name: 'Log',
    component: Log,
  },
  {
    path: '/setting',
    name: 'Setting',
    component: Setting,
  },
  {
    path: '/system',
    name: 'System',
    component: System,
  },
  {
    path: '/login',
    name: 'Login',
    component: Login,
  },
  {
    path: '/profile',
    name: 'Profile',
    component: Profile,
  },
  {
    path: '/about',
    name: 'About',
    component: About,
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;

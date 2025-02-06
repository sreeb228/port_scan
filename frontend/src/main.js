import {createApp} from 'vue'
import App from './App.vue'
import './style.css';

document.addEventListener('contextmenu', function (e) {
    e.preventDefault();
});


createApp(App).mount('#app')

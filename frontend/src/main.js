import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from '@/router/index.js'
import App from './App.vue'
import { useUiStore } from '@/stores/ui'
import '@/assets/styles/global.css'

const app = createApp(App)

const pinia = createPinia()
app.use(pinia)
app.use(router)

// Instancie le store UI AVANT le mount : son watch applique immédiatement le
// thème (mémorisé ou sombre par défaut) sur <html>, sur TOUS les écrans — y
// compris Login qui n'utilise pas ce store. Garantit une synchro DOM ↔ état
// dès le premier rendu, sans dépendre d'un composant particulier.
useUiStore(pinia)

app.mount('#app')

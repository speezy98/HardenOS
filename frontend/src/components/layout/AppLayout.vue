<script setup>
import Sidebar from './Sidebar.vue'
import TopBar from './TopBar.vue'
import { useUiStore } from '@/stores/ui'

const uiStore = useUiStore()
</script>

<template>
  <div class="app-layout">
    <Sidebar />
    <div class="main-area">
      <TopBar />
      <main class="content">
        <router-view />
      </main>
    </div>

    <!-- Toast global piloté par ui.notify(message, type) -->
    <Teleport to="body">
      <transition name="toast">
        <div
          v-if="uiStore.notification"
          class="global-toast"
          :data-kind="uiStore.notification.type"
        >
          <button class="toast-close" @click="uiStore.dismiss()" title="Fermer">×</button>
          <div class="toast-message">{{ uiStore.notification.message }}</div>
        </div>
      </transition>
    </Teleport>
  </div>
</template>

<style scoped>
.app-layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

.main-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.content {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-8);
  background-color: var(--bg-base);
}

.global-toast {
  position: fixed;
  bottom: var(--space-6);
  right: var(--space-6);
  z-index: 200;
  max-width: 480px;
  /* Hauteur plafonnée : un message très long (ex. liste d'actions manuelles) ne
     déborde plus au-delà du haut de l'écran — la croix de fermeture reste donc
     toujours visible et cliquable. */
  max-height: 70vh;
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  padding: var(--space-4) var(--space-5);
  background-color: var(--bg-elevated);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--text-primary);
  box-shadow: var(--shadow-lg);
}

/* Zone de message défilante (barre coulissante) : le contenu long défile à
   l'intérieur du toast au lieu de l'agrandir sans limite. */
.toast-message {
  overflow-y: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  padding-right: var(--space-2);
}

.toast-close {
  align-self: flex-end;
  flex-shrink: 0;
  background: transparent;
  border: none;
  color: var(--text-muted);
  font-size: var(--text-lg);
  line-height: 1;
  cursor: pointer;
  padding: 0;
}
.toast-close:hover { color: var(--text-primary); }

.global-toast[data-kind="error"]   { border-left-color: var(--status-fail); }
.global-toast[data-kind="success"] { border-left-color: var(--status-pass); }
.global-toast[data-kind="info"]    { border-left-color: var(--accent); }

.toast-enter-active,
.toast-leave-active {
  transition: opacity var(--transition-base), transform var(--transition-base);
}

.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(8px);
}
</style>

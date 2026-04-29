<script setup>
import { computed } from 'vue'
import { useRoute, useRouter, RouterLink } from 'vue-router'
import { Sun, Moon } from 'lucide-vue-next'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const ui = useUiStore()

const themeTitle = computed(() =>
  ui.theme === 'dark' ? 'Passer au thème clair' : 'Passer au thème sombre'
)

const handleLogout = async () => {
  await authStore.logout()
  router.push('/login')
}

const breadcrumbLabel = computed(() => {
  if (!route.name) return 'HardenOS'
  const labels = {
    'dashboard': 'Dashboard',
    'compare': 'Comparaison',
    'reports': 'Rapports',
    'users': 'Utilisateurs',
    'account': 'Mon compte',
    'audit': 'Audit',
    'system-detail': 'Détail système',
    'remediation': 'Remédiation',
    'login': 'Connexion'
  }
  return labels[route.name] || route.name
})
</script>

<template>
  <header class="topbar">
    <div class="breadcrumb">
      {{ breadcrumbLabel }}
    </div>

    <div class="right-section">
      <!-- Bascule sombre/clair : l'icône montre le thème CIBLE -->
      <button
        class="theme-btn"
        :title="themeTitle"
        :aria-label="themeTitle"
        @click="ui.toggleTheme()"
      >
        <!-- Soleil proposé en sombre, lune en clair -->
        <Sun
          v-if="ui.theme === 'dark'"
          :size="16"
        />
        <Moon
          v-else
          :size="16"
        />
      </button>

      <RouterLink
        to="/account"
        class="email"
        title="Mon compte"
      >
        {{ authStore.user?.email }}
      </RouterLink>
      <button
        class="logout-btn"
        @click="handleLogout"
      >
        Déconnexion
      </button>
    </div>
  </header>
</template>

<style scoped>
.topbar {
  height: 56px;
  background-color: var(--bg-surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 var(--space-6);
}

.breadcrumb {
  color: var(--text-secondary);
  font-size: var(--text-sm);
  font-family: var(--font-ui);
}

.right-section {
  display: flex;
  align-items: center;
  gap: var(--space-4);
}

.theme-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  background-color: transparent;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  color: var(--text-secondary);
  cursor: pointer;
  transition: border-color var(--transition-fast), color var(--transition-fast);
}

.theme-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
}

.theme-btn:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

.email {
  color: var(--text-secondary);
  font-size: var(--text-sm);
  font-family: var(--font-mono);
  text-decoration: none;
  transition: color 0.2s;
}

.email:hover {
  color: var(--accent);
}

.router-link-active.email {
  color: var(--accent);
}

.logout-btn {
  background-color: transparent;
  border: 1px solid var(--border);
  padding: var(--space-2) var(--space-4);
  border-radius: var(--radius-md);
  font-size: var(--text-sm);
  color: var(--text-secondary);
  font-family: var(--font-ui);
  cursor: pointer;
  transition: border-color 0.2s, color 0.2s;
}

.logout-btn:hover {
  border-color: var(--status-fail);
  color: var(--status-fail);
}
</style>

<script setup>
import { useRoute, RouterLink } from 'vue-router'
import { LayoutDashboard, GitCompareArrows, FileText, Users } from 'lucide-vue-next'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const authStore = useAuthStore()

const navItems = [
  { icon: LayoutDashboard, label: 'Dashboard', to: '/dashboard', name: 'dashboard' },
  { icon: GitCompareArrows, label: 'Comparaison', to: '/compare', name: 'compare' },
  { icon: FileText, label: 'Rapports', to: '/reports', name: 'reports' },
  { icon: Users, label: 'Utilisateurs', to: '/users', name: 'users', adminOnly: true }
]

const visibleItems = navItems.filter(item => !item.adminOnly || authStore.isAdmin())
</script>

<template>
  <aside class="sidebar">
    <!-- Logo -->
    <div class="logo">
      <div class="logo-icon">
        <span class="logo-bracket">[</span>
        <span class="logo-dot"></span>
        <span class="logo-bracket">]</span>
      </div>
      <span class="logo-text">HardenOS</span>
    </div>

    <!-- Divider -->
    <div class="divider"></div>

    <!-- Navigation -->
    <nav class="nav">
      <RouterLink
        v-for="item in visibleItems"
        :key="item.name"
        :to="item.to"
        class="nav-link"
        :class="{ active: route.name === item.name || (item.name === 'systems' && route.path.startsWith('/systems')) || (item.name === 'audits' && route.path.startsWith('/audits')) }"
        exact-active-class="active"
      >
        <component :is="item.icon" :size="18" class="icon" />
        <span class="label">{{ item.label }}</span>
      </RouterLink>
    </nav>

    <!-- Version -->
    <div class="version">v0.1.0</div>
  </aside>
</template>

<style scoped>
.sidebar {
  width: 240px;
  background-color: var(--bg-surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  height: 100vh;
}

.logo {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-6);
  border-bottom: 1px solid var(--border);
}

.logo-icon {
  display: flex;
  align-items: center;
  font-family: var(--font-mono);
  color: var(--accent);
  font-size: var(--text-lg);
  font-weight: 500;
}

.logo-bracket {
  color: var(--accent);
}

.logo-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background-color: var(--accent);
  margin: 0 3px;
  box-shadow: 0 0 8px var(--accent);
}

.logo-text {
  font-family: var(--font-mono);
  color: var(--text-primary);
  font-size: var(--text-base);
  font-weight: 500;
  letter-spacing: 0.5px;
}

.divider {
  border-bottom: 1px solid var(--border);
  margin: 0;
}

.nav {
  flex: 1;
  display: flex;
  flex-direction: column;
  padding: var(--space-3) 0;
  gap: 0;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-6);
  color: var(--text-secondary);
  font-size: var(--text-sm);
  text-decoration: none;
  transition: background-color 0.2s, color 0.2s, border-left-color 0.2s;
  border-left: 3px solid transparent;
}

.nav-link:hover {
  background-color: var(--bg-elevated);
  color: var(--text-primary);
}

.nav-link.active {
  background-color: var(--accent-dim);
  color: var(--accent);
  border-left-color: var(--accent);
  padding-left: calc(var(--space-6) - 3px);
}

/* Icône Lucide : hérite de la couleur du .nav-link via currentColor
   (secondaire → primary au survol → accent en actif). */
.icon {
  flex-shrink: 0;
}

.label {
  flex: 1;
}

.version {
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  padding: var(--space-6);
  text-align: center;
}
</style>

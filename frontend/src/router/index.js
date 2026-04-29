import { createRouter, createWebHistory } from 'vue-router'
import { useUiStore } from '@/stores/ui'

const routes = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue')
  },
  {
    path: '/',
    component: () => import('@/components/layout/AppLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        redirect: '/dashboard'
      },
      {
        path: 'dashboard',
        name: 'dashboard',
        component: () => import('@/views/DashboardView.vue')
      },
      {
        path: 'systems/:id',
        name: 'system-detail',
        component: () => import('@/views/SystemDetailView.vue')
      },
      {
        path: 'audits/:id',
        name: 'audit',
        component: () => import('@/views/AuditView.vue')
      },
      {
        path: 'remediation/:auditId',
        name: 'remediation',
        component: () => import('@/views/RemediationView.vue')
      },
      {
        path: 'compare',
        name: 'compare',
        component: () => import('@/views/CompareView.vue')
      },
      {
        path: 'reports',
        name: 'reports',
        component: () => import('@/views/ReportsView.vue')
      },
      {
        path: 'users',
        name: 'users',
        component: () => import('@/views/UsersView.vue'),
        meta: { role: 'admin' }
      },
      {
        // "Mon compte" : accessible à tout utilisateur authentifié (pas de role).
        path: 'account',
        name: 'account',
        component: () => import('@/views/AccountView.vue')
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('hardenos_access_token')

  // Rediriger les utilisateurs authentifiés qui tentent d'accéder à /login
  if (to.path === '/login') {
    if (token) return next('/dashboard')
    // Page de connexion : toujours sur le thème par défaut (sombre), quel que
    // soit un choix de session antérieur. L'utilisateur non connecté voit
    // toujours l'identité par défaut. resetTheme() purge aussi sessionStorage.
    try {
      useUiStore().resetTheme()
    } catch {
      // Pinia non initialisé (cas limite) : le défaut HTML statique s'applique.
    }
    return next()
  }

  if (to.meta.requiresAuth && !token) {
    return next('/login')
  }

  // Vérification du rôle si la route le requiert.
  // Le store ui n'est résolvable qu'après l'init de Pinia (donc ici, dans le
  // guard à l'exécution — pas au top-level du module).
  if (to.meta.role) {
    const rawUser = localStorage.getItem('hardenos_user')
    const user = rawUser ? JSON.parse(rawUser) : null
    if (!user || user.role !== to.meta.role) {
      try {
        useUiStore().notify(
          `Accès refusé : la page « ${String(to.name)} » est réservée aux ${to.meta.role}s.`,
          'error'
        )
      } catch {
        // Pinia non initialisé : on redirige silencieusement
      }
      return next('/dashboard')
    }
  }

  next()
})

export default router

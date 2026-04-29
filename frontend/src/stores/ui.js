// Store d'état d'interface transverse : ouverture de la sidebar, thème
// (sombre/clair), filtres actifs du parc, et notification globale (toast)
// partagée par toutes les vues.
import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

// Persistance « de session » : le choix de thème vit dans sessionStorage.
// → il survit à un rechargement de page (F5),
// → mais est effacé à la déconnexion (auth.clearSession() appelle resetTheme)
//   et à la fermeture de l'onglet.
// Au prochain login, on repart donc sur le défaut SOMBRE.
const THEME_KEY = 'hardenos-theme'
const DEFAULT_THEME = 'dark'

// Nettoyage d'un résidu de version antérieure : le thème a été un temps persisté
// en localStorage. On l'y purge une bonne fois pour éviter toute divergence
// trompeuse (DOM ↔ storage) au diagnostic. La source de vérité est sessionStorage.
localStorage.removeItem(THEME_KEY)

const initialTheme = () => {
  const saved = sessionStorage.getItem(THEME_KEY)
  return saved === 'light' || saved === 'dark' ? saved : DEFAULT_THEME
}

export const useUiStore = defineStore('ui', () => {
  const sidebarOpen = ref(true)

  // Thème : reflété sur <html data-theme="…"> ; tokens.css fait basculer les
  // jeux de couleurs. Défaut CLAIR (aussi posé statiquement dans index.html
  // pour éviter tout flash avant le démarrage de JS).
  const theme = ref(initialTheme())

  // Source de vérité UNIQUE : un watch synchronise TOUJOURS <html> et le
  // sessionStorage sur la valeur du store. Impossible de désynchroniser le
  // DOM et l'état, quel que soit le chemin (boot, toggle, HMR). immediate:true
  // applique dès l'instanciation du store.
  watch(
    theme,
    (value) => {
      document.documentElement.setAttribute('data-theme', value)
      sessionStorage.setItem(THEME_KEY, value)
    },
    { immediate: true }
  )

  const toggleTheme = () => {
    theme.value = theme.value === 'dark' ? 'light' : 'dark'
  }

  // Remet le thème au défaut et purge la mémoire de session. Appelé à la
  // déconnexion ET à l'arrivée sur /login (le guard du routeur), pour que la
  // page de connexion soit toujours sur le thème par défaut (sombre).
  const resetTheme = () => {
    sessionStorage.removeItem(THEME_KEY)
    theme.value = DEFAULT_THEME
  }

  const activeFilters = ref({
    os: null,
    risk: null,
    domain: null,
    cis_level: null
  })
  const notification = ref(null)

  const toggleSidebar = () => {
    sidebarOpen.value = !sidebarOpen.value
  }

  const setFilter = (key, value) => {
    activeFilters.value[key] = value
  }

  const clearFilters = () => {
    activeFilters.value = {
      os: null,
      risk: null,
      domain: null,
      cis_level: null
    }
  }

  // Affiche un toast (le rendu est centralisé dans AppLayout, donc n'importe
  // quelle vue peut notifier). Par défaut : 3 s pour success/info, mais
  // PERMANENT (fermeture manuelle via dismiss()) pour les erreurs — un
  // message d'erreur (souvent long, parfois à copier pour diagnostiquer)
  // qui disparaît avant d'être lu ne sert à rien. `duration` reste
  // surchageable explicitement (0 = permanent, N = ms) si besoin.
  const notify = (message, type = 'info', duration = null) => {
    notification.value = { message, type }

    const effectiveDuration = duration ?? (type === 'error' ? 0 : 3000)
    if (effectiveDuration > 0) {
      setTimeout(() => {
        notification.value = null
      }, effectiveDuration)
    }
  }

  const dismiss = () => {
    notification.value = null
  }

  return {
    sidebarOpen,
    theme,
    activeFilters,
    notification,
    toggleSidebar,
    toggleTheme,
    resetTheme,
    setFilter,
    clearFilters,
    notify,
    dismiss
  }
})

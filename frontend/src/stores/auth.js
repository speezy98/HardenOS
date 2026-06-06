import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import * as authApi from '@/api/auth.js'
import { useUiStore } from '@/stores/ui'

// Clés localStorage (source unique de vérité — réutilisées par client.js et le router guard)
export const ACCESS_TOKEN_KEY = 'hardenos_access_token'
export const REFRESH_TOKEN_KEY = 'hardenos_refresh_token'
export const USER_KEY = 'hardenos_user'

export const useAuthStore = defineStore('auth', () => {
  const accessToken = ref(localStorage.getItem(ACCESS_TOKEN_KEY) || null)
  const refreshToken = ref(localStorage.getItem(REFRESH_TOKEN_KEY) || null)
  const user = ref(JSON.parse(localStorage.getItem(USER_KEY) || 'null'))

  const isAuthenticated = computed(() => !!accessToken.value)

  // Persiste tokens + user dans le store et localStorage.
  const setSession = ({ access_token, refresh_token, user: u }) => {
    accessToken.value = access_token
    refreshToken.value = refresh_token
    user.value = u
    localStorage.setItem(ACCESS_TOKEN_KEY, access_token)
    localStorage.setItem(REFRESH_TOKEN_KEY, refresh_token)
    localStorage.setItem(USER_KEY, JSON.stringify(u))
  }

  // Nettoie l'état local et le localStorage (sans appel backend).
  const clearSession = () => {
    accessToken.value = null
    refreshToken.value = null
    user.value = null
    localStorage.removeItem(ACCESS_TOKEN_KEY)
    localStorage.removeItem(REFRESH_TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    // Le thème est une préférence de session : on le remet au défaut à la
    // déconnexion (le prochain utilisateur repart sur le thème par défaut).
    useUiStore().resetTheme()
  }

  const login = async (email, password) => {
    try {
      const { data } = await authApi.login(email, password)
      setSession(data)
      return data.user
    } catch (err) {
      // Message exploitable par LoginView (401 → identifiants invalides).
      const message =
        err.response?.status === 401
          ? 'Email ou mot de passe incorrect'
          : err.response?.data?.error || 'Échec de la connexion'
      throw new Error(message)
    }
  }

  const logout = async () => {
    try {
      // Révoque le token côté backend (best-effort).
      await authApi.logout()
    } catch {
      // Token déjà expiré/invalide : on déconnecte quand même côté interface.
    } finally {
      clearSession()
    }
  }

  // Récupère l'utilisateur courant (réhydratation / validation du token).
  const fetchCurrentUser = async () => {
    const { data } = await authApi.me()
    user.value = data
    localStorage.setItem(USER_KEY, JSON.stringify(data))
    return data
  }

  const isAdmin = () => user.value?.role === 'admin'

  return {
    accessToken,
    refreshToken,
    user,
    isAuthenticated,
    login,
    logout,
    fetchCurrentUser,
    setSession,
    clearSession,
    isAdmin
  }
})

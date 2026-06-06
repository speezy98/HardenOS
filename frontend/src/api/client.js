import axios from 'axios'
import router from '@/router/index.js'

// Clés localStorage — doivent rester alignées avec stores/auth.js.
const ACCESS_TOKEN_KEY = 'hardenos_access_token'
const REFRESH_TOKEN_KEY = 'hardenos_refresh_token'
const USER_KEY = 'hardenos_user'

const client = axios.create({
  // Base relative : les appels passent par le proxy Vite (/api → localhost:5001),
  // ce qui évite toute URL absolue codée en dur et le contournement du proxy.
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000
})

// Intercepteur de requête : ajoute l'access token courant.
client.interceptors.request.use((config) => {
  const token = localStorage.getItem(ACCESS_TOKEN_KEY)
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Déconnecte localement et redirige vers /login (refresh échoué).
const forceLogout = () => {
  localStorage.removeItem(ACCESS_TOKEN_KEY)
  localStorage.removeItem(REFRESH_TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
  if (router.currentRoute.value.path !== '/login') {
    router.push('/login')
  }
}

// Intercepteur de réponse : sur 401, tente UN refresh puis rejoue la requête.
client.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    // Pas un 401, ou pas de config exploitable : on propage.
    if (error.response?.status !== 401 || !originalRequest) {
      return Promise.reject(error)
    }

    // La requête de refresh elle-même a échoué, ou on a déjà réessayé :
    // on déconnecte pour éviter toute boucle infinie.
    if (originalRequest._skipAuthRefresh || originalRequest._retried) {
      forceLogout()
      return Promise.reject(error)
    }

    const refresh = localStorage.getItem(REFRESH_TOKEN_KEY)
    if (!refresh) {
      forceLogout()
      return Promise.reject(error)
    }

    originalRequest._retried = true
    try {
      // Import paresseux pour éviter une dépendance circulaire client ↔ api/auth.
      const { refreshToken } = await import('./auth.js')
      const { data } = await refreshToken(refresh)
      localStorage.setItem(ACCESS_TOKEN_KEY, data.access_token)
      originalRequest.headers.Authorization = `Bearer ${data.access_token}`
      return client(originalRequest)
    } catch (refreshError) {
      forceLogout()
      return Promise.reject(refreshError)
    }
  }
)

export default client

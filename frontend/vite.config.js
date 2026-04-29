import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')

  return {
    plugins: [vue()],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url))
      }
    },
    server: {
      port: 5173,
      proxy: {
        '/api': {
          // http par défaut : fonctionne immédiatement sur un clone neuf, sans
          // certificats déjà générés (le backend ne sert du HTTPS que si
          // BACKEND_TLS_CERT/KEY existent, cf. backend/wsgi.py). Pour tester
          // le chemin HTTPS localement, définir VITE_BACKEND_URL dans
          // frontend/.env (ex. https://localhost:5001).
          target: env.VITE_BACKEND_URL || 'https://localhost:5001',
          changeOrigin: true,
          // CA interne auto-signée (non reconnue par Node) : sans ça, le
          // proxy rejette la connexion HTTPS même avec un certificat backend
          // valide. Sans incidence en http.
          secure: false
        }
      }
    }
  }
})

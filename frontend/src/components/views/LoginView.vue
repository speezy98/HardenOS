<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const email = ref('')
const password = ref('')
const loading = ref(false)
const errorMessage = ref('')

const handleSubmit = async () => {
  errorMessage.value = ''
  loading.value = true
  
  try {
    await authStore.login(email.value, password.value)
    router.push('/dashboard')
  } catch (err) {
    errorMessage.value = err.message || 'Échec de la connexion'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-header">
        <div class="logo">
          <div class="logo-icon">
            <span class="logo-bracket">[</span>
            <span class="logo-dot"></span>
            <span class="logo-bracket">]</span>
          </div>
          <span class="logo-text">HardenOS</span>
        </div>
        <p class="subtitle">Scanner CIS Benchmark</p>
      </div>

      <form @submit.prevent="handleSubmit" class="login-form">
        <div class="field">
          <label for="email">Email</label>
          <input
            id="email"
            type="email"
            v-model="email"
            autocomplete="email"
            required
            :disabled="loading"
          />
        </div>

        <div class="field">
          <label for="password">Mot de passe</label>
          <input
            id="password"
            type="password"
            v-model="password"
            autocomplete="current-password"
            required
            :disabled="loading"
          />
        </div>

        <p v-if="errorMessage" class="error">{{ errorMessage }}</p>

        <button type="submit" class="submit-btn" :disabled="loading">
          {{ loading ? 'Connexion...' : 'Se connecter' }}
        </button>
      </form>
    </div>
  </div>
</template>

<style scoped>
@keyframes pulse {
  0%, 100% {
    opacity: 0.6;
  }
  50% {
    opacity: 1;
  }
}

.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: var(--bg-base);
  padding: var(--space-6);
}

.login-card {
  width: 100%;
  max-width: 400px;
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: var(--space-8);
  box-shadow: var(--shadow-lg);
}

.login-header {
  margin-bottom: var(--space-8);
  text-align: left;
}

.logo {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  margin-bottom: var(--space-2);
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
  animation: pulse 2s infinite;
}

.logo-text {
  font-family: var(--font-mono);
  color: var(--text-primary);
  font-size: var(--text-base);
  font-weight: 500;
  letter-spacing: 0.5px;
}

.subtitle {
  margin-top: var(--space-2);
  color: var(--text-muted);
  font-size: var(--text-sm);
  font-family: var(--font-mono);
  letter-spacing: 0.5px;
  margin: 0;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
}

.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.field label {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-secondary);
  font-family: var(--font-ui);
  font-weight: 500;
}

.field input {
  background-color: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  transition: var(--transition-base);
}

.field input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.field input:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.error {
  color: var(--status-fail);
  font-size: var(--text-sm);
  font-family: var(--font-mono);
  margin: 0;
}

.submit-btn {
  background-color: var(--accent);
  color: var(--bg-base);
  border: none;
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  font-weight: 600;
  cursor: pointer;
  transition: var(--transition-base);
  letter-spacing: 0.5px;
  margin-top: var(--space-2);
}

.submit-btn:hover:not(:disabled) {
  background-color: var(--accent-hover);
}

.submit-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>

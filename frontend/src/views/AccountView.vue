<script setup>
// Écran "Mon compte" — accessible à TOUT utilisateur authentifié (admin,
// auditor, readonly). Agit uniquement sur le compte courant (le backend
// identifie l'utilisateur via le JWT). Le rôle est affiché en lecture seule :
// il n'est jamais modifiable ici (seuls les endpoints admin le changent).
import { ref, reactive, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import * as accountApi from '@/api/account.js'
import RoleBadge from '@/components/audit/RoleBadge.vue'

const authStore = useAuthStore()
const uiStore = useUiStore()

const account = ref(null)
const loading = ref(true)
const loadError = ref(null)

const emailForm = reactive({ new_email: '', current_password: '', busy: false, error: null })
const pwdForm = reactive({
  current_password: '', new_password: '', confirm: '', busy: false, error: null
})

const statusLabel = (s) => ({ active: 'ACTIF', inactive: 'INACTIF', revoked: 'RÉVOQUÉ' })[s] || s

// Message d'erreur clair renvoyé par le backend (403 mauvais mdp, 409 email pris…).
const serverError = (err, fallback) => err?.response?.data?.error || fallback

const loadAccount = async () => {
  loading.value = true
  loadError.value = null
  try {
    const { data } = await accountApi.getAccount()
    account.value = data
    emailForm.new_email = data.email
  } catch (err) {
    loadError.value = serverError(err, 'Impossible de charger votre compte')
  } finally {
    loading.value = false
  }
}
onMounted(loadAccount)

// --- Changer l'email (re-confirmation du mot de passe actuel) --------------
const submitEmail = async () => {
  emailForm.error = null
  const newEmail = emailForm.new_email.trim()
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
    emailForm.error = 'Format email invalide'
    return
  }
  if (!emailForm.current_password) {
    emailForm.error = 'Mot de passe actuel requis'
    return
  }
  emailForm.busy = true
  try {
    const { data } = await accountApi.changeEmail({
      new_email: newEmail,
      current_password: emailForm.current_password
    })
    account.value = data
    emailForm.new_email = data.email
    emailForm.current_password = ''
    // Le store auth garde l'email affiché en haut à droite à jour.
    if (authStore.user) {
      authStore.user.email = data.email
      localStorage.setItem('hardenos_user', JSON.stringify(authStore.user))
    }
    uiStore.notify('Email mis à jour', 'success')
  } catch (err) {
    emailForm.error = serverError(err, 'Échec de la modification de l\'email')
  } finally {
    emailForm.busy = false
  }
}

// --- Changer le mot de passe (re-confirmation de l'ancien) -----------------
const submitPassword = async () => {
  pwdForm.error = null
  if (!pwdForm.current_password) {
    pwdForm.error = 'Mot de passe actuel requis'
    return
  }
  if (pwdForm.new_password.length < 8) {
    pwdForm.error = 'Le nouveau mot de passe doit contenir au moins 8 caractères'
    return
  }
  if (pwdForm.new_password !== pwdForm.confirm) {
    pwdForm.error = 'La confirmation ne correspond pas'
    return
  }
  pwdForm.busy = true
  try {
    await accountApi.changePassword({
      current_password: pwdForm.current_password,
      new_password: pwdForm.new_password
    })
    pwdForm.current_password = ''
    pwdForm.new_password = ''
    pwdForm.confirm = ''
    uiStore.notify('Mot de passe mis à jour', 'success')
  } catch (err) {
    pwdForm.error = serverError(err, 'Échec de la modification du mot de passe')
  } finally {
    pwdForm.busy = false
  }
}
</script>

<template>
  <div class="account-view">
    <header class="account-header">
      <h1>Mon compte</h1>
      <p class="subtitle">Gérez votre email et votre mot de passe</p>
    </header>

    <div v-if="loading" class="loading-state">Chargement…</div>
    <div v-else-if="loadError" class="error-state">{{ loadError }}</div>

    <template v-else-if="account">
      <!-- Infos du compte (rôle en lecture seule) -->
      <section class="card">
        <h2 class="card-title">Informations</h2>
        <div class="info-grid">
          <div class="info-item">
            <span class="info-label">Email</span>
            <span class="info-value">{{ account.email }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Rôle</span>
            <RoleBadge :role="account.role" />
          </div>
          <div class="info-item">
            <span class="info-label">Statut</span>
            <span class="status-pill" :data-status="account.status">
              {{ statusLabel(account.status) }}
            </span>
          </div>
        </div>
        <p class="readonly-note">
          Le rôle est défini par un administrateur et ne peut pas être modifié ici.
        </p>
      </section>

      <!-- Changer l'email -->
      <section class="card">
        <h2 class="card-title">Changer mon email</h2>
        <form class="form" @submit.prevent="submitEmail">
          <div class="field">
            <label class="field-label">Nouvel email</label>
            <input v-model="emailForm.new_email" type="email" class="field-input"
                   autocomplete="email" placeholder="nouvel@hardenos.local" />
          </div>
          <div class="field">
            <label class="field-label">Mot de passe actuel (confirmation)</label>
            <input v-model="emailForm.current_password" type="password" class="field-input"
                   autocomplete="current-password" placeholder="Votre mot de passe actuel" />
          </div>
          <span v-if="emailForm.error" class="field-error">{{ emailForm.error }}</span>
          <div class="form-actions">
            <button type="submit" class="primary-btn" :disabled="emailForm.busy">
              {{ emailForm.busy ? 'Envoi…' : 'Mettre à jour l\'email' }}
            </button>
          </div>
        </form>
      </section>

      <!-- Changer le mot de passe -->
      <section class="card">
        <h2 class="card-title">Changer mon mot de passe</h2>
        <form class="form" @submit.prevent="submitPassword">
          <div class="field">
            <label class="field-label">Mot de passe actuel</label>
            <input v-model="pwdForm.current_password" type="password" class="field-input"
                   autocomplete="current-password" placeholder="Votre mot de passe actuel" />
          </div>
          <div class="field">
            <label class="field-label">Nouveau mot de passe</label>
            <input v-model="pwdForm.new_password" type="password" class="field-input"
                   autocomplete="new-password" placeholder="Au moins 8 caractères" />
          </div>
          <div class="field">
            <label class="field-label">Confirmer le nouveau mot de passe</label>
            <input v-model="pwdForm.confirm" type="password" class="field-input"
                   autocomplete="new-password" placeholder="Répétez le nouveau mot de passe" />
          </div>
          <span v-if="pwdForm.error" class="field-error">{{ pwdForm.error }}</span>
          <div class="form-actions">
            <button type="submit" class="primary-btn" :disabled="pwdForm.busy">
              {{ pwdForm.busy ? 'Envoi…' : 'Mettre à jour le mot de passe' }}
            </button>
          </div>
        </form>
      </section>
    </template>
  </div>
</template>

<style scoped>
.account-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-6);
  max-width: 640px;
}

.account-header h1 {
  font-size: var(--text-2xl);
  font-family: var(--font-mono);
  color: var(--text-primary);
  margin: 0;
}

.account-header .subtitle {
  font-size: var(--text-sm);
  font-family: var(--font-mono);
  color: var(--text-muted);
  margin: var(--space-1) 0 0 0;
}

.loading-state,
.error-state {
  padding: var(--space-8);
  text-align: center;
  font-family: var(--font-mono);
  font-size: var(--text-sm);
}
.loading-state { color: var(--text-muted); }
.error-state { color: var(--status-fail); }

.card {
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-6);
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
}

.card-title {
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  color: var(--text-primary);
  margin: 0;
}

.info-grid {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.info-item {
  display: flex;
  align-items: center;
  gap: var(--space-4);
}

.info-label {
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-muted);
  width: 80px;
}

.info-value {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--text-primary);
}

.status-pill {
  display: inline-block;
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: 500;
  letter-spacing: 0.5px;
  border: 1px solid;
}
.status-pill[data-status="active"] {
  color: var(--status-pass);
  background-color: rgba(var(--rgb-status-pass), 0.1);
  border-color: var(--status-pass);
}
.status-pill[data-status="inactive"] {
  color: var(--status-warn);
  background-color: rgba(var(--rgb-status-warn), 0.1);
  border-color: var(--status-warn);
}
.status-pill[data-status="revoked"] {
  color: var(--text-muted);
  background-color: rgba(var(--rgb-status-na), 0.1);
  border-color: var(--text-muted);
}

.readonly-note {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-muted);
  margin: 0;
}

.form {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.field-label {
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-muted);
}

.field-input {
  background-color: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
}
.field-input:focus { outline: none; border-color: var(--accent); }

.field-error {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--status-fail);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
}

.primary-btn {
  background-color: var(--accent);
  color: var(--bg-base);
  border: none;
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-5);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  font-weight: 600;
  cursor: pointer;
  transition: var(--transition-base);
}
.primary-btn:hover:not(:disabled) { background-color: var(--accent-hover); }
.primary-btn:disabled { opacity: 0.6; cursor: not-allowed; }
</style>

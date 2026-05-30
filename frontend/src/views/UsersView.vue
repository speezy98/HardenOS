<script setup>
import { ref, computed, onMounted, reactive } from 'vue'
import { useUsersStore } from '@/stores/users'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import RoleBadge from '@/components/audit/RoleBadge.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'

const usersStore = useUsersStore()
const authStore = useAuthStore()
const uiStore = useUiStore()

const filterRole = ref('')
const filterStatus = ref('')

// Modale de création / édition
const formModal = reactive({
  open: false,
  mode: 'create', // 'create' | 'edit'
  user: null,
  // password : mot de passe initial (création) ou réinitialisation (édition).
  data: { email: '', role: 'auditor', password: '' },
  errors: {},
  busy: false
})

// Confirmation destructive (révoquer / réactiver / supprimer) via ConfirmDialog.
const confirmModal = reactive({
  open: false,
  type: null,    // 'revoke' | 'reactivate' | 'delete'
  user: null,
  busy: false
})

onMounted(async () => {
  try {
    await usersStore.fetchUsers()
  } catch (err) {
    uiStore.notify(usersStore.errorMessage(err, 'Chargement des utilisateurs impossible'), 'error')
  }
})

// --- Filtres -------------------------------------------------------------

const filteredUsers = computed(() => {
  let list = usersStore.users
  if (filterRole.value)   list = list.filter(u => u.role === filterRole.value)
  if (filterStatus.value) list = list.filter(u => u.status === filterStatus.value)
  return list
})

const counts = computed(() => usersStore.counts)

// --- Helpers d'affichage -------------------------------------------------

const relativeTime = (iso) => {
  if (!iso) return 'jamais'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1)   return 'à l\'instant'
  if (mins < 60)  return `il y a ${mins} min`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `il y a ${hours}h`
  const days = Math.floor(hours / 24)
  return `il y a ${days}j`
}

const statusLabel = (s) => ({ active: 'ACTIF', inactive: 'INACTIF', revoked: 'RÉVOQUÉ' })[s]

// L'utilisateur connecté ne doit pas pouvoir se supprimer / révoquer lui-même :
// le backend le refuse (409), on masque donc ces actions sur sa propre ligne.
const isCurrentUser = (user) => authStore.user?.id === user.id

// --- Création / édition --------------------------------------------------

const openCreate = () => {
  formModal.mode = 'create'
  formModal.user = null
  formModal.data = { email: '', role: 'auditor', password: '' }
  formModal.errors = {}
  formModal.open = true
}

const openEdit = (user) => {
  formModal.mode = 'edit'
  formModal.user = user
  // password vide en édition = « ne pas changer » ; rempli = réinitialisation.
  formModal.data = { email: user.email, role: user.role, password: '' }
  formModal.errors = {}
  formModal.open = true
}

const closeForm = () => {
  if (formModal.busy) return
  formModal.open = false
}

// Validation front : email format + unicité (création), mot de passe requis à
// la création. Le backend reste l'autorité finale (l'erreur est retoastée).
const validateForm = () => {
  const errors = {}
  const email = formModal.data.email.trim()
  const password = formModal.data.password

  if (!email) {
    errors.email = 'Email requis'
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.email = 'Format email invalide'
  } else {
    const dup = usersStore.users.find(
      u => u.email.toLowerCase() === email.toLowerCase() && u.id !== formModal.user?.id
    )
    if (dup) errors.email = 'Cet email existe déjà'
  }

  if (formModal.mode === 'create' && !password) {
    errors.password = 'Mot de passe initial requis'
  } else if (password && password.length < 8) {
    errors.password = 'Au moins 8 caractères'
  }

  formModal.errors = errors
  return Object.keys(errors).length === 0
}

const handleSubmit = async () => {
  if (!validateForm()) return
  formModal.busy = true
  try {
    if (formModal.mode === 'create') {
      await usersStore.createUser({
        email: formModal.data.email.trim(),
        role: formModal.data.role,
        password: formModal.data.password
      })
      uiStore.notify(`Utilisateur ${formModal.data.email.trim()} créé`, 'success')
    } else {
      // On n'envoie le mot de passe que s'il a été saisi (réinitialisation).
      const payload = {
        email: formModal.data.email.trim(),
        role: formModal.data.role
      }
      if (formModal.data.password) payload.password = formModal.data.password
      await usersStore.updateUser(formModal.user.id, payload)
      uiStore.notify(`Utilisateur ${formModal.data.email.trim()} mis à jour`, 'success')
    }
    formModal.open = false
  } catch (err) {
    // Refus backend (409 email pris, dernier admin, 400 rôle invalide…) :
    // message clair, la modale reste ouverte.
    uiStore.notify(usersStore.errorMessage(err, 'Action refusée par le serveur'), 'error')
  } finally {
    formModal.busy = false
  }
}

// --- Révocation / réactivation / suppression -----------------------------

const askRevoke = (user) => {
  confirmModal.type = 'revoke'
  confirmModal.user = user
  confirmModal.open = true
}

const askReactivate = (user) => {
  confirmModal.type = 'reactivate'
  confirmModal.user = user
  confirmModal.open = true
}

const askDelete = (user) => {
  confirmModal.type = 'delete'
  confirmModal.user = user
  confirmModal.open = true
}

const cancelConfirm = () => {
  if (confirmModal.busy) return
  confirmModal.open = false
  confirmModal.user = null
  confirmModal.type = null
}

const executeConfirm = async () => {
  const u = confirmModal.user
  if (!u) return cancelConfirm()
  confirmModal.busy = true
  try {
    if (confirmModal.type === 'revoke') {
      await usersStore.revokeUser(u.id)
      uiStore.notify(`Accès de ${u.email} révoqué`, 'success')
    } else if (confirmModal.type === 'reactivate') {
      await usersStore.reactivateUser(u.id)
      uiStore.notify(`Accès de ${u.email} réactivé`, 'success')
    } else if (confirmModal.type === 'delete') {
      await usersStore.deleteUser(u.id)
      uiStore.notify(`Utilisateur ${u.email} supprimé`, 'success')
    }
    confirmModal.busy = false
    confirmModal.open = false
    confirmModal.user = null
    confirmModal.type = null
  } catch (err) {
    // Garde-fous backend (auto-suppression, dernier admin actif…) : on affiche
    // le message renvoyé, sans prétendre que l'action a réussi.
    uiStore.notify(usersStore.errorMessage(err, 'Action refusée par le serveur'), 'error')
    confirmModal.busy = false
    confirmModal.open = false
    confirmModal.user = null
    confirmModal.type = null
  }
}

const confirmTitle = computed(() => {
  if (confirmModal.type === 'revoke') return 'Révoquer cet accès ?'
  if (confirmModal.type === 'reactivate') return 'Réactiver cet accès ?'
  if (confirmModal.type === 'delete') return 'Supprimer cet utilisateur ?'
  return ''
})

const confirmMessage = computed(() => {
  if (!confirmModal.user) return ''
  if (confirmModal.type === 'revoke') {
    return `${confirmModal.user.email} ne pourra plus se connecter. Cette action est réversible (bouton Réactiver).`
  }
  if (confirmModal.type === 'reactivate') {
    return `${confirmModal.user.email} pourra de nouveau se connecter.`
  }
  if (confirmModal.type === 'delete') {
    return `${confirmModal.user.email} sera définitivement supprimé. Cette action est irréversible.`
  }
  return ''
})

const confirmCta = computed(() => {
  if (confirmModal.type === 'delete') return 'Supprimer définitivement'
  if (confirmModal.type === 'reactivate') return 'Réactiver'
  return 'Révoquer'
})
</script>

<template>
  <div class="users-view">
    <header class="users-header">
      <div class="header-titles">
        <h1>Utilisateurs</h1>
        <p class="subtitle">
          {{ counts.total }} comptes
          · {{ counts.admin }} {{ counts.admin > 1 ? 'admins' : 'admin' }}
          · {{ counts.auditor }} {{ counts.auditor > 1 ? 'auditeurs' : 'auditeur' }}
          · {{ counts.readonly }} lecture seule
        </p>
      </div>
      <button class="primary-btn" @click="openCreate">
        + Nouvel utilisateur
      </button>
    </header>

    <section class="users-section">
      <div class="section-header">
        <h2>Comptes du parc</h2>
        <div class="filters">
          <select v-model="filterRole" class="filter-select">
            <option value="">Tous rôles</option>
            <option value="admin">Admin</option>
            <option value="auditor">Auditeur</option>
            <option value="readonly">Lecture seule</option>
          </select>
          <select v-model="filterStatus" class="filter-select">
            <option value="">Tous statuts</option>
            <option value="active">Actif</option>
            <option value="inactive">Inactif</option>
            <option value="revoked">Révoqué</option>
          </select>
        </div>
      </div>

      <div class="users-table">
        <div class="table-head">
          <span>#</span>
          <span>EMAIL</span>
          <span>RÔLE</span>
          <span>DERNIÈRE CONNEXION</span>
          <span>STATUT</span>
          <span>ACTIONS</span>
        </div>

        <div
          v-for="(user, idx) in filteredUsers"
          :key="user.id"
          class="user-row"
          :data-status="user.status"
        >
          <span class="row-index">{{ String(idx + 1).padStart(2, '0') }}</span>
          <span class="row-email">{{ user.email }}</span>
          <RoleBadge :role="user.role" />
          <span class="row-time">{{ relativeTime(user.last_login_at) }}</span>
          <span class="status-pill" :data-status="user.status">{{ statusLabel(user.status) }}</span>
          <div class="row-actions">
            <template v-if="!isCurrentUser(user)">
              <button class="ghost-btn" @click="openEdit(user)">Modifier</button>
              <button
                v-if="user.status === 'revoked'"
                class="ghost-btn"
                @click="askReactivate(user)"
              >
                Réactiver
              </button>
              <button
                v-else
                class="ghost-btn ghost-btn--warn"
                @click="askRevoke(user)"
              >
                Révoquer
              </button>
              <button class="ghost-btn ghost-btn--danger" @click="askDelete(user)">
                Supprimer
              </button>
            </template>
            <span v-else class="self-tag">vous</span>
          </div>
        </div>

        <div v-if="filteredUsers.length === 0" class="empty-state">
          <template v-if="usersStore.users.length === 0">
            Aucun utilisateur enregistré.
          </template>
          <template v-else>
            Aucun utilisateur ne correspond aux filtres.
          </template>
        </div>
      </div>
    </section>

    <!-- Modale création / édition -->
    <Teleport to="body">
      <div v-if="formModal.open" class="modal-overlay" @click.self="closeForm">
        <div class="modal">
          <h2 class="modal-title">
            {{ formModal.mode === 'create' ? 'Nouvel utilisateur' : 'Modifier l\'utilisateur' }}
          </h2>

          <div class="field">
            <label class="field-label">Email</label>
            <input
              v-model="formModal.data.email"
              type="email"
              class="field-input"
              placeholder="exemple@hardenos.local"
            />
            <span v-if="formModal.errors.email" class="field-error">
              {{ formModal.errors.email }}
            </span>
          </div>

          <div class="field">
            <label class="field-label">Rôle</label>
            <select v-model="formModal.data.role" class="field-input">
              <option value="admin">Admin</option>
              <option value="auditor">Auditeur</option>
              <option value="readonly">Lecture seule</option>
            </select>
          </div>

          <div class="field">
            <label class="field-label">
              {{ formModal.mode === 'create' ? 'Mot de passe initial' : 'Nouveau mot de passe' }}
            </label>
            <input
              v-model="formModal.data.password"
              type="password"
              class="field-input"
              autocomplete="new-password"
              :placeholder="formModal.mode === 'create'
                ? 'Au moins 8 caractères'
                : 'Laisser vide pour ne pas changer'"
            />
            <span v-if="formModal.errors.password" class="field-error">
              {{ formModal.errors.password }}
            </span>
            <span v-else-if="formModal.mode === 'edit'" class="field-hint">
              Renseigner ce champ réinitialise le mot de passe de l'utilisateur.
            </span>
          </div>

          <div class="modal-actions">
            <button class="secondary-btn" :disabled="formModal.busy" @click="closeForm">Annuler</button>
            <button class="primary-btn" :disabled="formModal.busy" @click="handleSubmit">
              {{ formModal.busy
                ? 'Envoi…'
                : (formModal.mode === 'create' ? 'Créer' : 'Enregistrer') }}
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Confirmation destructive (révoquer / réactiver / supprimer) -->
    <Teleport to="body">
      <ConfirmDialog
        v-if="confirmModal.open"
        :title="confirmTitle"
        :message="confirmMessage"
        :confirm-label="confirmCta"
        :danger="confirmModal.type === 'delete'"
        :busy="confirmModal.busy"
        @confirm="executeConfirm"
        @cancel="cancelConfirm"
      />
    </Teleport>
  </div>
</template>

<style scoped>
.users-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-8);
}

.users-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
}

.header-titles h1 {
  font-size: var(--text-2xl);
  font-family: var(--font-mono);
  color: var(--text-primary);
  margin: 0;
}

.header-titles .subtitle {
  font-size: var(--text-sm);
  font-family: var(--font-mono);
  color: var(--text-muted);
  margin: var(--space-1) 0 0 0;
}

.users-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.section-header h2 {
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  color: var(--text-primary);
  margin: 0;
}

.filters {
  display: flex;
  gap: var(--space-3);
}

.filter-select {
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-2) var(--space-3);
  color: var(--text-primary);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  cursor: pointer;
}

/* Table */
.users-table {
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
}

.table-head {
  display: grid;
  grid-template-columns: 40px 1fr 120px 180px 120px 280px;
  gap: var(--space-4);
  padding: var(--space-3) var(--space-6);
  background-color: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-muted);
  font-family: var(--font-ui);
  font-weight: 500;
}

.user-row {
  display: grid;
  grid-template-columns: 40px 1fr 120px 180px 120px 280px;
  gap: var(--space-4);
  align-items: center;
  padding: var(--space-3) var(--space-6);
  border-bottom: 1px solid var(--border-subtle);
  transition: var(--transition-base);
}

.user-row:hover {
  background-color: var(--bg-elevated);
}

.user-row[data-status="revoked"] {
  opacity: 0.55;
}

.user-row:last-child { border-bottom: none; }

.row-index {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-muted);
}

.row-email {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--text-primary);
}

.row-time {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-secondary);
}

/* Status pill (interne à la vue, distinct du StatusBadge CIS) */
.status-pill {
  display: inline-block;
  width: fit-content;
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

/* Actions */
.row-actions {
  display: flex;
  gap: var(--space-2);
  align-items: center;
}

.ghost-btn {
  background-color: transparent;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  padding: var(--space-1) var(--space-3);
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  cursor: pointer;
  transition: var(--transition-base);
}

.ghost-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
}

.ghost-btn--warn:hover {
  border-color: var(--status-warn);
  color: var(--status-warn);
}

.ghost-btn--danger:hover {
  border-color: var(--status-fail);
  color: var(--status-fail);
}

.self-tag {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-muted);
  font-style: italic;
}

.empty-state {
  padding: var(--space-8);
  text-align: center;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
}

/* Boutons partagés */
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

.primary-btn:hover {
  background-color: var(--accent-hover);
}

.secondary-btn {
  background-color: transparent;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-5);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  cursor: pointer;
  transition: var(--transition-base);
}

.secondary-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
}

/* Modale */
.modal-overlay {
  position: fixed;
  inset: 0;
  z-index: 100;
  background-color: var(--overlay);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--space-6);
}

.modal {
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-6) var(--space-8);
  width: 100%;
  max-width: 520px;
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
  box-shadow: var(--shadow-lg);
}

.modal-title {
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  color: var(--text-primary);
  margin: 0;
}

.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.field-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--space-4);
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

.field-input:focus {
  outline: none;
  border-color: var(--accent);
}

.field-input--readonly {
  opacity: 0.5;
  cursor: not-allowed;
}

.field-error {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--status-fail);
}

.field-hint {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-muted);
}

.secondary-btn:disabled,
.primary-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  margin-top: var(--space-2);
}
</style>

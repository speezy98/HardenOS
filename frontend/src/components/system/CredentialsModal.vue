<script setup>
// Modale de saisie des credentials SSH avant de lancer un audit sur un système
// qui n'en a pas encore. Le mot de passe n'est jamais persisté côté frontend ;
// il part directement au backend (qui le chiffre si "enregistrer" est coché).
import { ref } from 'vue'

defineProps({
  hostname: { type: String, default: '' }
})

const emit = defineEmits(['confirm', 'cancel'])

const sshUser = ref('')
const sshPassword = ref('')
const saveCredentials = ref(true)
const error = ref('')

const submit = () => {
  if (!sshUser.value || !sshPassword.value) {
    error.value = 'Utilisateur et mot de passe SSH requis.'
    return
  }
  emit('confirm', {
    ssh_user: sshUser.value,
    ssh_password: sshPassword.value,
    save_credentials: saveCredentials.value
  })
}
</script>

<template>
  <div class="modal-overlay" @click.self="emit('cancel')">
    <div class="modal-card">
      <h2 class="modal-title">Credentials SSH</h2>
      <p class="modal-sub">
        Aucun identifiant enregistré pour
        <span class="mono">{{ hostname }}</span>. Saisissez un compte SSH avec
        accès en lecture pour exécuter l'audit (lecture seule, aucune modification
        de la machine).
      </p>

      <form class="modal-form" @submit.prevent="submit">
        <div class="field">
          <label for="ssh-user">Utilisateur SSH</label>
          <input id="ssh-user" v-model="sshUser" type="text" autocomplete="off" />
        </div>
        <div class="field">
          <label for="ssh-pass">Mot de passe SSH</label>
          <input id="ssh-pass" v-model="sshPassword" type="password" autocomplete="off" />
        </div>
        <label class="checkbox">
          <input v-model="saveCredentials" type="checkbox" />
          Enregistrer (chiffré) pour les prochains audits
        </label>

        <p v-if="error" class="modal-error">{{ error }}</p>

        <div class="modal-actions">
          <button type="button" class="btn-ghost" @click="emit('cancel')">Annuler</button>
          <button type="submit" class="btn-primary">Lancer l'audit</button>
        </div>
      </form>
    </div>
  </div>
</template>

<style scoped>
.modal-overlay {
  position: fixed;
  inset: 0;
  background-color: var(--overlay);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  padding: var(--space-6);
}

.modal-card {
  width: 100%;
  max-width: 440px;
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: var(--space-8);
  box-shadow: var(--shadow-lg);
}

.modal-title {
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  color: var(--text-primary);
  margin: 0 0 var(--space-3) 0;
}

.modal-sub {
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-muted);
  line-height: 1.5;
  margin: 0 0 var(--space-5) 0;
}

.mono { font-family: var(--font-mono); color: var(--text-secondary); }

.modal-form { display: flex; flex-direction: column; gap: var(--space-4); }

.field { display: flex; flex-direction: column; gap: var(--space-2); }

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
}

.field input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.checkbox {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-secondary);
  cursor: pointer;
}

.modal-error {
  color: var(--status-fail);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  margin: 0;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  margin-top: var(--space-2);
}

.btn-ghost {
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
.btn-ghost:hover { border-color: var(--accent); color: var(--accent); }

.btn-primary {
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
.btn-primary:hover { background-color: var(--accent-hover); }
</style>

<script setup>
// Boîte de dialogue de confirmation générique, cohérente avec les modales
// existantes (CredentialsModal / AddMachineModal). Le bouton de confirmation
// peut être marqué "danger" (couleur d'alerte) pour les actions destructives.
defineProps({
  title: { type: String, required: true },
  message: { type: String, default: '' },
  confirmLabel: { type: String, default: 'Confirmer' },
  cancelLabel: { type: String, default: 'Annuler' },
  danger: { type: Boolean, default: false },
  // Action en cours : bloque les boutons (évite les doubles clics).
  busy: { type: Boolean, default: false }
})

const emit = defineEmits(['confirm', 'cancel'])
</script>

<template>
  <div class="modal-overlay" @click.self="emit('cancel')">
    <div class="modal-card" role="dialog" aria-modal="true">
      <h2 class="modal-title">{{ title }}</h2>
      <p v-if="message" class="modal-message">{{ message }}</p>

      <div class="modal-actions">
        <button type="button" class="btn-ghost" :disabled="busy" @click="emit('cancel')">
          {{ cancelLabel }}
        </button>
        <button
          type="button"
          class="btn-confirm"
          :class="{ 'btn-confirm--danger': danger }"
          :disabled="busy"
          @click="emit('confirm')"
        >
          {{ busy ? 'Suppression…' : confirmLabel }}
        </button>
      </div>
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

.modal-message {
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-muted);
  line-height: 1.5;
  margin: 0 0 var(--space-6) 0;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
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
.btn-ghost:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }

.btn-confirm {
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
.btn-confirm:hover:not(:disabled) { background-color: var(--accent-hover); }

/* Variante destructive : couleur d'alerte du design system (pas l'accent vert). */
.btn-confirm--danger { background-color: var(--status-fail); color: var(--bg-base); }
.btn-confirm--danger:hover:not(:disabled) {
  background-color: var(--status-fail);
  filter: brightness(1.12);
}

.btn-ghost:disabled,
.btn-confirm:disabled { opacity: 0.6; cursor: not-allowed; }
</style>

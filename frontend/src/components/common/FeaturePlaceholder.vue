<script setup>
// État neutre « fonctionnalité en cours d'intégration ».
// Utilisé pour les vues dont le branchement backend n'est pas encore fait,
// afin de ne jamais afficher une page qui semble cassée.
defineProps({
  title: { type: String, required: true },
  message: { type: String, default: '' }
})
</script>

<template>
  <div class="feature-placeholder">
    <div class="placeholder-card">
      <div class="placeholder-icon">
        <span class="bracket">[</span>
        <span class="dot"></span>
        <span class="bracket">]</span>
      </div>
      <h1 class="placeholder-title">{{ title }}</h1>
      <p class="placeholder-tag">Fonctionnalité en cours d'intégration</p>
      <p v-if="message" class="placeholder-message">{{ message }}</p>
    </div>
  </div>
</template>

<style scoped>
@keyframes pulse {
  0%, 100% { opacity: 0.5; }
  50% { opacity: 1; }
}

.feature-placeholder {
  min-height: 60vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--space-6);
}

.placeholder-card {
  max-width: 440px;
  text-align: center;
  background-color: var(--bg-surface);
  border: 1px dashed var(--border);
  border-radius: var(--radius-lg);
  padding: var(--space-10) var(--space-8);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-4);
}

.placeholder-icon {
  display: flex;
  align-items: center;
  font-family: var(--font-mono);
  color: var(--accent);
  font-size: var(--text-2xl);
  font-weight: 500;
  margin-bottom: var(--space-2);
}

.bracket { color: var(--accent); }

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: var(--accent);
  margin: 0 var(--space-2);
  box-shadow: 0 0 10px var(--accent);
  animation: pulse 2s infinite;
}

.placeholder-title {
  font-family: var(--font-mono);
  font-size: var(--text-xl);
  color: var(--text-primary);
  margin: 0;
}

.placeholder-tag {
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--accent);
  margin: 0;
}

.placeholder-message {
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-muted);
  line-height: 1.6;
  margin: var(--space-2) 0 0 0;
}
</style>

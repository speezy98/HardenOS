<script setup>
import { useRoute } from 'vue-router'

const route = useRoute()
</script>

<template>
  <div class="placeholder-view">
    <h1>Audit</h1>
    <p class="id">ID: {{ route.params.id }}</p>
    <p class="subtitle">Résultats d'audit — à implémenter</p>
  </div>
</template>

<style scoped>
.placeholder-view {
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background-color: var(--bg-base);
  color: var(--text-primary);
  font-family: var(--font-mono);
  gap: var(--space-4);
}

.placeholder-view h1 {
  font-size: var(--text-2xl);
}

.placeholder-view .id {
  color: var(--text-secondary);
  font-size: var(--text-sm);
}

.placeholder-view .subtitle {
  color: var(--text-secondary);
  font-size: var(--text-sm);
}
</style>

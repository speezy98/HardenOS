<script setup>
import { computed } from 'vue'

const props = defineProps({
  level: {
    type: String,
    required: true,
    validator: (val) => ['low', 'moderate', 'high', 'critical'].includes(val)
  }
})

const label = computed(() => {
  const labels = {
    'low': 'FAIBLE',
    'moderate': 'MODÉRÉ',
    'high': 'ÉLEVÉ',
    'critical': 'CRITIQUE'
  }
  return labels[props.level]
})
</script>

<template>
  <span
    class="risk-badge"
    :data-level="level"
  >
    {{ label }}
  </span>
</template>

<style scoped>
.risk-badge {
  display: inline-block;
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: 500;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

.risk-badge[data-level="low"] {
  background-color: rgba(var(--rgb-risk-low), 0.1);
  color: var(--risk-low);
  border: 1px solid var(--risk-low);
}

.risk-badge[data-level="moderate"] {
  background-color: rgba(var(--rgb-risk-moderate), 0.1);
  color: var(--risk-moderate);
  border: 1px solid var(--risk-moderate);
}

.risk-badge[data-level="high"] {
  background-color: rgba(var(--rgb-risk-high), 0.1);
  color: var(--risk-high);
  border: 1px solid var(--risk-high);
}

/* Critique : fond plus soutenu (pas d'animation — la couleur et la densité
   du fond portent l'alerte, lisible dans les deux thèmes). */
.risk-badge[data-level="critical"] {
  background-color: rgba(var(--rgb-risk-critical), 0.18);
  color: var(--risk-critical);
  border: 1px solid var(--risk-critical);
}
</style>

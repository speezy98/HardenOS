<script setup>
import { computed } from 'vue'
import { CheckCircle2, XCircle, AlertTriangle, MinusCircle } from 'lucide-vue-next'

const props = defineProps({
  status: {
    type: String,
    required: true,
    validator: (val) => ['pass', 'fail', 'warn', 'na'].includes(val)
  }
})

const config = computed(() => {
  const configs = {
    'pass': { label: 'CONFORME', icon: CheckCircle2 },
    'fail': { label: 'NON CONFORME', icon: XCircle },
    'warn': { label: 'AVERTISSEMENT', icon: AlertTriangle },
    'na': { label: 'N/A', icon: MinusCircle }
  }
  return configs[props.status]
})
</script>

<template>
  <span class="status-badge" :data-status="status">
    <component :is="config.icon" :size="13" class="symbol" />
    <span class="label">{{ config.label }}</span>
  </span>
</template>

<style scoped>
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: 500;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

/* Icône Lucide : hérite de la couleur du badge (var(--status-*)) via currentColor. */
.symbol {
  flex-shrink: 0;
}

.status-badge[data-status="pass"] {
  color: var(--status-pass);
  background-color: rgba(var(--rgb-status-pass), 0.1);
  border: 1px solid var(--status-pass);
}

.status-badge[data-status="fail"] {
  color: var(--status-fail);
  background-color: rgba(var(--rgb-status-fail), 0.1);
  border: 1px solid var(--status-fail);
}

.status-badge[data-status="warn"] {
  color: var(--status-warn);
  background-color: rgba(var(--rgb-status-warn), 0.1);
  border: 1px solid var(--status-warn);
}

.status-badge[data-status="na"] {
  color: var(--status-na);
  background-color: rgba(var(--rgb-status-na), 0.1);
  border: 1px solid var(--status-na);
}
</style>

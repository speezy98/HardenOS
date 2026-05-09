<script setup>
import { computed } from 'vue'

const props = defineProps({
  label: {
    type: String,
    required: true
  },
  value: {
    type: Number,
    required: true
  },
  weight: {
    type: Number,
    required: true
  }
})

const status = computed(() => {
  if (props.value >= 80) return 'pass'
  if (props.value >= 60) return 'warn'
  return 'fail'
})
</script>

<template>
  <div class="domain-bar">
    <div class="bar-header">
      <span class="bar-label">{{ label }}</span>
      <span class="bar-weight">{{ weight }}%</span>
    </div>
    <div class="bar-track">
      <div class="bar-fill" :style="{ width: value + '%' }" :data-status="status"></div>
      <span class="bar-value">{{ value }}</span>
    </div>
  </div>
</template>

<style scoped>
.domain-bar {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.bar-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.bar-label {
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-primary);
  font-weight: 500;
}

.bar-weight {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-muted);
}

.bar-track {
  position: relative;
  height: 24px;
  background-color: var(--bg-elevated);
  border-radius: var(--radius-sm);
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  border-radius: var(--radius-sm);
  transition: width 600ms ease;
}

.bar-fill[data-status="pass"] {
  background-color: var(--status-pass);
}

.bar-fill[data-status="warn"] {
  background-color: var(--status-warn);
}

.bar-fill[data-status="fail"] {
  background-color: var(--status-fail);
}

.bar-value {
  position: absolute;
  right: var(--space-3);
  top: 50%;
  transform: translateY(-50%);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-primary);
  font-weight: 500;
}
</style>

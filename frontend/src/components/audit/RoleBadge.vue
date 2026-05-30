<script setup>
import { computed } from 'vue'

const props = defineProps({
  role: {
    type: String,
    required: true,
    validator: (val) => ['admin', 'auditor', 'readonly'].includes(val)
  }
})

const label = computed(() => {
  const labels = {
    admin: 'ADMIN',
    auditor: 'AUDITEUR',
    readonly: 'LECTURE'
  }
  return labels[props.role]
})
</script>

<template>
  <span class="role-badge" :data-role="role">
    {{ label }}
  </span>
</template>

<style scoped>
.role-badge {
  display: inline-block;
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  font-weight: 500;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

.role-badge[data-role="admin"] {
  color: var(--role-admin);
  background-color: rgba(var(--rgb-role-admin), 0.1);
  border: 1px solid var(--role-admin);
}

.role-badge[data-role="auditor"] {
  color: var(--role-auditor);
  background-color: rgba(var(--rgb-role-auditor), 0.1);
  border: 1px solid var(--role-auditor);
}

.role-badge[data-role="readonly"] {
  color: var(--role-readonly);
  background-color: rgba(var(--rgb-role-readonly), 0.1);
  border: 1px solid var(--role-readonly);
}
</style>

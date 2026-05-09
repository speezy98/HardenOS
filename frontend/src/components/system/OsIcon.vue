<script setup>
// Wrapper qui choisit l'icône SVG en fonction du type d'OS.
// Évite la logique conditionnelle dispersée dans les vues consommatrices.
import LinuxIcon from '@/components/icons/LinuxIcon.vue'
import WindowsIcon from '@/components/icons/WindowsIcon.vue'

defineProps({
  osType: {
    type: String,
    required: true,
    validator: (val) => ['linux', 'windows'].includes(val)
  },
  size: { type: Number, default: 16 }
})
</script>

<template>
  <LinuxIcon   v-if="osType === 'linux'"   :size="size" />
  <WindowsIcon v-else-if="osType === 'windows'" :size="size" />
</template>

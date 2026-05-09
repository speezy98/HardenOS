<script setup>
defineProps({
  size: { type: Number, default: 16 }
})
</script>

<template>
  <img
    src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/windows11/windows11-original.svg"
    :width="size"
    :height="size"
    alt="Windows"
    class="os-icon"
  />
</template>

<style scoped>
.os-icon {
  display: inline-block;
  vertical-align: middle;
  object-fit: contain;
}
</style>

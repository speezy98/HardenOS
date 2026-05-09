<script setup>
defineProps({
  size: { type: Number, default: 16 }
})
</script>

<template>
  <img
    src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/linux/linux-original.svg"
    :width="size"
    :height="size"
    alt="Linux"
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

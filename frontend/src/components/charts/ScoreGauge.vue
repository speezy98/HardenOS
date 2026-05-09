<script setup>
// Jauge circulaire SVG du score global (0-100). Couleur selon le seuil,
// cohérente avec les tokens de risque.
import { computed } from 'vue'

const props = defineProps({
  score: { type: Number, default: 0 },
  size: { type: Number, default: 140 }
})

const RADIUS = 54
const CIRC = 2 * Math.PI * RADIUS

const clamped = computed(() => Math.max(0, Math.min(100, props.score ?? 0)))
const dash = computed(() => (clamped.value / 100) * CIRC)

// Mêmes bornes que le backend : >=90 vert, >=70 jaune, >=50 orange, sinon rouge.
const colorVar = computed(() => {
  const s = clamped.value
  if (s >= 90) return 'var(--risk-low)'
  if (s >= 70) return 'var(--risk-moderate)'
  if (s >= 50) return 'var(--risk-high)'
  return 'var(--risk-critical)'
})
</script>

<template>
  <div
    class="gauge"
    :style="{ width: size + 'px', height: size + 'px' }"
  >
    <svg
      viewBox="0 0 140 140"
      class="gauge-svg"
    >
      <circle
        cx="70"
        cy="70"
        :r="RADIUS"
        class="gauge-track"
      />
      <circle
        cx="70"
        cy="70"
        :r="RADIUS"
        class="gauge-fill"
        :stroke="colorVar"
        :stroke-dasharray="`${dash} ${CIRC}`"
      />
    </svg>
    <div class="gauge-center">
      <!-- Taille du texte proportionnelle à la jauge (utilisable en compact). -->
      <span
        class="gauge-score"
        :style="{ color: colorVar, fontSize: size * 0.22 + 'px' }"
      >{{ Math.round(clamped) }}</span>
      <span
        class="gauge-unit"
        :style="{ fontSize: Math.max(9, size * 0.085) + 'px' }"
      >/ 100</span>
    </div>
  </div>
</template>

<style scoped>
.gauge {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.gauge-svg {
  width: 100%;
  height: 100%;
  transform: rotate(-90deg);
}

.gauge-track {
  fill: none;
  stroke: var(--bg-elevated);
  stroke-width: 10;
}

.gauge-fill {
  fill: none;
  stroke-width: 10;
  stroke-linecap: round;
  transition: stroke-dasharray 700ms ease;
}

.gauge-center {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.gauge-score {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-weight: 600;
  line-height: 1;
}

.gauge-unit {
  font-family: var(--font-mono);
  color: var(--text-muted);
  margin-top: 2px;
}
</style>

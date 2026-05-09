<script setup>
// Radar SVG fait main des 6 scores par domaine (0-100).
// Pas de dépendance externe : léger, cohérent avec l'ambiance dark/SOC.
import { computed } from 'vue'

const props = defineProps({
  scores: {
    type: Object,
    required: true
    // { access, network, logging, crypto, updates, services }
  }
})

const DOMAINS = [
  { key: 'access', label: 'Accès' },
  { key: 'network', label: 'Réseau' },
  { key: 'logging', label: 'Journal.' },
  { key: 'crypto', label: 'Chiffr.' },
  { key: 'updates', label: 'MAJ' },
  { key: 'services', label: 'Services' }
]

const SIZE = 260
const CENTER = SIZE / 2
const RADIUS = 90
const RINGS = [25, 50, 75, 100]

// Angle d'un axe i (départ en haut, sens horaire).
const angleFor = (i) => (Math.PI * 2 * i) / DOMAINS.length - Math.PI / 2

const pointAt = (value, i) => {
  const r = (Math.max(0, Math.min(100, value ?? 0)) / 100) * RADIUS
  const a = angleFor(i)
  return [CENTER + r * Math.cos(a), CENTER + r * Math.sin(a)]
}

// Grille (anneaux concentriques) + axes.
const ringPolygons = computed(() =>
  RINGS.map((pct) =>
    DOMAINS.map((_, i) => {
      const r = (pct / 100) * RADIUS
      const a = angleFor(i)
      return `${CENTER + r * Math.cos(a)},${CENTER + r * Math.sin(a)}`
    }).join(' ')
  )
)

const axes = computed(() =>
  DOMAINS.map((d, i) => {
    const a = angleFor(i)
    return {
      x2: CENTER + RADIUS * Math.cos(a),
      y2: CENTER + RADIUS * Math.sin(a)
    }
  })
)

// Polygone des valeurs réelles.
const valuePolygon = computed(() =>
  DOMAINS.map((d, i) => pointAt(props.scores?.[d.key], i).join(',')).join(' ')
)

const valuePoints = computed(() =>
  DOMAINS.map((d, i) => {
    const [x, y] = pointAt(props.scores?.[d.key], i)
    return { x, y, value: props.scores?.[d.key] }
  })
)

// Position des libellés, légèrement au-delà du rayon.
const labels = computed(() =>
  DOMAINS.map((d, i) => {
    const a = angleFor(i)
    const lr = RADIUS + 22
    const x = CENTER + lr * Math.cos(a)
    const y = CENTER + lr * Math.sin(a)
    let anchor = 'middle'
    if (Math.cos(a) > 0.3) anchor = 'start'
    else if (Math.cos(a) < -0.3) anchor = 'end'
    return { ...d, x, y, anchor, value: props.scores?.[d.key] }
  })
)
</script>

<template>
  <div class="radar">
    <svg :viewBox="`0 0 ${SIZE} ${SIZE}`" class="radar-svg" role="img"
         aria-label="Scores de conformité par domaine">
      <!-- Anneaux de la grille -->
      <polygon
        v-for="(poly, idx) in ringPolygons"
        :key="`ring-${idx}`"
        :points="poly"
        class="ring"
      />
      <!-- Axes -->
      <line
        v-for="(ax, i) in axes"
        :key="`axis-${i}`"
        :x1="CENTER" :y1="CENTER" :x2="ax.x2" :y2="ax.y2"
        class="axis"
      />
      <!-- Zone des valeurs -->
      <polygon :points="valuePolygon" class="value-area" />
      <!-- Points -->
      <circle
        v-for="(p, i) in valuePoints"
        :key="`pt-${i}`"
        :cx="p.x" :cy="p.y" r="3"
        class="value-point"
      />
      <!-- Libellés + valeur -->
      <text
        v-for="(l, i) in labels"
        :key="`lbl-${i}`"
        :x="l.x" :y="l.y"
        :text-anchor="l.anchor"
        class="domain-label"
      >
        {{ l.label }} <tspan class="domain-value">{{ l.value ?? '—' }}</tspan>
      </text>
    </svg>
  </div>
</template>

<style scoped>
.radar {
  display: flex;
  justify-content: center;
  padding: var(--space-4);
}

.radar-svg {
  width: 100%;
  max-width: 340px;
  height: auto;
  overflow: visible;
}

.ring {
  fill: none;
  stroke: var(--border);
  stroke-width: 1;
  opacity: 0.5;
}

.axis {
  stroke: var(--border);
  stroke-width: 1;
  opacity: 0.6;
}

.value-area {
  fill: var(--accent-dim);
  stroke: var(--accent);
  stroke-width: 2;
  stroke-linejoin: round;
}

.value-point {
  fill: var(--accent);
}

.domain-label {
  fill: var(--text-secondary);
  font-family: var(--font-ui);
  font-size: 11px;
}

.domain-value {
  fill: var(--text-primary);
  font-family: var(--font-mono);
  font-weight: 600;
}
</style>

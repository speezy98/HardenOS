<script setup>
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import OsIcon from '@/components/system/OsIcon.vue'
import RiskBadge from '@/components/audit/RiskBadge.vue'

const props = defineProps({
  system: {
    type: Object,
    required: true
  },
  index: {
    type: Number,
    required: true
  },
  // Résumé du dernier audit du système ({ score_global, risk_level, … })
  // ou null si jamais audité. Fourni par la vue parente.
  audit: {
    type: Object,
    default: null
  },
  // Met brièvement en évidence une machine (ex. celle qu'on vient de créer).
  highlight: {
    type: Boolean,
    default: false
  }
})

const formattedIndex = computed(() => {
  return props.index.toString().padStart(2, '0')
})

// Score du dernier audit (arrondi) ; null si non audité / non scoré.
const score = computed(() => {
  const s = props.audit?.score_global
  return typeof s === 'number' ? Math.round(s) : null
})

// Mêmes bornes que le backend et ScoreGauge : >=90, >=70, >=50, sinon critique.
const scoreBand = computed(() => {
  if (score.value === null) return null
  if (score.value >= 90) return 'low'
  if (score.value >= 70) return 'moderate'
  if (score.value >= 50) return 'high'
  return 'critical'
})

const riskLevel = computed(() => {
  const level = props.audit?.risk_level
  return ['low', 'moderate', 'high', 'critical'].includes(level) ? level : null
})

// last_audit_at peut être null (jamais audité). On n'invente aucun audit.
const lastAuditLabel = computed(() => {
  if (!props.system.last_audit_at) return 'Non audité'
  const now = new Date()
  const auditTime = new Date(props.system.last_audit_at)
  const diffMins = Math.floor((now - auditTime) / 60000)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)
  if (diffMins < 1) return "à l'instant"
  if (diffMins < 60) return `il y a ${diffMins} min`
  if (diffHours < 24) return `il y a ${diffHours}h`
  return `il y a ${diffDays}j`
})
</script>

<template>
  <RouterLink
    :to="`/systems/${system.id}`"
    class="system-row"
    :class="{ highlight }"
  >
    <span class="row-index">{{ formattedIndex }}</span>
    <div class="row-host">
      <span class="hostname">{{ system.hostname }}</span>
      <span class="ip">{{ system.ip_address }}</span>
    </div>
    <span class="row-os">
      <OsIcon
        :os-type="system.os_type"
        :size="14"
      />
      {{ system.os_version }}
    </span>
    <span class="row-mode">{{ system.connection_mode }}</span>
    <span
      v-if="score !== null"
      class="row-score"
      :data-band="scoreBand"
    >
      {{ score }}<span class="score-unit">%</span>
    </span>
    <span
      v-else
      class="row-score row-score--na"
    >—</span>
    <span class="row-risk">
      <RiskBadge
        v-if="riskLevel"
        :level="riskLevel"
      />
      <span
        v-else
        class="row-risk--na"
      >—</span>
    </span>
    <span
      class="row-status"
      :data-status="system.status"
    >
      <span class="status-dot" />
      {{ system.status === 'online' ? 'en ligne' : 'hors ligne' }}
    </span>
    <span
      class="row-audit"
      :class="{ 'not-audited': !system.last_audit_at }"
    >
      {{ lastAuditLabel }}
    </span>
  </RouterLink>
</template>

<style scoped>
/* Doit rester STRICTEMENT identique au .table-head de DashboardView. */
.system-row {
  display: grid;
  grid-template-columns: 40px minmax(220px, 1.4fr) 188px 96px 76px 108px 104px 120px;
  gap: var(--space-4);
  align-items: center;
  min-width: 1052px;
  padding: var(--space-3) var(--space-5);
  border-bottom: 1px solid var(--border-subtle);
  text-decoration: none;
  color: var(--text-primary);
  transition: background-color var(--transition-fast);
  cursor: pointer;
}

.system-row:hover {
  background-color: var(--bg-elevated);
}

/* Machine récemment créée : mise en avant en AMBRE (accent d'action), pour la
   distinguer nettement du bleu de marque (sélection / lien / menu actif). */
.system-row.highlight {
  background-color: var(--accent-action-dim);
  box-shadow: inset 3px 0 0 var(--accent-action);
}

.row-index {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-size: var(--text-xs);
  color: var(--text-muted);
}

.row-host {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.hostname {
  display: block;
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ip {
  display: block;
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-size: var(--text-xs);
  color: var(--text-muted);
  margin-top: 1px;
}

.row-os {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  font-size: var(--text-sm);
  color: var(--text-secondary);
  white-space: nowrap;
}

/* L'icône OS ne doit pas rétrécir et voler de la place au libellé. */
.row-os :deep(svg) {
  flex-shrink: 0;
}

.row-mode {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

/* Score du dernier audit, coloré par seuil (mêmes bornes que la jauge). */
.row-score {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-size: var(--text-sm);
  font-weight: 600;
  text-align: right;
}

.score-unit {
  font-weight: 400;
  font-size: var(--text-xs);
  color: var(--text-muted);
}

.row-score[data-band="low"] { color: var(--risk-low); }
.row-score[data-band="moderate"] { color: var(--risk-moderate); }
.row-score[data-band="high"] { color: var(--risk-high); }
.row-score[data-band="critical"] { color: var(--risk-critical); }

.row-score--na,
.row-risk--na {
  color: var(--text-muted);
  font-weight: 400;
}

.row-status {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  letter-spacing: 0.5px;
  white-space: nowrap;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.row-status[data-status="online"] {
  color: var(--status-pass);
}

.row-status[data-status="online"] .status-dot {
  background-color: var(--status-pass);
}

.row-status[data-status="offline"] {
  color: var(--text-muted);
}

.row-status[data-status="offline"] .status-dot {
  background-color: var(--text-muted);
}

.row-audit {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-size: var(--text-xs);
  color: var(--text-muted);
  text-align: right;
  white-space: nowrap;
}

/* Italique discret UNIQUEMENT quand la machine n'a jamais été auditée. */
.not-audited {
  font-style: italic;
}
</style>

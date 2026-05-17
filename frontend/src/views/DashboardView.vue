<script setup>
import { ref, computed, onMounted } from 'vue'
import { useSystemsStore } from '@/stores/systems'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import * as auditsApi from '@/api/audits.js'
import SystemCard from '@/components/system/SystemCard.vue'
import AddMachineModal from '@/components/system/AddMachineModal.vue'
import ScoreGauge from '@/components/charts/ScoreGauge.vue'

const systemsStore = useSystemsStore()
const authStore = useAuthStore()
const ui = useUiStore()

const filterOs = ref('')
const filterStatus = ref('')

// Ajout de machine réservé à auditor + admin (le backend reste l'autorité).
const canAddMachine = computed(() =>
  ['auditor', 'admin'].includes(authStore.user?.role)
)

// Modale d'ajout : création réelle en deux temps déléguée au store (brique 3).
const showAddModal = ref(false)

const openAddModal = () => {
  systemsStore.createError = null
  showAddModal.value = true
}

const handleAddSubmit = async (payload) => {
  try {
    const created = await systemsStore.createMachine(payload)
    // Succès : fermer la modale et recharger les résumés d'audit du parc.
    showAddModal.value = false
    ui.notify(`Machine « ${created.hostname} » ajoutée`, 'success')
    await loadAuditSummaries()
  } catch {
    // Échec (POST ou PUT credentials) : on GARDE la modale ouverte ; le message
    // (createError) est affiché dans la modale via la prop server-error.
  }
}

// Derniers audits par système audité (latest audit résumé), chargés une fois.
const latestBySystem = ref({}) // { system_id: { score_global, risk_level, ... } }
const auditLoading = ref(false)

const kpis = computed(() => {
  const list = systemsStore.systems
  return {
    total: list.length,
    online: list.filter((s) => s.status === 'online').length,
    offline: list.filter((s) => s.status !== 'online').length,
    linux: list.filter((s) => s.os_type === 'linux').length,
    windows: list.filter((s) => s.os_type === 'windows').length
  }
})

// Synthèse audit réelle, basée sur les derniers audits chargés.
const auditStats = computed(() => {
  const list = systemsStore.systems
  const audited = list.filter((s) => s.last_audit_at)
  const scored = audited
    .map((s) => latestBySystem.value[s.id])
    .filter((a) => a && typeof a.score_global === 'number')

  const risk = { low: 0, moderate: 0, high: 0, critical: 0 }
  for (const a of scored) {
    if (a.risk_level && risk[a.risk_level] !== undefined) risk[a.risk_level]++
  }
  const avg =
    scored.length > 0
      ? Math.round(scored.reduce((sum, a) => sum + a.score_global, 0) / scored.length)
      : null

  return {
    auditedCount: audited.length,
    notAuditedCount: list.length - audited.length,
    avgScore: avg,
    risk,
    riskTotal: risk.low + risk.moderate + risk.high + risk.critical
  }
})

// Segments de la mini-barre de répartition (uniquement les niveaux non nuls).
const riskSegments = computed(() => {
  const { risk } = auditStats.value
  return [
    { level: 'low', count: risk.low },
    { level: 'moderate', count: risk.moderate },
    { level: 'high', count: risk.high },
    { level: 'critical', count: risk.critical }
  ].filter((s) => s.count > 0)
})

const filteredSystems = computed(() => {
  let result = [...systemsStore.systems]
  if (filterOs.value) {
    result = result.filter((s) => s.os_type === filterOs.value)
  }
  if (filterStatus.value) {
    result = result.filter((s) => s.status === filterStatus.value)
  }
  return result
})

// Charge le dernier audit de chaque système AUDITÉ (1 requête par système
// audité, en parallèle). Choix assumé : pas de N+1 sur tout le parc, seulement
// sur les systèmes ayant un last_audit_at. À remplacer par un endpoint agrégé
// côté backend si le parc devient très grand.
const loadAuditSummaries = async () => {
  const audited = systemsStore.systems.filter((s) => s.last_audit_at)
  if (audited.length === 0) return
  auditLoading.value = true
  try {
    const results = await Promise.allSettled(
      audited.map((s) => auditsApi.listForSystem(s.id))
    )
    const map = {}
    results.forEach((res, i) => {
      if (res.status === 'fulfilled' && res.value.data.length > 0) {
        map[audited[i].id] = res.value.data[0] // le plus récent (trié backend)
      }
    })
    latestBySystem.value = map
  } finally {
    auditLoading.value = false
  }
}

onMounted(async () => {
  await systemsStore.fetchSystems()
  await loadAuditSummaries()
})
</script>

<template>
  <div class="dashboard">
    <header class="dashboard-header">
      <div class="header-titles">
        <h1>Vue d'ensemble</h1>
        <p class="subtitle">
          Parc surveillé · {{ kpis.total }} systèmes
        </p>
      </div>
      <button
        v-if="canAddMachine"
        class="add-machine-btn"
        @click="openAddModal"
      >
        + Ajouter une machine
      </button>
    </header>

    <!-- Bande d'indicateurs clés : une seule surface, cellules séparées
         par des filets — lecture d'un coup d'œil, densité SOC. -->
    <section
      class="kpi-strip"
      aria-label="Indicateurs clés du parc"
    >
      <div class="kpi-cell">
        <span class="kpi-label">Parc</span>
        <span class="kpi-value">{{ kpis.total }}</span>
        <span class="kpi-sub">{{ kpis.linux }} linux · {{ kpis.windows }} windows</span>
      </div>

      <div class="kpi-cell">
        <span class="kpi-label">Disponibilité</span>
        <span class="kpi-value">
          {{ kpis.online }}<span class="kpi-sep">/ {{ kpis.total }}</span>
        </span>
        <span class="kpi-sub">{{ kpis.offline }} hors ligne</span>
      </div>

      <div class="kpi-cell">
        <span class="kpi-label">Score moyen parc</span>
        <ScoreGauge
          v-if="auditStats.avgScore !== null"
          :score="auditStats.avgScore"
          :size="72"
        />
        <span
          v-else
          class="kpi-value kpi-value--na"
        >N/D</span>
        <span class="kpi-sub">
          {{ auditStats.auditedCount }}/{{ kpis.total }} audités ·
          {{ auditStats.notAuditedCount }} non audité(s)
        </span>
      </div>

      <div class="kpi-cell">
        <span class="kpi-label">Critiques</span>
        <span
          class="kpi-value"
          :data-alert="auditStats.risk.critical > 0"
        >
          {{ auditStats.risk.critical }}
        </span>
        <span class="kpi-sub">{{ auditStats.risk.high }} élevé(s) à surveiller</span>
      </div>

      <div class="kpi-cell kpi-cell--risk">
        <span class="kpi-label">Répartition des risques</span>
        <template v-if="auditStats.riskTotal > 0">
          <!-- Barre empilée proportionnelle (segments séparés de 2px) -->
          <div
            class="dist-bar"
            role="img"
            aria-label="Répartition des niveaux de risque"
          >
            <span
              v-for="seg in riskSegments"
              :key="seg.level"
              class="dist-seg"
              :data-level="seg.level"
              :style="{ flexGrow: seg.count }"
            />
          </div>
          <div class="risk-dist">
            <span
              class="risk-chip"
              data-level="low"
              :data-zero="auditStats.risk.low === 0"
            >{{ auditStats.risk.low }} faible</span>
            <span
              class="risk-chip"
              data-level="moderate"
              :data-zero="auditStats.risk.moderate === 0"
            >{{ auditStats.risk.moderate }} modéré</span>
            <span
              class="risk-chip"
              data-level="high"
              :data-zero="auditStats.risk.high === 0"
            >{{ auditStats.risk.high }} élevé</span>
            <span
              class="risk-chip"
              data-level="critical"
              :data-zero="auditStats.risk.critical === 0"
            >{{ auditStats.risk.critical }} critique</span>
          </div>
        </template>
        <span
          v-else
          class="kpi-sub"
        >Aucun système audité</span>
      </div>
    </section>

    <section class="systems-section">
      <div class="section-header">
        <h2>
          Systèmes
          <span class="section-count">{{ filteredSystems.length }}</span>
        </h2>
        <div class="filters">
          <select
            v-model="filterOs"
            class="filter-select"
          >
            <option value="">
              Tous OS
            </option>
            <option value="linux">
              Linux
            </option>
            <option value="windows">
              Windows
            </option>
          </select>
          <select
            v-model="filterStatus"
            class="filter-select"
          >
            <option value="">
              Tous statuts
            </option>
            <option value="online">
              En ligne
            </option>
            <option value="offline">
              Hors ligne
            </option>
          </select>
        </div>
      </div>

      <!-- Chargement -->
      <div
        v-if="systemsStore.loading"
        class="state-block"
      >
        Chargement des systèmes…
      </div>

      <!-- Erreur (backend injoignable, etc.) -->
      <div
        v-else-if="systemsStore.error"
        class="state-block state-block--error"
      >
        {{ systemsStore.error }}
        <button
          class="retry-btn"
          @click="systemsStore.fetchSystems"
        >
          Réessayer
        </button>
      </div>

      <!-- Tableau dense du parc -->
      <div
        v-else
        class="systems-table"
      >
        <div class="table-head">
          <span>#</span>
          <span>Hostname / IP</span>
          <span>OS</span>
          <span>Mode</span>
          <span class="head-right">Score</span>
          <span>Risque</span>
          <span>Statut</span>
          <span class="head-right">Dernier audit</span>
        </div>
        <SystemCard
          v-for="(system, idx) in filteredSystems"
          :key="system.id"
          :system="system"
          :index="idx + 1"
          :audit="latestBySystem[system.id] || null"
          :highlight="system.id === systemsStore.lastCreatedId"
        />

        <!-- Aucun système en base -->
        <div
          v-if="systemsStore.total === 0"
          class="empty-state"
        >
          Aucun système enregistré.
        </div>
        <!-- Des systèmes existent mais aucun ne passe les filtres -->
        <div
          v-else-if="filteredSystems.length === 0"
          class="empty-state"
        >
          Aucun système ne correspond aux filtres.
        </div>
      </div>
    </section>

    <!-- Modale d'ajout de machine (auditor / admin) -->
    <AddMachineModal
      v-if="showAddModal"
      :busy="systemsStore.creating"
      :server-error="systemsStore.createError"
      @submit="handleAddSubmit"
      @cancel="showAddModal = false"
    />
  </div>
</template>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: var(--space-7);
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
}

.add-machine-btn {
  background-color: var(--accent);
  color: var(--accent-contrast);
  border: none;
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-5);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  font-weight: 600;
  cursor: pointer;
  transition: background-color var(--transition-base);
}
.add-machine-btn:hover { background-color: var(--accent-hover); }

.header-titles h1 {
  font-size: var(--text-2xl);
  font-family: var(--font-mono);
  color: var(--text-primary);
  margin: 0;
}

.header-titles .subtitle {
  font-size: var(--text-sm);
  font-family: var(--font-mono);
  color: var(--text-muted);
  margin: var(--space-1) 0 0 0;
}

/* ---------- Bande KPI ---------- */

.kpi-strip {
  display: grid;
  grid-template-columns: repeat(4, 1fr) 1.7fr;
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
}

.kpi-cell {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: var(--space-3);
  padding: var(--space-5) var(--space-6);
  border-left: 1px solid var(--border-subtle);
  min-width: 0;
}

.kpi-cell:first-child {
  border-left: none;
}

.kpi-label {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-secondary);
  font-family: var(--font-ui);
  font-weight: 500;
}

.kpi-value {
  font-size: 1.75rem;
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-weight: 500;
  color: var(--text-primary);
  line-height: 1;
}

.kpi-value[data-alert="true"] {
  color: var(--risk-critical);
}

.kpi-value--na {
  color: var(--text-muted);
}

.kpi-sep {
  font-size: var(--text-sm);
  color: var(--text-muted);
  margin-left: var(--space-1);
}

.kpi-sub {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-size: var(--text-xs);
  color: var(--text-muted);
}

/* Mini-barre empilée de répartition des risques (2px d'écart entre segments). */
.dist-bar {
  display: flex;
  gap: 2px;
  height: 6px;
  width: 100%;
}

.dist-seg {
  border-radius: 2px;
  min-width: 6px;
}

.dist-seg[data-level="low"] { background-color: var(--risk-low); }
.dist-seg[data-level="moderate"] { background-color: var(--risk-moderate); }
.dist-seg[data-level="high"] { background-color: var(--risk-high); }
.dist-seg[data-level="critical"] { background-color: var(--risk-critical); }

.risk-dist {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-1) var(--space-2);
}

.risk-chip {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-size: var(--text-xs);
  padding: 1px var(--space-2);
  border-radius: var(--radius-sm);
  border: 1px solid;
  white-space: nowrap;
}
.risk-chip[data-level="low"] { color: var(--risk-low); border-color: var(--risk-low); background-color: rgba(var(--rgb-risk-low), 0.1); }
.risk-chip[data-level="moderate"] { color: var(--risk-moderate); border-color: var(--risk-moderate); background-color: rgba(var(--rgb-risk-moderate), 0.1); }
.risk-chip[data-level="high"] { color: var(--risk-high); border-color: var(--risk-high); background-color: rgba(var(--rgb-risk-high), 0.1); }
.risk-chip[data-level="critical"] { color: var(--risk-critical); border-color: var(--risk-critical); background-color: rgba(var(--rgb-risk-critical), 0.1); }

/* Niveau absent du parc : atténué, mais l'information reste lisible. */
.risk-chip[data-zero="true"] {
  opacity: 0.45;
}

/* Bande KPI sur écrans étroits : 2 colonnes, répartition en pleine largeur. */
@media (max-width: 1200px) {
  .kpi-strip {
    grid-template-columns: repeat(2, 1fr);
  }
  .kpi-cell {
    border-left: none;
    border-top: 1px solid var(--border-subtle);
  }
  .kpi-cell:nth-child(-n + 2) {
    border-top: none;
  }
  .kpi-cell:nth-child(even) {
    border-left: 1px solid var(--border-subtle);
  }
  .kpi-cell--risk {
    grid-column: 1 / -1;
    border-left: none;
  }
}

/* ---------- Section Systèmes ---------- */

.systems-section {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.section-header h2 {
  font-size: var(--text-lg);
  font-family: var(--font-mono);
  color: var(--text-primary);
  margin: 0;
  display: flex;
  align-items: baseline;
  gap: var(--space-2);
}

.section-count {
  font-size: var(--text-xs);
  font-variant-numeric: tabular-nums;
  color: var(--text-muted);
  background-color: var(--bg-elevated);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-full);
  padding: 1px var(--space-2);
}

.filters {
  display: flex;
  gap: var(--space-3);
}

.filter-select {
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-1) var(--space-3);
  color: var(--text-primary);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  cursor: pointer;
}

.systems-table {
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow-x: auto;
}

/* Doit rester STRICTEMENT identique au .system-row de SystemCard. */
.table-head {
  display: grid;
  grid-template-columns: 40px minmax(220px, 1.4fr) 188px 96px 76px 108px 104px 120px;
  gap: var(--space-4);
  min-width: 1052px;
  padding: var(--space-3) var(--space-5);
  background-color: var(--bg-elevated);
  border-bottom: 1px solid var(--border);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-secondary);
  font-family: var(--font-ui);
  font-weight: 500;
}

.head-right {
  text-align: right;
}

.state-block {
  padding: var(--space-8);
  text-align: center;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-4);
}

.state-block--error {
  color: var(--status-fail);
  border-color: var(--status-fail);
}

.retry-btn {
  background-color: transparent;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-2) var(--space-4);
  color: var(--text-secondary);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  cursor: pointer;
}

.retry-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
}

.empty-state {
  padding: var(--space-8);
  text-align: center;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
}
</style>

<script setup>
// Vue Comparaison d'audits — branchée sur le backend réel (/api/comparison).
// Parcours en 3 étapes : choisir une machine comparable (>= 2 audits terminés),
// choisir deux audits (avant / après), afficher l'évolution (score global,
// domaines, contrôles). Totalement AGNOSTIQUE À L'OS : aucun filtrage ni
// affichage spécifique Linux/Windows — une machine Windows se compare comme une
// Linux. Tout utilisateur authentifié y a accès (lecture seule).
import { ref, computed, onMounted } from 'vue'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'
import { useComparisonStore } from '@/stores/comparison'
import ScoreGauge from '@/components/charts/ScoreGauge.vue'
import StatusBadge from '@/components/audit/StatusBadge.vue'

const store = useComparisonStore()

const selectedSystemId = ref('')
const auditBeforeId = ref('') // audit A (avant)
const auditAfterId = ref('')  // audit B (après)
const showUnchanged = ref(false)

const DOMAIN_LABELS = {
  access: 'Accès',
  network: 'Réseau',
  logging: 'Journalisation',
  crypto: 'Chiffrement',
  updates: 'Mises à jour',
  services: 'Services'
}

onMounted(() => store.fetchSystems())

// --- Étape 1 : machine -----------------------------------------------------

const onSystemChange = async () => {
  auditBeforeId.value = ''
  auditAfterId.value = ''
  store.clearResult()
  if (selectedSystemId.value) {
    await store.fetchAudits(Number(selectedSystemId.value))
  }
}

// --- Étape 2 : deux audits distincts ---------------------------------------

const bothSelected = computed(() =>
  auditBeforeId.value && auditAfterId.value
)
const sameAudit = computed(() =>
  bothSelected.value && auditBeforeId.value === auditAfterId.value
)
const canCompare = computed(() => bothSelected.value && !sameAudit.value)

const runCompare = async () => {
  if (!canCompare.value) return
  await store.compare(Number(auditBeforeId.value), Number(auditAfterId.value))
}

const auditLabel = (a) => {
  const date = a.finished_at || a.created_at
  const when = date ? new Date(date).toLocaleString('fr-FR') : 'date inconnue'
  const score = a.score_global != null ? `${a.score_global} pts` : '—'
  return `#${a.id} · ${when} · ${score}`
}

// --- Étape 3 : rendu de la comparaison -------------------------------------

const result = computed(() => store.result)

const scoreDelta = computed(() => result.value?.score_diff?.delta ?? null)

// Classe sémantique d'un delta (amélioration = vert, régression = rouge).
const deltaClass = (delta) => {
  if (delta == null || delta === 0) return 'delta--flat'
  return delta > 0 ? 'delta--up' : 'delta--down'
}
const deltaArrow = (delta) => {
  if (delta == null || delta === 0) return '='
  return delta > 0 ? '▲' : '▼'
}
const deltaText = (delta) => {
  if (delta == null) return '—'
  const sign = delta > 0 ? '+' : ''
  return `${sign}${delta}`
}

// Domaines sous forme de liste ordonnée pour l'affichage (before/after/delta).
const domainRows = computed(() => {
  const d = result.value?.domains || {}
  return Object.keys(DOMAIN_LABELS)
    .filter((k) => k in d)
    .map((k) => ({ key: k, label: DOMAIN_LABELS[k], ...d[k] }))
})

const summary = computed(() => result.value?.summary || null)
</script>

<template>
  <div class="compare-view">
    <header class="compare-header">
      <h1>Comparaison d'audits</h1>
      <p class="subtitle">Mesurez l'évolution de la conformité entre deux audits d'une même machine.</p>
    </header>

    <!-- Sélecteurs (étapes 1 & 2) -->
    <section class="card selectors">
      <!-- État chargement machines -->
      <div v-if="store.loadingSystems" class="state-line">Chargement des machines…</div>

      <!-- État erreur machines -->
      <div v-else-if="store.systemsError" class="state-line state-line--error">
        {{ store.systemsError }}
        <button class="ghost-btn" @click="store.fetchSystems">Réessayer</button>
      </div>

      <!-- Aucune machine comparable : message pédagogique -->
      <div v-else-if="store.systems.length === 0" class="empty-pedago">
        <p class="empty-title">Aucune machine comparable pour l'instant</p>
        <p class="empty-msg">
          Aucune machine n'a encore assez d'audits pour être comparée.
          Lancez <strong>au moins deux audits</strong> sur une machine, puis revenez ici.
        </p>
      </div>

      <template v-else>
        <!-- Étape 1 : machine -->
        <div class="field">
          <label class="field-label">Machine</label>
          <select v-model="selectedSystemId" class="field-input" @change="onSystemChange">
            <option value="">— Choisir une machine —</option>
            <option v-for="s in store.systems" :key="s.id" :value="s.id">
              {{ s.hostname }} ({{ s.os_version }}) · {{ s.done_audits_count }} audits
            </option>
          </select>
        </div>

        <!-- Étape 2 : deux audits -->
        <template v-if="selectedSystemId">
          <div v-if="store.loadingAudits" class="state-line">Chargement des audits…</div>
          <div v-else-if="store.auditsError" class="state-line state-line--error">
            {{ store.auditsError }}
          </div>
          <div v-else class="audit-pickers">
            <div class="field">
              <label class="field-label">Audit avant (A)</label>
              <select v-model="auditBeforeId" class="field-input">
                <option value="">— Choisir —</option>
                <option v-for="a in store.audits" :key="a.id" :value="a.id">
                  {{ auditLabel(a) }}
                </option>
              </select>
            </div>
            <div class="field">
              <label class="field-label">Audit après (B)</label>
              <select v-model="auditAfterId" class="field-input">
                <option value="">— Choisir —</option>
                <option v-for="a in store.audits" :key="a.id" :value="a.id">
                  {{ auditLabel(a) }}
                </option>
              </select>
            </div>
          </div>

          <p v-if="sameAudit" class="state-line state-line--error">
            Choisissez deux audits différents.
          </p>

          <div class="selectors-actions">
            <button class="primary-btn" :disabled="!canCompare || store.loadingResult" @click="runCompare">
              {{ store.loadingResult ? 'Comparaison…' : 'Comparer' }}
            </button>
          </div>
        </template>
      </template>
    </section>

    <!-- Erreur de comparaison -->
    <div v-if="store.resultError" class="state-line state-line--error card">
      {{ store.resultError }}
    </div>

    <!-- Étape 3 : résultat -->
    <template v-if="result">
      <!-- Score global -->
      <section class="card">
        <h2 class="card-title">Score global</h2>
        <div class="score-evolution">
          <div class="gauge-block">
            <span class="gauge-caption">Avant</span>
            <ScoreGauge :score="result.score_diff.before ?? 0" :size="120" />
          </div>
          <div class="delta-badge" :class="deltaClass(scoreDelta)">
            <span class="delta-arrow">{{ deltaArrow(scoreDelta) }}</span>
            <span class="delta-value">{{ deltaText(scoreDelta) }}</span>
            <span class="delta-unit">pts</span>
          </div>
          <div class="gauge-block">
            <span class="gauge-caption">Après</span>
            <ScoreGauge :score="result.score_diff.after ?? 0" :size="120" />
          </div>
        </div>

        <!-- Récapitulatif chiffré -->
        <div v-if="summary" class="summary-pills">
          <span class="pill pill--up">{{ summary.improved }} améliorés</span>
          <span class="pill pill--down">{{ summary.regressed }} régressés</span>
          <span class="pill pill--flat">{{ summary.unchanged }} inchangés</span>
          <span v-if="summary.added" class="pill pill--info">{{ summary.added }} ajoutés</span>
          <span v-if="summary.removed" class="pill pill--info">{{ summary.removed }} retirés</span>
        </div>
      </section>

      <!-- Évolution par domaine -->
      <section class="card">
        <h2 class="card-title">Évolution par domaine</h2>
        <div class="domain-list">
          <div v-for="d in domainRows" :key="d.key" class="domain-row">
            <span class="domain-name">{{ d.label }}</span>
            <div class="domain-bars">
              <div class="mini-bar">
                <div class="mini-fill mini-fill--before" :style="{ width: (d.before ?? 0) + '%' }"></div>
              </div>
              <div class="mini-bar">
                <div class="mini-fill mini-fill--after" :style="{ width: (d.after ?? 0) + '%' }"></div>
              </div>
            </div>
            <span class="domain-scores">
              <span class="score-before">{{ d.before ?? '—' }}</span>
              <span class="arrow">→</span>
              <span class="score-after">{{ d.after ?? '—' }}</span>
            </span>
            <span class="domain-delta" :class="deltaClass(d.delta)">
              {{ deltaArrow(d.delta) }} {{ deltaText(d.delta) }}
            </span>
          </div>
        </div>
      </section>

      <!-- Régressions (mises en avant) -->
      <section v-if="result.regressions.length" class="card card--alert">
        <h2 class="card-title">
          <span class="dot dot--fail"></span>
          Régressions ({{ result.regressions.length }})
        </h2>
        <div class="control-list">
          <div v-for="c in result.regressions" :key="c.control_id" class="control-row">
            <div class="control-info">
              <span class="control-id">{{ c.control_id }}</span>
              <span class="control-title">{{ c.title }}</span>
            </div>
            <div class="control-transition">
              <StatusBadge :status="c.status_before" />
              <span class="arrow">→</span>
              <StatusBadge :status="c.status_after" />
            </div>
          </div>
        </div>
      </section>

      <!-- Améliorations -->
      <section v-if="result.improvements.length" class="card">
        <h2 class="card-title">
          <span class="dot dot--pass"></span>
          Améliorations ({{ result.improvements.length }})
        </h2>
        <div class="control-list">
          <div v-for="c in result.improvements" :key="c.control_id" class="control-row">
            <div class="control-info">
              <span class="control-id">{{ c.control_id }}</span>
              <span class="control-title">{{ c.title }}</span>
            </div>
            <div class="control-transition">
              <StatusBadge :status="c.status_before" />
              <span class="arrow">→</span>
              <StatusBadge :status="c.status_after" />
            </div>
          </div>
        </div>
      </section>

      <!-- Contrôles ajoutés / retirés (structure d'audit différente) -->
      <section v-if="result.added.length || result.removed.length" class="card">
        <h2 class="card-title">Contrôles apparus / disparus</h2>
        <div class="control-list">
          <div v-for="c in result.added" :key="'add-' + c.control_id" class="control-row">
            <div class="control-info">
              <span class="control-id">{{ c.control_id }}</span>
              <span class="control-title">{{ c.title }}</span>
            </div>
            <div class="control-transition">
              <span class="side-tag side-tag--add">apparu (B)</span>
              <StatusBadge :status="c.status" />
            </div>
          </div>
          <div v-for="c in result.removed" :key="'rem-' + c.control_id" class="control-row">
            <div class="control-info">
              <span class="control-id">{{ c.control_id }}</span>
              <span class="control-title">{{ c.title }}</span>
            </div>
            <div class="control-transition">
              <span class="side-tag side-tag--rem">disparu (A)</span>
              <StatusBadge :status="c.status" />
            </div>
          </div>
        </div>
      </section>

      <!-- Inchangés (repliés par défaut, souvent nombreux) -->
      <section v-if="result.unchanged.length" class="card">
        <button class="collapse-toggle" @click="showUnchanged = !showUnchanged">
          <span class="dot dot--flat"></span>
          Contrôles inchangés ({{ result.unchanged.length }})
          <component :is="showUnchanged ? ChevronDown : ChevronRight" :size="16" class="chevron" />
        </button>
        <div v-if="showUnchanged" class="control-list control-list--muted">
          <div v-for="c in result.unchanged" :key="c.control_id" class="control-row">
            <div class="control-info">
              <span class="control-id">{{ c.control_id }}</span>
              <span class="control-title">{{ c.title }}</span>
            </div>
            <div class="control-transition">
              <StatusBadge :status="c.status_after" />
            </div>
          </div>
        </div>
      </section>
    </template>
  </div>
</template>

<style scoped>
.compare-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-6);
}

.compare-header h1 {
  font-size: var(--text-2xl);
  font-family: var(--font-mono);
  color: var(--text-primary);
  margin: 0;
}
.compare-header .subtitle {
  font-size: var(--text-sm);
  font-family: var(--font-mono);
  color: var(--text-muted);
  margin: var(--space-1) 0 0 0;
}

.card {
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-6);
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
}
.card--alert { border-color: var(--status-fail); }

.card-title {
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  color: var(--text-primary);
  margin: 0;
  display: flex;
  align-items: center;
  gap: var(--space-2);
}

/* Sélecteurs */
.selectors { gap: var(--space-4); }

.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}
.field-label {
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-muted);
}
.field-input {
  background-color: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  cursor: pointer;
}
.field-input:focus { outline: none; border-color: var(--accent); }

.audit-pickers {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--space-4);
}
.selectors-actions { display: flex; justify-content: flex-end; }

/* États */
.state-line {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: var(--space-3);
}
.state-line--error { color: var(--status-fail); }

.empty-pedago { text-align: center; padding: var(--space-6) var(--space-4); }
.empty-title {
  font-family: var(--font-mono);
  font-size: var(--text-base);
  color: var(--text-primary);
  margin: 0 0 var(--space-2) 0;
}
.empty-msg {
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-muted);
  line-height: 1.6;
  margin: 0;
  max-width: 520px;
  margin-inline: auto;
}

/* Boutons */
.primary-btn {
  background-color: var(--accent);
  color: var(--bg-base);
  border: none;
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-6);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  font-weight: 600;
  cursor: pointer;
  transition: var(--transition-base);
}
.primary-btn:hover:not(:disabled) { background-color: var(--accent-hover); }
.primary-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.ghost-btn {
  background-color: transparent;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  padding: var(--space-1) var(--space-3);
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  cursor: pointer;
}
.ghost-btn:hover { border-color: var(--accent); color: var(--accent); }

/* Score global */
.score-evolution {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-8);
}
.gauge-block {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-2);
}
.gauge-caption {
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-muted);
}

.delta-badge {
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 90px;
  padding: var(--space-3) var(--space-4);
  border-radius: var(--radius-md);
  border: 1px solid;
}
.delta-arrow { font-size: var(--text-lg); line-height: 1; }
.delta-value {
  font-family: var(--font-mono);
  font-size: 1.6rem;
  font-weight: 700;
  line-height: 1.1;
}
.delta-unit {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  opacity: 0.8;
}

/* Sémantique de delta (partagée par le score et les domaines) */
.delta--up   { color: var(--status-pass); border-color: var(--status-pass); background-color: rgba(var(--rgb-status-pass), 0.08); }
.delta--down { color: var(--status-fail); border-color: var(--status-fail); background-color: rgba(var(--rgb-status-fail), 0.08); }
.delta--flat { color: var(--text-muted); border-color: var(--border); }

.summary-pills {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  justify-content: center;
}
.pill {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  padding: var(--space-1) var(--space-3);
  border-radius: var(--radius-sm);
  border: 1px solid;
}
.pill--up   { color: var(--status-pass); border-color: var(--status-pass); }
.pill--down { color: var(--status-fail); border-color: var(--status-fail); }
.pill--flat { color: var(--text-muted); border-color: var(--border); }
.pill--info { color: var(--text-secondary); border-color: var(--border); }

/* Domaines */
.domain-list { display: flex; flex-direction: column; gap: var(--space-4); }
.domain-row {
  display: grid;
  grid-template-columns: 120px 1fr 100px 90px;
  align-items: center;
  gap: var(--space-4);
}
.domain-name {
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-primary);
}
.domain-bars { display: flex; flex-direction: column; gap: 3px; }
.mini-bar {
  height: 8px;
  background-color: var(--bg-elevated);
  border-radius: var(--radius-sm);
  overflow: hidden;
}
.mini-fill { height: 100%; border-radius: var(--radius-sm); transition: width 600ms ease; }
.mini-fill--before { background-color: var(--text-muted); }
.mini-fill--after  { background-color: var(--accent); }

.domain-scores {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  display: flex;
  align-items: center;
  gap: var(--space-2);
  justify-content: flex-end;
}
.score-before { color: var(--text-muted); }
.score-after  { color: var(--text-primary); font-weight: 600; }
.arrow { color: var(--text-muted); }

.domain-delta {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  font-weight: 600;
  text-align: right;
}
.domain-delta.delta--up   { color: var(--status-pass); }
.domain-delta.delta--down { color: var(--status-fail); }
.domain-delta.delta--flat { color: var(--text-muted); }

/* Contrôles */
.control-list { display: flex; flex-direction: column; }
.control-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  padding: var(--space-3) 0;
  border-bottom: 1px solid var(--border-subtle);
}
.control-row:last-child { border-bottom: none; }
.control-list--muted { opacity: 0.75; }

.control-info { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.control-id {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-muted);
}
.control-title {
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-primary);
}
.control-transition {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  flex-shrink: 0;
}

.side-tag {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  color: var(--text-secondary);
}
.side-tag--add { color: var(--status-pass); border-color: var(--status-pass); }
.side-tag--rem { color: var(--text-muted); }

.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot--fail { background-color: var(--status-fail); }
.dot--pass { background-color: var(--status-pass); }
.dot--flat { background-color: var(--text-muted); }

.collapse-toggle {
  background: none;
  border: none;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: 0;
}
.chevron { color: var(--text-muted); font-size: var(--text-sm); }
</style>

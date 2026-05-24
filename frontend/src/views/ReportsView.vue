<script setup>
// Vue Rapports — branchée sur les vrais audits (GET /api/reports/<audit_id>).
// Parcours : choisir une machine, puis un de ses audits TERMINÉS, afficher le
// rapport (synthèse -> domaines -> non-conformités avec remédiation -> reste
// replié), et exporter en JSON / CSV. Accessible à tous les rôles (lecture).
import { ref, computed } from 'vue'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'
import { useSystemsStore } from '@/stores/systems'
import * as auditsApi from '@/api/audits.js'
import * as reportsApi from '@/api/reports.js'
import {
  generateJSON,
  generateCSV,
  generateHTML,
  downloadFile,
  estimateSize,
  buildFilename
} from '@/services/exportService.js'
import ScoreGauge from '@/components/charts/ScoreGauge.vue'
import DomainRadar from '@/components/charts/DomainRadar.vue'
import RiskBadge from '@/components/audit/RiskBadge.vue'
import StatusBadge from '@/components/audit/StatusBadge.vue'

const systemsStore = useSystemsStore()

const selectedSystemId = ref('')
const selectedAuditId = ref('')

const audits = ref([])          // audits terminés de la machine choisie
const report = ref(null)        // rapport assemblé par le backend

const loadingSystems = ref(false)
const loadingAudits = ref(false)
const loadingReport = ref(false)
const systemsError = ref(null)
const auditsError = ref(null)
const reportError = ref(null)

// Sections repliables (le détail non prioritaire est masqué par défaut).
const openSections = ref({ warn: false, pass: false, na: false })

const DOMAIN_LABELS = {
  access: 'Accès', network: 'Réseau', logging: 'Journalisation',
  crypto: 'Chiffrement', updates: 'Mises à jour', services: 'Services'
}

const errorMessage = (err, fallback) => err?.response?.data?.error || fallback

// --- Chargement machines (au montage) --------------------------------------

const loadSystems = async () => {
  loadingSystems.value = true
  systemsError.value = null
  try {
    await systemsStore.fetchSystems()
  } catch (err) {
    systemsError.value = errorMessage(err, 'Impossible de charger les machines')
  } finally {
    loadingSystems.value = false
  }
}
loadSystems()

const systems = computed(() => systemsStore.systems)

// --- Étape 1 : machine -> ses audits terminés ------------------------------

const onSystemChange = async () => {
  selectedAuditId.value = ''
  report.value = null
  reportError.value = null
  audits.value = []
  if (!selectedSystemId.value) return

  loadingAudits.value = true
  auditsError.value = null
  try {
    const { data } = await auditsApi.listForSystem(Number(selectedSystemId.value))
    // On ne propose QUE les audits terminés (un rapport n'a de sens que sur done).
    audits.value = data.filter((a) => a.status === 'done')
  } catch (err) {
    auditsError.value = errorMessage(err, 'Impossible de charger les audits')
  } finally {
    loadingAudits.value = false
  }
}

const auditLabel = (a) => {
  const date = a.finished_at || a.created_at
  const when = date ? new Date(date).toLocaleString('fr-FR') : 'date inconnue'
  const score = a.score_global != null ? `${a.score_global}/100` : '—'
  return `#${a.id} · ${when} · ${score}`
}

// --- Étape 2 : charger le rapport de l'audit choisi ------------------------

const onAuditChange = async () => {
  report.value = null
  reportError.value = null
  if (!selectedAuditId.value) return

  loadingReport.value = true
  try {
    const { data } = await reportsApi.getReport(Number(selectedAuditId.value))
    report.value = data
  } catch (err) {
    reportError.value = errorMessage(err, 'Impossible de charger le rapport')
  } finally {
    loadingReport.value = false
  }
}

// --- Dérivés d'affichage ----------------------------------------------------

const counts = computed(() => report.value?.summary?.counts || null)
const scoresByDomain = computed(() => report.value?.summary?.scores_by_domain || {})

const controlsByStatus = (status) =>
  (report.value?.controls || []).filter((c) => c.status === status)

const fails = computed(() => controlsByStatus('fail'))
const warns = computed(() => controlsByStatus('warn'))
const passes = computed(() => controlsByStatus('pass'))
const nas = computed(() => controlsByStatus('na'))

const domainRows = computed(() =>
  Object.keys(DOMAIN_LABELS)
    .filter((k) => k in scoresByDomain.value)
    .map((k) => ({ key: k, label: DOMAIN_LABELS[k], score: scoresByDomain.value[k] }))
)

const reportDate = computed(() => {
  const d = report.value?.audit?.finished_at || report.value?.audit?.created_at
  return d ? new Date(d).toLocaleString('fr-FR') : '—'
})

const remediationScript = (rem) => {
  if (!rem) return null
  return typeof rem === 'string' ? rem : rem.script
}

// --- Export -----------------------------------------------------------------

// Génère le contenu selon le format (fonctions pures d'exportService).
const buildContent = (format) => {
  if (format === 'json') return JSON.stringify(generateJSON(report.value), null, 2)
  if (format === 'csv') return generateCSV(report.value)
  return generateHTML(report.value) // html
}

const MIME = { json: 'application/json', csv: 'text/csv', html: 'text/html' }

const exportAs = (format) => {
  if (!report.value) return
  const content = buildContent(format)
  const filename = buildFilename(report.value.system, format)
  downloadFile(content, filename, MIME[format])
}

const jsonSize = computed(() => {
  if (!report.value) return null
  return estimateSize(JSON.stringify(generateJSON(report.value), null, 2)).formatted
})
const csvSize = computed(() => {
  if (!report.value) return null
  return estimateSize(generateCSV(report.value)).formatted
})
const htmlSize = computed(() => {
  if (!report.value) return null
  return estimateSize(generateHTML(report.value)).formatted
})
</script>

<template>
  <div class="reports-view">
    <header class="reports-header">
      <h1>Rapports d'audit</h1>
      <p class="subtitle">Consultez et exportez le rapport de conformité d'un audit.</p>
    </header>

    <!-- Sélection machine + audit -->
    <section class="card selectors">
      <div v-if="loadingSystems" class="state-line">Chargement des machines…</div>
      <div v-else-if="systemsError" class="state-line state-line--error">
        {{ systemsError }}
        <button class="ghost-btn" @click="loadSystems">Réessayer</button>
      </div>
      <div v-else-if="systems.length === 0" class="state-line">Aucune machine enregistrée.</div>

      <template v-else>
        <div class="field">
          <label class="field-label">Machine</label>
          <select v-model="selectedSystemId" class="field-input" @change="onSystemChange">
            <option value="">— Choisir une machine —</option>
            <option v-for="s in systems" :key="s.id" :value="s.id">
              {{ s.hostname }} ({{ s.os_version }})
            </option>
          </select>
        </div>

        <template v-if="selectedSystemId">
          <div v-if="loadingAudits" class="state-line">Chargement des audits…</div>
          <div v-else-if="auditsError" class="state-line state-line--error">{{ auditsError }}</div>
          <div v-else-if="audits.length === 0" class="state-line">
            Aucun audit terminé sur cette machine.
          </div>
          <div v-else class="field">
            <label class="field-label">Audit</label>
            <select v-model="selectedAuditId" class="field-input" @change="onAuditChange">
              <option value="">— Choisir un audit —</option>
              <option v-for="a in audits" :key="a.id" :value="a.id">
                {{ auditLabel(a) }}
              </option>
            </select>
          </div>
        </template>
      </template>
    </section>

    <div v-if="loadingReport" class="state-line card">Chargement du rapport…</div>
    <div v-else-if="reportError" class="state-line state-line--error card">{{ reportError }}</div>

    <!-- Rapport -->
    <template v-if="report && !loadingReport">
      <!-- Synthèse / verdict -->
      <section class="card">
        <div class="report-head">
          <div class="report-identity">
            <h2 class="host">{{ report.system.hostname }}</h2>
            <p class="host-meta">
              {{ report.system.ip_address }} · {{ report.system.os_version }}
            </p>
            <p class="host-meta">Audit #{{ report.audit.id }} · {{ reportDate }} · niveau {{ report.audit.cis_level }}</p>
          </div>
          <div class="export-actions">
            <button class="export-btn" @click="exportAs('json')">
              Exporter JSON <span class="export-size">{{ jsonSize }}</span>
            </button>
            <button class="export-btn" @click="exportAs('csv')">
              Exporter CSV <span class="export-size">{{ csvSize }}</span>
            </button>
            <button class="export-btn" @click="exportAs('html')">
              Exporter HTML <span class="export-size">{{ htmlSize }}</span>
            </button>
          </div>
        </div>

        <div class="verdict">
          <div class="verdict-score">
            <ScoreGauge :score="report.summary.score_global ?? 0" :size="130" />
          </div>
          <div class="verdict-side">
            <div class="verdict-risk">
              <span class="verdict-label">Niveau de risque</span>
              <RiskBadge v-if="report.summary.risk_level" :level="report.summary.risk_level" />
              <span v-else class="verdict-na">—</span>
            </div>
            <div v-if="counts" class="counts">
              <div class="count count--pass"><span class="count-num">{{ counts.pass }}</span><span class="count-lbl">conformes</span></div>
              <div class="count count--fail"><span class="count-num">{{ counts.fail }}</span><span class="count-lbl">non conformes</span></div>
              <div class="count count--warn"><span class="count-num">{{ counts.warn }}</span><span class="count-lbl">avertissements</span></div>
              <div class="count count--na"><span class="count-num">{{ counts.na }}</span><span class="count-lbl">non vérifiables</span></div>
              <div class="count count--total"><span class="count-num">{{ counts.total }}</span><span class="count-lbl">contrôles</span></div>
            </div>
          </div>
        </div>
      </section>

      <!-- Par domaine -->
      <section class="card">
        <h2 class="card-title">Scores par domaine</h2>
        <div class="domain-block">
          <DomainRadar :scores="scoresByDomain" />
          <div class="domain-bars">
            <div v-for="d in domainRows" :key="d.key" class="domain-line">
              <span class="domain-name">{{ d.label }}</span>
              <div class="mini-bar">
                <div class="mini-fill" :style="{ width: (d.score ?? 0) + '%' }" :data-band="d.score >= 80 ? 'pass' : d.score >= 60 ? 'warn' : 'fail'"></div>
              </div>
              <span class="domain-score">{{ d.score ?? '—' }}</span>
            </div>
          </div>
        </div>
      </section>

      <!-- Non-conformités en avant -->
      <section class="card card--alert">
        <h2 class="card-title">
          <span class="dot dot--fail"></span>
          Non-conformités à corriger ({{ fails.length }})
        </h2>
        <p v-if="fails.length === 0" class="empty-good">Aucune non-conformité — excellent.</p>
        <div v-else class="fail-list">
          <article v-for="c in fails" :key="c.control_id" class="fail-card">
            <div class="fail-head">
              <span class="control-id">{{ c.control_id }}</span>
              <span class="control-title">{{ c.title }}</span>
            </div>
            <div class="fail-diff">
              <div class="diff-item diff-item--bad">
                <span class="diff-label">Observé</span>
                <span class="diff-value">{{ c.actual_value || '—' }}</span>
              </div>
              <div class="diff-item diff-item--good">
                <span class="diff-label">Attendu</span>
                <span class="diff-value">{{ c.expected_value || '—' }}</span>
              </div>
            </div>
            <div v-if="remediationScript(c.remediation)" class="remediation">
              <span class="remediation-label">Recommandation</span>
              <pre class="remediation-script">{{ remediationScript(c.remediation) }}</pre>
            </div>
            <p v-else class="remediation-none">Aucune remédiation automatique documentée pour ce contrôle.</p>
          </article>
        </div>
      </section>

      <!-- Reste : discret et replié -->
      <section v-if="warns.length" class="card">
        <button class="collapse-toggle" @click="openSections.warn = !openSections.warn">
          <span class="dot dot--warn"></span>
          Avertissements ({{ warns.length }})
          <component :is="openSections.warn ? ChevronDown : ChevronRight" :size="16" class="chevron" />
        </button>
        <div v-if="openSections.warn" class="control-list">
          <div v-for="c in warns" :key="c.control_id" class="control-row">
            <div class="control-info">
              <span class="control-id">{{ c.control_id }}</span>
              <span class="control-title">{{ c.title }}</span>
            </div>
            <StatusBadge :status="c.status" />
          </div>
        </div>
      </section>

      <section v-if="passes.length" class="card">
        <button class="collapse-toggle" @click="openSections.pass = !openSections.pass">
          <span class="dot dot--pass"></span>
          Conformes ({{ passes.length }})
          <component :is="openSections.pass ? ChevronDown : ChevronRight" :size="16" class="chevron" />
        </button>
        <div v-if="openSections.pass" class="control-list">
          <div v-for="c in passes" :key="c.control_id" class="control-row">
            <div class="control-info">
              <span class="control-id">{{ c.control_id }}</span>
              <span class="control-title">{{ c.title }}</span>
            </div>
            <StatusBadge :status="c.status" />
          </div>
        </div>
      </section>

      <section v-if="nas.length" class="card">
        <button class="collapse-toggle" @click="openSections.na = !openSections.na">
          <span class="dot dot--na"></span>
          Non vérifiables ({{ nas.length }})
          <component :is="openSections.na ? ChevronDown : ChevronRight" :size="16" class="chevron" />
        </button>
        <div v-if="openSections.na" class="control-list">
          <div v-for="c in nas" :key="c.control_id" class="control-row">
            <div class="control-info">
              <span class="control-id">{{ c.control_id }}</span>
              <span class="control-title">{{ c.title }}</span>
            </div>
            <StatusBadge :status="c.status" />
          </div>
        </div>
      </section>
    </template>
  </div>
</template>

<style scoped>
.reports-view { display: flex; flex-direction: column; gap: var(--space-6); }

.reports-header h1 {
  font-size: var(--text-2xl);
  font-family: var(--font-mono);
  color: var(--text-primary);
  margin: 0;
}
.reports-header .subtitle {
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
  display: flex; align-items: center; gap: var(--space-2);
}

.selectors { gap: var(--space-4); }
.field { display: flex; flex-direction: column; gap: var(--space-2); }
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

.state-line {
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  color: var(--text-muted);
  display: flex; align-items: center; gap: var(--space-3);
}
.state-line--error { color: var(--status-fail); }

.ghost-btn {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  padding: var(--space-1) var(--space-3);
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  cursor: pointer;
}
.ghost-btn:hover { border-color: var(--accent); color: var(--accent); }

/* Synthèse */
.report-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--space-4);
  flex-wrap: wrap;
}
.report-identity .host {
  font-family: var(--font-mono);
  font-size: var(--text-xl);
  color: var(--text-primary);
  margin: 0;
}
.host-meta {
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-muted);
  margin: var(--space-1) 0 0 0;
}
.export-actions { display: flex; align-items: center; gap: var(--space-2); flex-wrap: wrap; }
.export-btn {
  background-color: var(--accent);
  color: var(--bg-base);
  border: none;
  border-radius: var(--radius-md);
  padding: var(--space-2) var(--space-4);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  font-weight: 600;
  cursor: pointer;
  transition: var(--transition-base);
}
.export-btn:hover { background-color: var(--accent-hover); }
.export-size { font-family: var(--font-mono); font-size: var(--text-xs); opacity: 0.8; margin-left: var(--space-1); }

.verdict {
  display: flex;
  align-items: center;
  gap: var(--space-8);
  flex-wrap: wrap;
}
.verdict-side { display: flex; flex-direction: column; gap: var(--space-4); flex: 1; min-width: 260px; }
.verdict-risk { display: flex; align-items: center; gap: var(--space-3); }
.verdict-label {
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-muted);
}
.verdict-na { color: var(--text-muted); font-family: var(--font-mono); }

.counts { display: flex; flex-wrap: wrap; gap: var(--space-3); }
.count {
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 84px;
  padding: var(--space-3);
  border-radius: var(--radius-md);
  border: 1px solid var(--border);
}
.count-num { font-family: var(--font-mono); font-size: 1.5rem; font-weight: 700; line-height: 1; }
.count-lbl { font-family: var(--font-ui); font-size: var(--text-xs); color: var(--text-muted); margin-top: var(--space-1); }
.count--pass { border-color: var(--status-pass); } .count--pass .count-num { color: var(--status-pass); }
.count--fail { border-color: var(--status-fail); } .count--fail .count-num { color: var(--status-fail); }
.count--warn { border-color: var(--status-warn); } .count--warn .count-num { color: var(--status-warn); }
.count--na .count-num { color: var(--text-muted); }
.count--total .count-num { color: var(--text-primary); }

/* Domaines */
.domain-block { display: flex; gap: var(--space-6); align-items: center; flex-wrap: wrap; }
.domain-bars { flex: 1; min-width: 260px; display: flex; flex-direction: column; gap: var(--space-3); }
.domain-line { display: grid; grid-template-columns: 120px 1fr 40px; align-items: center; gap: var(--space-3); }
.domain-name { font-family: var(--font-ui); font-size: var(--text-sm); color: var(--text-primary); }
.mini-bar { height: 10px; background-color: var(--bg-elevated); border-radius: var(--radius-sm); overflow: hidden; }
.mini-fill { height: 100%; border-radius: var(--radius-sm); transition: width 600ms ease; }
.mini-fill[data-band="pass"] { background-color: var(--status-pass); }
.mini-fill[data-band="warn"] { background-color: var(--status-warn); }
.mini-fill[data-band="fail"] { background-color: var(--status-fail); }
.domain-score { font-family: var(--font-mono); font-size: var(--text-sm); color: var(--text-primary); text-align: right; }

/* Non-conformités */
.empty-good { font-family: var(--font-mono); font-size: var(--text-sm); color: var(--status-pass); margin: 0; }
.fail-list { display: flex; flex-direction: column; gap: var(--space-4); }
.fail-card {
  border: 1px solid var(--border-subtle);
  border-left: 3px solid var(--status-fail);
  border-radius: var(--radius-md);
  padding: var(--space-4);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.fail-head { display: flex; flex-direction: column; gap: 2px; }
.control-id { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-muted); }
.control-title { font-family: var(--font-ui); font-size: var(--text-sm); color: var(--text-primary); }

.fail-diff { display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-3); }
.diff-item { display: flex; flex-direction: column; gap: 2px; padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm); }
.diff-item--bad { background-color: rgba(var(--rgb-status-fail), 0.08); }
.diff-item--good { background-color: rgba(var(--rgb-status-pass), 0.08); }
.diff-label { font-family: var(--font-ui); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }
.diff-value { font-family: var(--font-mono); font-size: var(--text-sm); color: var(--text-primary); word-break: break-word; }

.remediation { display: flex; flex-direction: column; gap: var(--space-2); }
.remediation-label { font-family: var(--font-ui); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 1px; color: var(--accent); }
.remediation-script {
  margin: 0;
  background-color: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: var(--space-3);
  font-family: var(--font-mono);
  font-size: var(--text-xs);
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-word;
}
.remediation-none { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-muted); margin: 0; }

/* Reste replié */
.collapse-toggle {
  background: none; border: none;
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  cursor: pointer;
  display: flex; align-items: center; gap: var(--space-2);
  padding: 0;
}
.chevron { color: var(--text-muted); font-size: var(--text-sm); }
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
.control-info { display: flex; flex-direction: column; gap: 2px; min-width: 0; }

.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot--fail { background-color: var(--status-fail); }
.dot--pass { background-color: var(--status-pass); }
.dot--warn { background-color: var(--status-warn); }
.dot--na { background-color: var(--text-muted); }
</style>

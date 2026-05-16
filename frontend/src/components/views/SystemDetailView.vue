<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import client from '@/api/client.js'
import { useRoute, useRouter } from 'vue-router'
import {
  ArrowLeft, Play, Download, Wrench, Trash2, Zap, AlertTriangle
} from 'lucide-vue-next'
import { useSystemsStore } from '@/stores/systems'
import { useAuditsStore } from '@/stores/audits'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'
import OsIcon from '@/components/system/OsIcon.vue'
import RiskBadge from '@/components/audit/RiskBadge.vue'
import StatusBadge from '@/components/audit/StatusBadge.vue'
import ScoreGauge from '@/components/charts/ScoreGauge.vue'
import DomainRadar from '@/components/charts/DomainRadar.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'

const route = useRoute()
const router = useRouter()
const systemsStore = useSystemsStore()
const auditsStore  = useAuditsStore()
const authStore    = useAuthStore()
const ui           = useUiStore()

const system = ref(null)

const canRunAudit = computed(() => ['auditor', 'admin'].includes(authStore.user?.role))
const canDelete   = computed(() => authStore.isAdmin())
const audit = computed(() => auditsStore.currentAudit)

const DOMAIN_LABELS = {
  access: 'Accès', network: 'Réseau', logging: 'Journalisation',
  crypto: 'Chiffrement', updates: 'Mises à jour', services: 'Services'
}

// N'affiche que les contrôles non conformes (status === 'fail'), pour Linux
// comme pour Windows — ce composant ne fait pas de distinction d'OS, les
// deux passent par le même modèle AuditResult.
const filterDomain = ref('')
const filteredControls = computed(() => {
  const results = audit.value?.results || []
  return results.filter(
    (c) => c.status === 'fail' && (!filterDomain.value || c.domain === filterDomain.value)
  )
})

// Contrôles à condition ambiguë (le moteur d'évaluation ne sait pas trancher
// pass/fail) : ne sont JAMAIS 'fail', donc invisibles dans le tableau
// ci-dessus et jamais proposés à la remédiation groupée. Section séparée
// pour ne pas les laisser invisibles ni les mélanger aux vrais échecs.
const warnControls = computed(() => {
  const results = audit.value?.results || []
  return results.filter(
    (c) => c.status === 'warn' && (!filterDomain.value || c.domain === filterDomain.value)
  )
})

const statusCounts = computed(() => {
  const counts = { pass: 0, fail: 0, warn: 0, na: 0 }
  for (const c of audit.value?.results || []) counts[c.status]++
  return counts
})

const loadSystemAndAudits = async (id) => {
  system.value = await systemsStore.fetchSystem(id)
  if (!system.value) return
  await auditsStore.loadHistory(id)
  if (auditsStore.history.length > 0) {
    await auditsStore.loadAudit(auditsStore.history[0].id)
  } else {
    auditsStore.clearCurrent()
  }
}

// ---- Sauvegardes (Brique 2) ----
const snapshots = ref([])
const loadSnapshots = async (id) => {
  try {
    const res = await client.get(`/agent/snapshots/${id}`)
    snapshots.value = res.data
  } catch {
    snapshots.value = []
  }
}

onMounted(() => {
  loadSystemAndAudits(route.params.id)
  loadSnapshots(route.params.id)
})

// ---- Lancer un audit ----
const handleRunAudit = async () => {
  try {
    const created = await auditsStore.runAudit(Number(route.params.id))
    ui.notify(`Audit terminé — score ${created.score_global}/100`, 'success')
    await auditsStore.loadHistory(route.params.id)
    system.value = await systemsStore.fetchSystem(route.params.id)
  } catch (err) {
    ui.notify(err.message, 'error')
  }
}

// ---- Remédiation globale (envoi direct à l'agent) ----
const remediating       = ref(false)
const downloadingScript = ref(false)

// Le script n'est jamais affiché à l'écran : uniquement téléchargeable.
const downloadRemediationScript = async () => {
  downloadingScript.value = true
  try {
    const res = await client.get(`/agent/remediation-script/${route.params.id}`)
    const blob = new Blob([res.data.script], { type: 'text/plain' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url
    a.download = `remediation_${system.value?.hostname || 'host'}.ps1`
    a.click()
    URL.revokeObjectURL(url)
  } catch (err) {
    ui.notify(err.response?.data?.error || 'Impossible de générer le script.', 'error')
  } finally {
    downloadingScript.value = false
  }
}

const executeRemediation = async () => {
  remediating.value = true
  try {
    // Timeout étendu (défaut du client : 30s) : sauvegarde + script + rejeu
    // de chaque contrôle corrigé peuvent largement dépasser 30s en groupé.
    const res = await client.post(`/agent/remediate/${route.params.id}`, null, { timeout: 300000 })
    const data = res.data
    // Permanent : contient le décompte final (contrôles traités/vérifiés
    // conformes), à lire sans course contre la montre.
    ui.notify(data.message || 'Remédiation envoyée à l\'agent.', 'success', 0)

    // Contrôles sans remédiation automatisable : recommandations à traiter à
    // la main, jamais exécutées silencieusement.
    const manual = data.manual_actions || []
    if (manual.length > 0) {
      const list = manual
        .map(m => `${m.control_id} : ${m.condition ? `${m.condition} — ` : ''}${m.recommendation}`)
        .join(' — ')
      // Permanent (duration: 0) : le texte (condition + recommandation) est
      // trop long pour être lu dans le délai par défaut de 3 s.
      ui.notify(`${manual.length} action(s) manuelle(s) requise(s) : ${list}`, 'warning', 0)
    }

    // Contrôles rejoués mais dont le statut reste incertain ('warn', pas un
    // échec) : distingués des vrais échecs pour ne pas induire en erreur.
    const uncertain = (data.results || []).filter(r => r.control_status === 'warn')
    if (uncertain.length > 0) {
      ui.notify(
        `${uncertain.length} contrôle(s) en statut incertain après vérification : ${uncertain.map(r => r.control_id).join(', ')} — nécessitent une revue manuelle.`,
        'warning', 0
      )
    }

    await auditsStore.loadHistory(route.params.id)
    // loadHistory() ne rafraîchit que la liste des audits passés, pas l'audit
    // COURAMMENT affiché (celui qui pilote le tableau des contrôles) — sans
    // ça, les contrôles corrigés restent affichés "non conforme" à l'écran
    // alors que le backend a déjà mis à jour leur statut en base.
    if (audit.value) await auditsStore.loadAudit(audit.value.id)
    // Une sauvegarde est créée avant le script (cf. _snapshot_before_windows_remediation) :
    // sans ça, la liste « Sauvegardes » reste figée sur son état d'avant l'action.
    await loadSnapshots(route.params.id)
  } catch (err) {
    ui.notify(err.response?.data?.error || 'Erreur lors de la remédiation.', 'error')
  } finally {
    remediating.value = false
  }
}

// ---- Remédiation par contrôle individuel ----
const remediatingControl = ref(null)   // control_id en cours de remédiation unitaire

// ---- Rollback individuel (registre + net accounts, cf. agent/undo.py) ----
// Un contrôle corrigé avec succès sort des tableaux fail/warn (il repasse
// 'pass'), donc pas d'endroit où accrocher un bouton "Annuler" dans les
// lignes du tableau — liste séparée, persistante pour toute la session sur
// cette page, de tous les contrôles corrigés (pas juste le dernier).
const remediatedControls = ref([])   // [{ controlId, title, domain, logId, undoAvailable }]

const handleRemediate = async (controlId) => {
  remediatingControl.value = controlId
  // Capturé AVANT l'appel : une fois le contrôle repassé 'pass', il sort de
  // filteredControls/warnControls et son titre/domaine ne sont plus
  // accessibles depuis ces listes.
  const beforeRow = (audit.value?.results || []).find(r => r.control_id === controlId)
  try {
    // Timeout étendu (défaut du client : 30s) : sauvegarde (jusqu'à 200s) +
    // script + rejeu peuvent largement dépasser 30s.
    const res  = await client.post(`/agent/remediate/${route.params.id}/${controlId}`, null, { timeout: 300000 })
    const data = res.data
    if (data.log_status === 'success') {
      const entry = {
        controlId,
        title: beforeRow?.title || controlId,
        domain: beforeRow?.domain || null,
        logId: data.remediation_log_id || null,
        undoAvailable: Boolean(data.undo_available && data.remediation_log_id),
      }
      const idx = remediatedControls.value.findIndex(r => r.controlId === controlId)
      if (idx >= 0) remediatedControls.value.splice(idx, 1, entry)
      else remediatedControls.value.unshift(entry)
    }
    if (data.status === 'skipped') {
      // Certains contrôles ne sont pas automatisables (script YAML = commentaire
      // décrivant l'action à mener à la main) : on affiche la condition (ce qui
      // est vérifié) et la recommandation (quoi faire), au lieu de juste dire
      // "non disponible".
      let msg = data.reason || 'Remédiation non disponible.'
      if (data.condition) msg += ` Condition : ${data.condition}.`
      if (data.recommendation) msg += ` Recommandation : ${data.recommendation}`
      // Permanent (duration: 0) : trop long pour être lu en 3 s.
      ui.notify(msg, 'warning', 0)
    } else if (data.log_status === 'success') {
      // log_status='success' signifie que le contrôle a été REJOUÉ et est
      // repassé à 'pass' — pas juste que le script s'est lancé sans erreur.
      ui.notify(`Contrôle ${controlId} corrigé et vérifié (conforme).`, 'success', 0)
    } else if (data.log_status === 'error' && data.control_status === 'warn') {
      // 'warn' = statut incertain (condition ambiguë, contrôle à revue manuelle)
      // — ce n'est PAS un échec de remédiation, on ne l'affiche pas en rouge.
      ui.notify(
        `Contrôle ${controlId} : statut incertain après vérification — nécessite une revue manuelle.`,
        'warning', 0
      )
    } else if (data.log_status === 'error') {
      const reason = data.remediation?.error
        || (data.control_status
              ? `le contrôle reste en statut « ${data.control_status} » après vérification`
              : 'la remédiation a échoué')
      ui.notify(`Remédiation de ${controlId} : ${reason}`, 'error')
    } else {
      ui.notify(data.error || 'Erreur de remédiation.', 'error')
    }
    // Le backend met à jour AuditResult (statut + valeur observée) à CHAQUE
    // rejeu, succès ou non : on rafraîchit toujours l'affichage, pas juste
    // en cas de succès, sinon la valeur observée reste visuellement figée.
    if (data.log_status && audit.value) await auditsStore.loadAudit(audit.value.id)
    // Une sauvegarde est créée avant le script dès qu'une remédiation est
    // réellement tentée (pas pour le cas 'skipped', où aucun script ne tourne).
    if (data.log_status) await loadSnapshots(route.params.id)
  } catch (err) {
    ui.notify(err.response?.data?.error || err.message, 'error')
  } finally {
    remediatingControl.value = null
  }
}

// ---- Navigation ----
const viewAudit = async (auditId) => {
  await auditsStore.loadAudit(auditId)
  filterDomain.value = ''
}

const formatDate = (iso) => (iso ? new Date(iso).toLocaleString('fr-FR') : null)
const goBack = () => router.push('/dashboard')

// ---- Suppression de la machine ----
const confirmDelete = reactive({ open: false, busy: false })

const askDeleteSystem = () => { confirmDelete.open = true }

const cancelDeleteSystem = () => {
  if (confirmDelete.busy) return
  confirmDelete.open = false
}

const executeDeleteSystem = async () => {
  confirmDelete.busy = true
  try {
    await systemsStore.deleteMachine(route.params.id)
    ui.notify(`Machine « ${system.value?.hostname} » supprimée`, 'success')
    router.push('/dashboard')
  } catch (err) {
    ui.notify(err.message, 'error')
  } finally {
    confirmDelete.busy = false
    confirmDelete.open = false
  }
}

// ---- Rollback (restauration d'une sauvegarde) ----
const confirmRollback = reactive({ open: false, busy: false, snapshot: null })

const askRollback = (snapshot) => {
  confirmRollback.snapshot = snapshot
  confirmRollback.open = true
}

const cancelRollback = () => {
  if (confirmRollback.busy) return
  confirmRollback.open = false
  confirmRollback.snapshot = null
}

const executeRollback = async () => {
  const snapshot = confirmRollback.snapshot
  if (!snapshot) return cancelRollback()
  confirmRollback.busy = true
  try {
    // Timeout étendu (défaut du client : 30s) : 3 commandes séquentielles
    // (secedit + 2x reg import) côté agent, jusqu'à 540s au pire cas
    // (backend -> agent : 600s) — doit rester au moins aussi long.
    const res = await client.post(`/agent/rollback/${snapshot.id}`, null, { timeout: 650000 })
    ui.notify(`Restauration de la sauvegarde « ${snapshot.name} » effectuée.`, 'success')

    // La restauration change l'état réel de la machine sans mettre à jour les
    // AuditResult déjà en base (secedit/registre/services touchés d'un coup,
    // pas contrôle par contrôle) : le backend déclenche donc un audit complet
    // automatique pour resynchroniser — on le suit ici pour rafraîchir le
    // score dès qu'il est prêt, sans bloquer la fermeture de cette boîte de dialogue.
    const newAuditId = res.data?.new_audit_id
    if (newAuditId) {
      ui.notify('Audit automatique en cours après la restauration', 'info', 0)
      auditsStore.pollUntilDone(newAuditId)
        .then(async () => {
          await auditsStore.loadHistory(route.params.id)
          if (audit.value) await auditsStore.loadAudit(audit.value.id)
          ui.notify('Audit post-restauration terminé : score à jour.', 'success', 0)
        })
        .catch((err) => {
          ui.notify(`Audit post-restauration : ${err.message}`, 'error')
        })
    }
  } catch (err) {
    ui.notify(err.response?.data?.error || 'Échec de la restauration.', 'error')
  } finally {
    confirmRollback.busy = false
    confirmRollback.open = false
    confirmRollback.snapshot = null
  }
}

// ---- Rollback individuel (annulation d'une remédiation précise) ----
const confirmControlRollback = reactive({ open: false, busy: false, controlId: null, logId: null })

const askControlRollback = (entry) => {
  if (!entry?.undoAvailable) return
  confirmControlRollback.controlId = entry.controlId
  confirmControlRollback.logId = entry.logId
  confirmControlRollback.open = true
}

const cancelControlRollback = () => {
  if (confirmControlRollback.busy) return
  confirmControlRollback.open = false
  confirmControlRollback.controlId = null
  confirmControlRollback.logId = null
}

const executeControlRollback = async () => {
  const { controlId, logId } = confirmControlRollback
  if (!logId) return cancelControlRollback()
  confirmControlRollback.busy = true
  try {
    // Même marge de timeout que la remédiation initiale : signature + envoi
    // à l'agent + rejeu.
    const res = await client.post(`/agent/rollback-control/${logId}`, null, { timeout: 300000 })
    const data = res.data
    if (data.log_status === 'success') {
      ui.notify(`Annulation de ${controlId} effectuée et vérifiée.`, 'success', 0)
    } else {
      const reason = data.remediation?.error || 'l\'annulation a échoué'
      ui.notify(`Annulation de ${controlId} : ${reason}`, 'error')
    }
    if (audit.value) await auditsStore.loadAudit(audit.value.id)
    // Annulé avec succès (ou tenté) : sort de la liste des contrôles corrigés
    // — un rejeu 'error' remet de toute façon le contrôle en échec, donc il
    // n'a plus sa place ici (le rafraîchissement ci-dessus le fera réapparaître
    // dans le tableau des non-conformes s'il y a lieu).
    remediatedControls.value = remediatedControls.value.filter(r => r.controlId !== controlId)
  } catch (err) {
    ui.notify(err.response?.data?.error || err.message, 'error')
  } finally {
    confirmControlRollback.busy = false
    confirmControlRollback.open = false
    confirmControlRollback.controlId = null
    confirmControlRollback.logId = null
  }
}
</script>

<template>
  <div v-if="systemsStore.currentLoading" class="state-block">Chargement du système…</div>
  <div v-else-if="systemsStore.currentError === 'not_found'" class="state-block">
    <p>Ce système n'existe pas (ou plus).</p>
    <button class="secondary-btn" @click="goBack">
      <ArrowLeft :size="15" /> Retour au tableau de bord
    </button>
  </div>
  <div v-else-if="systemsStore.currentError" class="state-block state-block--error">
    <p>{{ systemsStore.currentError }}</p>
    <button class="secondary-btn" @click="loadSystemAndAudits(route.params.id)">Réessayer</button>
  </div>

  <div v-else-if="system" class="system-detail">
    <header class="system-header">
      <button class="back-btn" @click="goBack">
        <ArrowLeft :size="15" /> Retour
      </button>
      <div class="system-meta">
        <h1 class="hostname">{{ system.hostname }}</h1>
        <div class="meta-row">
          <span class="meta-item mono">{{ system.ip_address }}</span>
          <span class="separator">·</span>
          <span class="meta-item os-meta">
            <OsIcon :os-type="system.os_type" :size="14" />
            {{ system.os_version }}
          </span>
          <span class="separator">·</span>
          <span class="status-indicator" :data-status="system.status">
            <span class="status-dot"></span>
            {{ system.status === 'online' ? 'EN LIGNE' : 'HORS LIGNE' }}
          </span>
        </div>
      </div>
      <div class="header-actions">
        <button
          v-if="canRunAudit"
          class="primary-btn"
          :disabled="auditsStore.running"
          @click="handleRunAudit"
        >
          <Play v-if="!auditsStore.running" :size="15" />
          {{ auditsStore.running ? 'Audit en cours…' : 'Lancer un audit' }}
        </button>
        <template v-if="canRunAudit && statusCounts.fail > 0">
          <button class="primary-btn script-btn" :disabled="downloadingScript" @click="downloadRemediationScript">
            <Download v-if="!downloadingScript" :size="15" />
            {{ downloadingScript ? '…' : 'Télécharger le script' }}
          </button>
          <button class="primary-btn remediate-btn" :disabled="remediating" @click="executeRemediation">
            <Wrench v-if="!remediating" :size="15" />
            {{ remediating ? 'Envoi en cours…' : `Remédier (${statusCounts.fail} échecs)` }}
          </button>
        </template>
        <span v-else-if="!canRunAudit" class="role-hint">Lecture seule — audit réservé aux auditeurs</span>
        <button v-if="canDelete" class="danger-btn" @click="askDeleteSystem">
          <Trash2 :size="15" /> Supprimer
        </button>
      </div>
    </header>

    <div v-if="auditsStore.running" class="running-banner">
      <span class="spinner"></span>
      Exécution de l'audit en cours sur {{ system.hostname }}…
    </div>

    <section
      v-if="!audit && !auditsStore.loadingDetail && !auditsStore.running"
      class="audit-empty"
    >
      <span class="audit-empty-icon">○</span>
      <div>
        <p class="audit-empty-title">Aucun audit pour ce système</p>
        <p class="audit-empty-sub">
          Ce système n'a pas encore été audité.
          <template v-if="canRunAudit">Lancez un audit pour évaluer sa conformité CIS.</template>
          <template v-else>Un auditeur peut lancer un audit pour évaluer sa conformité.</template>
        </p>
      </div>
    </section>

    <template v-if="audit">
      <section class="score-section">
        <div class="score-card">
          <span class="card-label">Dernier audit</span>
          <ScoreGauge :score="audit.score_global || 0" />
          <RiskBadge v-if="audit.risk_level" :level="audit.risk_level" />
          <span class="audit-date">{{ formatDate(audit.finished_at || audit.created_at) }}</span>
        </div>
        <div class="radar-card">
          <h3 class="card-title">Scores par domaine</h3>
          <DomainRadar v-if="audit.scores_by_domain" :scores="audit.scores_by_domain" />
        </div>
      </section>

      <section class="controls-section">
        <div class="section-header">
          <h2>Contrôles non conformes · {{ filteredControls.length }} / {{ audit.results.length }}</h2>
          <div class="filters">
            <select v-model="filterDomain" class="filter-select">
              <option value="">Tous domaines</option>
              <option v-for="(label, key) in DOMAIN_LABELS" :key="key" :value="key">{{ label }}</option>
            </select>
          </div>
        </div>

        <div class="controls-table">
          <div class="table-head">
            <span>ID</span>
            <span>TITRE</span>
            <span>DOMAINE</span>
            <span>STATUT</span>
          </div>
          <div v-for="c in filteredControls" :key="c.control_id" class="control-row">
            <span class="control-id" :title="c.control_id">{{ c.control_id }}</span>
            <div class="control-title">
              <span class="title-text">{{ c.title }}</span>
              <span class="title-detail">
                attendu : <span class="exp">{{ c.expected_value ?? '—' }}</span> ·
                observé : <span class="act">{{ c.actual_value ?? '—' }}</span>
              </span>
            </div>
            <span class="control-domain">{{ DOMAIN_LABELS[c.domain] || c.domain }}</span>
            <div class="control-actions">
              <StatusBadge :status="c.status" />
              <button
                v-if="canRunAudit"
                class="btn-remediate"
                :disabled="remediatingControl === c.control_id"
                @click="handleRemediate(c.control_id)"
                title="Remédiation unitaire de ce contrôle"
              >
                <Zap v-if="remediatingControl !== c.control_id" :size="14" />
                {{ remediatingControl === c.control_id ? '…' : 'Remédier' }}
              </button>
            </div>
          </div>
          <div v-if="filteredControls.length === 0" class="empty-state">
            {{ filterDomain ? 'Aucun contrôle non conforme dans ce domaine.' : 'Aucun contrôle non conforme — tout est conforme.' }}
          </div>
        </div>
      </section>

      <!-- Contrôles corrigés sortant des tableaux fail/warn (repassés 'pass') :
           liste séparée, seul endroit où accrocher l'annulation ciblée. -->
      <section v-if="remediatedControls.length > 0" class="controls-section remediated-section">
        <div class="section-header">
          <h2> Corrigés durant cette session · {{ remediatedControls.length }}</h2>
        </div>
        <div class="controls-table">
          <div class="table-head">
            <span>ID</span>
            <span>TITRE</span>
            <span>DOMAINE</span>
            <span>STATUT</span>
          </div>
          <div v-for="r in remediatedControls" :key="r.controlId" class="control-row">
            <span class="control-id" :title="r.controlId">{{ r.controlId }}</span>
            <div class="control-title">
              <span class="title-text">{{ r.title }}</span>
            </div>
            <span class="control-domain">{{ DOMAIN_LABELS[r.domain] || r.domain || '—' }}</span>
            <div class="control-actions">
              <StatusBadge status="pass" />
              <button
                v-if="canRunAudit && r.undoAvailable"
                class="btn-remediate"
                @click="askControlRollback(r)"
                title="Annuler cette remédiation (remet la valeur d'avant)"
              >
                ↩ Annuler
              </button>
              <span v-else-if="canRunAudit" class="undo-unavailable" title="Annulation individuelle non disponible pour ce type de contrôle — seule la restauration globale (Sauvegardes) couvre ce réglage.">
                annulation indisponible
              </span>
            </div>
          </div>
        </div>
      </section>

      <!-- Contrôles à condition ambiguë : jamais 'fail', donc absents du
           tableau ci-dessus et jamais proposés à la remédiation groupée.
           Rendus visibles ici plutôt que silencieusement invisibles. -->
      <section v-if="warnControls.length > 0" class="controls-section warn-section">
        <div class="section-header">
          <h2><AlertTriangle :size="16" class="h2-icon" /> À vérifier manuellement · {{ warnControls.length }}</h2>
        </div>

        <div class="controls-table">
          <div class="table-head">
            <span>ID</span>
            <span>TITRE</span>
            <span>DOMAINE</span>
            <span>STATUT</span>
          </div>
          <div v-for="c in warnControls" :key="c.control_id" class="control-row">
            <span class="control-id" :title="c.control_id">{{ c.control_id }}</span>
            <div class="control-title">
              <span class="title-text">{{ c.title }}</span>
              <span class="title-detail">
                attendu : <span class="exp">{{ c.expected_value ?? '—' }}</span> ·
                observé : <span class="act">{{ c.actual_value ?? '—' }}</span>
              </span>
            </div>
            <span class="control-domain">{{ DOMAIN_LABELS[c.domain] || c.domain }}</span>
            <div class="control-actions">
              <StatusBadge :status="c.status" />
              <button
                v-if="canRunAudit"
                class="btn-remediate"
                :disabled="remediatingControl === c.control_id"
                @click="handleRemediate(c.control_id)"
                title="Tenter une remédiation automatique si disponible (le statut restera à vérifier manuellement après)"
              >
                <Zap v-if="remediatingControl !== c.control_id" :size="14" />
                {{ remediatingControl === c.control_id ? '…' : 'Remédier' }}
              </button>
            </div>
          </div>
        </div>
      </section>
    </template>

    <section v-if="auditsStore.history.length > 0" class="history-section">
      <h2 class="section-title">Historique des audits</h2>
      <div class="history-table">
        <div class="history-head">
          <span>DATE</span><span>SCORE</span><span>RISQUE</span><span>STATUT</span><span></span>
        </div>
        <div
          v-for="h in auditsStore.history" :key="h.id"
          class="history-row" :class="{ active: audit && h.id === audit.id }"
          @click="viewAudit(h.id)"
        >
          <span class="mono">{{ formatDate(h.finished_at || h.created_at) }}</span>
          <span class="mono">{{ h.score_global ?? '—' }}</span>
          <RiskBadge v-if="h.risk_level" :level="h.risk_level" />
          <span v-else class="mono muted">—</span>
          <span class="mono">{{ h.status }}</span>
          <span class="view-link">{{ audit && h.id === audit.id ? 'affiché' : 'voir →' }}</span>
        </div>
      </div>
    </section>

    <section v-if="snapshots.length > 0" class="snapshots-section">
      <h2 class="section-title">Sauvegardes</h2>
      <p class="section-hint">Sauvegarde globale créée automatiquement avant chaque remédiation (Windows : politique de sécurité + registre ; Linux : archive /etc). La restauration rétablit l'état complet capturé — pas un réglage ciblé.</p>
      <div class="snapshots-table">
        <div class="snapshots-head">
          <span>DATE</span><span>NOM</span><span></span>
        </div>
        <div v-for="s in snapshots" :key="s.id" class="snapshots-row">
          <span class="mono">{{ formatDate(s.created_at) }}</span>
          <span class="mono">{{ s.name }}</span>
          <button
            v-if="canRunAudit"
            class="secondary-btn"
            @click="askRollback(s)"
          >
            ↩ Restaurer
          </button>
        </div>
      </div>
    </section>
  </div>

  <Teleport to="body">
    <ConfirmDialog
      v-if="confirmDelete.open"
      title="Supprimer cette machine ?"
      :message="`« ${system?.hostname} » et tout son historique d'audits seront définitivement supprimés. Cette action est irréversible.`"
      confirm-label="Supprimer définitivement"
      danger
      :busy="confirmDelete.busy"
      @confirm="executeDeleteSystem"
      @cancel="cancelDeleteSystem"
    />
    <ConfirmDialog
      v-if="confirmRollback.open"
      title="Restaurer cette sauvegarde ?"
      :message="`La politique de sécurité et le registre seront restaurés à l'état de la sauvegarde « ${confirmRollback.snapshot?.name} » (${formatDate(confirmRollback.snapshot?.created_at)}). C'est une restauration GLOBALE : tout changement effectué depuis sera perdu.`"
      confirm-label="Restaurer"
      danger
      :busy="confirmRollback.busy"
      @confirm="executeRollback"
      @cancel="cancelRollback"
    />
    <ConfirmDialog
      v-if="confirmControlRollback.open"
      title="Annuler cette remédiation ?"
      :message="`Le contrôle « ${confirmControlRollback.controlId} » sera remis à sa valeur d'avant la remédiation. Contrairement à la restauration globale, seul ce réglage est concerné.`"
      confirm-label="Annuler la remédiation"
      danger
      :busy="confirmControlRollback.busy"
      @confirm="executeControlRollback"
      @cancel="cancelControlRollback"
    />
  </Teleport>
</template>

<style scoped>
.system-detail { display: flex; flex-direction: column; gap: var(--space-8); }
.state-block { padding: var(--space-12); text-align: center; font-family: var(--font-mono); color: var(--text-muted); display: flex; flex-direction: column; align-items: center; gap: var(--space-5); }
.state-block--error { color: var(--status-fail); }
.system-header { display: flex; align-items: center; gap: var(--space-6); }
.header-actions { margin-left: auto; display: flex; gap: var(--space-3); align-items: center; }
.role-hint { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-muted); }
.back-btn, .secondary-btn { background-color: transparent; border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-2) var(--space-4); color: var(--text-secondary); font-family: var(--font-ui); font-size: var(--text-sm); cursor: pointer; transition: var(--transition-base); white-space: nowrap; }
.back-btn:hover, .secondary-btn:hover { border-color: var(--accent); color: var(--accent); }
.primary-btn { background-color: var(--accent); color: var(--bg-base); border: none; border-radius: var(--radius-md); padding: var(--space-3) var(--space-5); font-family: var(--font-ui); font-size: var(--text-sm); font-weight: 600; cursor: pointer; transition: var(--transition-base); }
.primary-btn:hover:not(:disabled) { background-color: var(--accent-hover); }
.primary-btn:disabled { opacity: 0.6; cursor: not-allowed; }
.remediate-btn { background: transparent !important; border: 1px solid var(--status-warn) !important; color: var(--status-warn) !important; }
.remediate-btn:hover { background: var(--status-warn) !important; color: var(--bg-base) !important; }
.danger-btn { background-color: transparent; border: 1px solid var(--status-fail); border-radius: var(--radius-md); padding: var(--space-3) var(--space-5); color: var(--status-fail); font-family: var(--font-ui); font-size: var(--text-sm); cursor: pointer; transition: var(--transition-base); white-space: nowrap; }
.danger-btn:hover { background-color: var(--status-fail); color: var(--bg-base); }
/* Alignement icône Lucide + texte dans les boutons (les icônes héritent de
   la couleur du bouton via currentColor, donc suivent le thème). */
.back-btn, .secondary-btn, .primary-btn, .danger-btn {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
}
.system-meta { display: flex; flex-direction: column; gap: var(--space-2); }
.hostname { font-family: var(--font-mono); font-size: var(--text-2xl); color: var(--text-primary); margin: 0; }
.meta-row { display: flex; align-items: center; gap: var(--space-3); font-size: var(--text-sm); color: var(--text-secondary); }
.meta-item.mono { font-family: var(--font-mono); }
.meta-item.os-meta { display: inline-flex; align-items: center; gap: var(--space-2); }
.separator { color: var(--text-muted); }
.status-indicator { display: flex; align-items: center; gap: var(--space-2); font-family: var(--font-mono); font-size: var(--text-xs); letter-spacing: 0.5px; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; }
.status-indicator[data-status="online"] .status-dot { background-color: var(--status-pass); box-shadow: 0 0 8px var(--status-pass); }
.status-indicator[data-status="online"] { color: var(--status-pass); }
.status-indicator[data-status="offline"] .status-dot { background-color: var(--text-muted); }
.status-indicator[data-status="offline"] { color: var(--text-muted); }
.running-banner { display: flex; align-items: center; gap: var(--space-3); padding: var(--space-4) var(--space-6); background-color: var(--accent-dim); border: 1px solid var(--accent); border-radius: var(--radius-md); color: var(--accent); font-family: var(--font-mono); font-size: var(--text-sm); }
.spinner { width: 14px; height: 14px; border: 2px solid var(--accent-dim); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.audit-empty { display: flex; align-items: center; gap: var(--space-4); padding: var(--space-8); background-color: var(--bg-surface); border: 1px dashed var(--border); border-radius: var(--radius-md); }
.audit-empty-icon { font-size: 2rem; color: var(--text-muted); line-height: 1; }
.audit-empty-title { font-family: var(--font-mono); font-size: var(--text-base); color: var(--text-secondary); margin: 0 0 var(--space-2) 0; }
.audit-empty-sub { font-family: var(--font-ui); font-size: var(--text-sm); color: var(--text-muted); margin: 0; line-height: 1.5; }
.score-section { display: grid; grid-template-columns: 260px 1fr; gap: var(--space-6); }
.score-card, .radar-card { background-color: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-6); }
.score-card { display: flex; flex-direction: column; align-items: center; gap: var(--space-4); }
.card-label { font-family: var(--font-ui); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }
.audit-date { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-muted); }
.card-title { font-family: var(--font-mono); font-size: var(--text-base); color: var(--text-primary); margin: 0 0 var(--space-3) 0; }
.controls-section, .history-section, .snapshots-section { display: flex; flex-direction: column; gap: var(--space-4); }
.section-hint { font-family: var(--font-ui); font-size: var(--text-sm); color: var(--text-muted); margin: 0; }
.snapshots-table { background-color: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-md); overflow: hidden; }
.snapshots-head { display: grid; grid-template-columns: 220px minmax(0, 1fr) 140px; gap: var(--space-4); padding: var(--space-3) var(--space-6); background-color: var(--bg-elevated); border-bottom: 1px solid var(--border); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); font-family: var(--font-ui); font-weight: 500; }
.snapshots-row { display: grid; grid-template-columns: 220px minmax(0, 1fr) 140px; gap: var(--space-4); align-items: center; padding: var(--space-3) var(--space-6); border-bottom: 1px solid var(--border-subtle); }
.snapshots-row:last-child { border-bottom: none; }
.remediated-section .section-header h2 { color: var(--status-pass); }
.undo-unavailable { font-family: var(--font-ui); font-size: var(--text-xs); color: var(--text-muted); font-style: italic; white-space: nowrap; }
.section-header { display: flex; justify-content: space-between; align-items: center; }
.section-header h2, .section-title { font-family: var(--font-mono); font-size: var(--text-lg); color: var(--text-primary); margin: 0; }
.warn-section .section-header h2 { color: var(--status-warn); display: inline-flex; align-items: center; gap: var(--space-2); }
/* L'icône du titre suit la couleur du h2 (var(--status-warn)) via currentColor. */
.h2-icon { flex-shrink: 0; }
.filters { display: flex; gap: var(--space-3); align-items: center; }
.filter-select { background-color: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-2) var(--space-3); color: var(--text-primary); font-family: var(--font-ui); font-size: var(--text-sm); cursor: pointer; }
.controls-table, .history-table { background-color: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-md); overflow: hidden; }
.table-head { display: grid; grid-template-columns: 180px minmax(0, 1fr) 130px 160px; gap: var(--space-4); padding: var(--space-3) var(--space-6); background-color: var(--bg-elevated); border-bottom: 1px solid var(--border); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); font-family: var(--font-ui); font-weight: 500; }
.control-row { display: grid; grid-template-columns: 180px minmax(0, 1fr) 130px 160px; gap: var(--space-4); align-items: center; padding: var(--space-3) var(--space-6); border-bottom: 1px solid var(--border-subtle); }
.control-row:last-child { border-bottom: none; }
.control-id { font-family: var(--font-mono); font-size: var(--text-sm); color: var(--text-secondary); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.control-title { display: flex; flex-direction: column; gap: var(--space-1); min-width: 0; }
.title-text { font-family: var(--font-ui); font-size: var(--text-sm); color: var(--text-primary); }
.title-detail { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-muted); }
.title-detail .exp { color: var(--status-pass); }
.title-detail .act { color: var(--status-fail); }
.control-domain { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary); }
/* Colonne STATUT : badge au-dessus du bouton, empilés et étirés à la même
   largeur (bords alignés d'une ligne à l'autre). align-items: stretch évite
   l'alignement irrégulier dû aux largeurs de badge variables. gap tokenisé.
   min-height réserve la place du bouton même sur les lignes SANS bouton
   (conformes) → hauteur de ligne régulière avec ou sans « Remédier ». */
.control-actions { display: flex; flex-direction: column; align-items: stretch; justify-content: center; gap: var(--space-2); min-height: calc(var(--space-12) + var(--space-4)); }
/* Badge étiré à toute la largeur de la colonne (via align-items: stretch du
   parent) : on centre son contenu pour un rendu régulier. Ciblé UNIQUEMENT ici
   (:deep) pour ne pas affecter StatusBadge dans les autres vues. */
.control-actions :deep(.status-badge) { justify-content: center; }
.btn-remediate { display: inline-flex; align-items: center; justify-content: center; gap: var(--space-2); font-family: var(--font-mono); font-size: var(--text-xs); padding: var(--space-1) var(--space-2); border: 1px solid var(--status-warn); border-radius: var(--radius-sm); background: transparent; color: var(--status-warn); cursor: pointer; white-space: nowrap; transition: background 0.15s, color 0.15s; }
.btn-remediate:hover:not(:disabled) { background: var(--status-warn); color: var(--bg-base); }
.btn-remediate:disabled { opacity: 0.5; cursor: default; }
.empty-state { padding: var(--space-8); text-align: center; color: var(--text-muted); font-family: var(--font-mono); font-size: var(--text-sm); }
.history-head, .history-row { display: grid; grid-template-columns: 1fr 80px 120px 90px 80px; gap: var(--space-4); align-items: center; padding: var(--space-3) var(--space-6); }
.history-head { background-color: var(--bg-elevated); border-bottom: 1px solid var(--border); font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); font-family: var(--font-ui); }
.history-row { border-bottom: 1px solid var(--border-subtle); cursor: pointer; transition: var(--transition-base); font-size: var(--text-sm); }
.history-row:last-child { border-bottom: none; }
.history-row:hover { background-color: var(--bg-elevated); }
.history-row.active { background-color: var(--accent-dim); }
.mono { font-family: var(--font-mono); }
.muted { color: var(--text-muted); }
.view-link { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--accent); text-align: right; }
.script-btn { background: transparent !important; border: 1px solid var(--text-secondary) !important; color: var(--text-secondary) !important; }
.script-btn:hover:not(:disabled) { border-color: var(--accent) !important; color: var(--accent) !important; }
</style>

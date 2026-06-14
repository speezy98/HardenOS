import { defineStore } from 'pinia'
import { ref } from 'vue'
import * as auditsApi from '@/api/audits.js'

export const useAuditsStore = defineStore('audits', () => {
  // --- État réel (backend) ---
  const currentAudit = ref(null) // détail d'un audit (avec results)
  const history = ref([]) // historique résumé d'un système (récent -> ancien)

  const loadingDetail = ref(false)
  const detailError = ref(null)

  const loadingHistory = ref(false)
  const historyError = ref(null)

  const running = ref(false) // un audit est en cours d'exécution
  const runError = ref(null)

  // Déclenche un audit (POST /api/audits) avec options éventuelles
  // (ssh_user, ssh_password, save_credentials, use_stub, seed).
  // - Bouchon (use_stub) : réponse 201, audit déjà terminé.
  // - SSH réel : réponse 202, audit en `running` -> on POLL jusqu'à done/error.
  // Propage une erreur exploitable par la vue (403, 400 credentials requis, etc.).
  const runAudit = async (systemId, options = {}) => {
    running.value = true
    runError.value = null
    try {
      const { data } = await auditsApi.trigger(systemId, options)
      currentAudit.value = data
      // Audit asynchrone encore en cours : on suit son avancement.
      if (data.status === 'running') {
        return await _pollUntilDone(data.id)
      }
      return data
    } catch (err) {
      const status = err.response?.status
      if (status === 403) {
        runError.value = "Accès refusé : seul un auditeur ou un administrateur peut lancer un audit."
      } else {
        runError.value =
          err.response?.data?.error ||
          "Échec du lancement de l'audit (backend injoignable ?)"
      }
      throw new Error(runError.value)
    } finally {
      running.value = false
    }
  }

  // Poll l'audit jusqu'à done/error (ou délai max). Met à jour currentAudit.
  const _pollUntilDone = async (auditId, { intervalMs = 1500, maxMs = 180000 } = {}) => {
    const start = Date.now()
    // eslint-disable-next-line no-constant-condition
    while (true) {
      await new Promise((r) => setTimeout(r, intervalMs))
      const { data } = await auditsApi.getById(auditId)
      currentAudit.value = data
      if (data.status === 'done') return data
      if (data.status === 'error') {
        runError.value = "L'audit a échoué (connexion SSH ou exécution). Voir le statut de l'audit."
        throw new Error(runError.value)
      }
      if (Date.now() - start > maxMs) {
        runError.value = "L'audit prend trop de temps (délai dépassé)."
        throw new Error(runError.value)
      }
    }
  }

  // Charge le détail complet d'un audit (GET /api/audits/<id>), résultats inclus.
  const loadAudit = async (id) => {
    loadingDetail.value = true
    detailError.value = null
    try {
      const { data } = await auditsApi.getById(id)
      currentAudit.value = data
      return data
    } catch (err) {
      if (err.response?.status === 404) {
        detailError.value = 'not_found'
      } else {
        detailError.value =
          err.response?.data?.error || "Impossible de charger l'audit."
      }
      return null
    } finally {
      loadingDetail.value = false
    }
  }

  // Charge l'historique résumé des audits d'un système (GET /api/audits?system_id=).
  const loadHistory = async (systemId) => {
    loadingHistory.value = true
    historyError.value = null
    try {
      const { data } = await auditsApi.listForSystem(systemId)
      history.value = data
      return data
    } catch (err) {
      historyError.value =
        err.response?.data?.error || "Impossible de charger l'historique des audits."
      history.value = []
      return []
    } finally {
      loadingHistory.value = false
    }
  }

  const clearCurrent = () => {
    currentAudit.value = null
    detailError.value = null
  }

  // --- Compat héritée (vues encore en mock : Reports, Compare, Remediation) ---
  // Ces vues seront branchées sur le vrai backend dans des branches dédiées.
  // En attendant : `fetchAudit` délègue au vrai backend ; `getAuditPair` rend
  // une paire vide MAIS NON NULLE (pour que la vue Comparaison dégrade sans
  // planter), sans réintroduire de jeu de données factice.
  const fetchAudit = async (id) => loadAudit(id)
  const _emptySnapshot = (systemId) => ({
    id: null,
    system_id: Number(systemId) || null,
    started_at: null,
    cis_level: 'L1',
    score_global: 0,
    risk_level: 'low',
    results: []
  })
  const getAuditPair = (systemId) => ({
    snapshotA: _emptySnapshot(systemId),
    snapshotB: _emptySnapshot(systemId)
  })

  return {
    currentAudit,
    history,
    loadingDetail,
    detailError,
    loadingHistory,
    historyError,
    running,
    runError,
    runAudit,
    // Exposée pour suivre un audit déclenché en dehors de runAudit (ex. audit
    // automatique après une restauration globale, cf. SystemDetailView).
    pollUntilDone: _pollUntilDone,
    loadAudit,
    loadHistory,
    clearCurrent,
    // compat
    fetchAudit,
    getAuditPair
  }
})

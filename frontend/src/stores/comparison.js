import { defineStore } from 'pinia'
import { ref } from 'vue'
import * as comparisonApi from '@/api/comparison.js'

// Message d'erreur clair renvoyé par le backend (ou repli générique).
const errorMessage = (err, fallback) => err?.response?.data?.error || fallback

export const useComparisonStore = defineStore('comparison', () => {
  // Étape 1 — machines comparables (>= 2 audits terminés, filtré par le backend).
  const systems = ref([])
  const loadingSystems = ref(false)
  const systemsError = ref(null)

  // Étape 2 — audits terminés de la machine choisie.
  const audits = ref([])
  const loadingAudits = ref(false)
  const auditsError = ref(null)

  // Étape 3 — résultat de la comparaison de deux audits.
  const result = ref(null)
  const loadingResult = ref(false)
  const resultError = ref(null)

  const fetchSystems = async () => {
    loadingSystems.value = true
    systemsError.value = null
    try {
      const { data } = await comparisonApi.getComparableSystems()
      systems.value = data
    } catch (err) {
      systemsError.value = errorMessage(err, 'Impossible de charger les machines comparables')
      systems.value = []
    } finally {
      loadingSystems.value = false
    }
  }

  const fetchAudits = async (systemId) => {
    loadingAudits.value = true
    auditsError.value = null
    audits.value = []
    result.value = null // une nouvelle machine invalide la comparaison affichée
    try {
      const { data } = await comparisonApi.getSystemAudits(systemId)
      audits.value = data
    } catch (err) {
      auditsError.value = errorMessage(err, 'Impossible de charger les audits de cette machine')
      audits.value = []
    } finally {
      loadingAudits.value = false
    }
  }

  const compare = async (auditA, auditB) => {
    loadingResult.value = true
    resultError.value = null
    try {
      const { data } = await comparisonApi.compare(auditA, auditB)
      result.value = data
      return data
    } catch (err) {
      // 400 (même machine / mêmes audits), 404 (audit introuvable)… : message clair.
      resultError.value = errorMessage(err, 'Impossible de comparer ces deux audits')
      result.value = null
      return null
    } finally {
      loadingResult.value = false
    }
  }

  const clearResult = () => {
    result.value = null
    resultError.value = null
  }

  return {
    systems, loadingSystems, systemsError,
    audits, loadingAudits, auditsError,
    result, loadingResult, resultError,
    fetchSystems, fetchAudits, compare, clearResult
  }
})

import client from './client.js'

// Rapport complet d'un audit (identité, synthèse, compteurs, contrôles +
// remediation). Assemblé par le backend : GET /api/reports/<audit_id>.
// Lecture seule, accessible à tout utilisateur authentifié.
export const getReport = (auditId) => {
  return client.get(`/reports/${auditId}`)
}

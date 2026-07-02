import client from './client.js'

// --- Comparaison d'audits (/api/comparison) ---------------------------------
// Lecture seule, accessible à tout utilisateur authentifié. Totalement
// agnostique à l'OS : ces appels n'envoient jamais de filtre os_type.

// Machines comparables : celles ayant au moins deux audits terminés
// (le filtre >= 2 audits est fait côté backend).
export const getComparableSystems = () => {
  return client.get('/comparison/systems')
}

// Audits terminés d'un système (id, date, score) pour choisir les deux à comparer.
export const getSystemAudits = (systemId) => {
  return client.get(`/comparison/systems/${systemId}/audits`)
}

// Compare deux audits d'une même machine (A = avant, B = après).
export const compare = (auditA, auditB) => {
  return client.get('/comparison', { params: { audit_a: auditA, audit_b: auditB } })
}

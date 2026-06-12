import client from './client.js'

// Familles / OS / versions auditables, dérivées des référentiels CIS présents
// côté backend (GET /api/cis-rules/available). Le formulaire d'ajout de machine
// s'en sert pour ne proposer QUE ce qui est réellement auditable — aucune valeur
// codée en dur : si un référentiel est ajouté/retiré, le formulaire suit.
export const getAvailable = () => {
  return client.get('/cis-rules/available')
}

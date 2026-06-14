import client from './client.js'

export const getById = (id) => {
  return client.get(`/audits/${id}`)
}

export const listForSystem = (systemId) => {
  return client.get('/audits', { params: { system_id: systemId } })
}

// Déclenche un audit. `options` peut contenir ssh_user, ssh_password,
// save_credentials, use_stub, seed (voir le backend).
export const trigger = (systemId, options = {}) => {
  return client.post('/audits', { system_id: systemId, ...options })
}

export const createSnapshot = (auditId, name) => {
  return client.post(`/audits/${auditId}/snapshot`, { name })
}

export const compareSnapshots = (snapAId, snapBId) => {
  return client.get('/snapshots/compare', {
    params: { a: snapAId, b: snapBId }
  })
}

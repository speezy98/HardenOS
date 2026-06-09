import client from './client.js'

export const getAll = (params) => {
  return client.get('/systems', { params })
}

export const getById = (id) => {
  return client.get(`/systems/${id}`)
}

export const create = (data) => {
  return client.post('/systems', data)
}

export const update = (id, data) => {
  return client.put(`/systems/${id}`, data)
}

export const remove = (id) => {
  return client.delete(`/systems/${id}`)
}

// Pose / met à jour les credentials SSH via l'endpoint DÉDIÉ. Corps EXACT
// attendu par le scanner : { ssh_user, ssh_password } (le backend le chiffre en
// JSON {ssh_user, ssh_password} relu par le collecteur). Ne jamais passer par le
// POST /systems pour les credentials.
export const setCredentials = (id, { ssh_user, ssh_password }) => {
  return client.put(`/systems/${id}/credentials`, { ssh_user, ssh_password })
}

export const testConnection = (id) => {
  return client.post(`/systems/${id}/test-connection`)
}

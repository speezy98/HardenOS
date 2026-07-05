import client from './client.js'

// --- Administration des utilisateurs (réservé aux admins, /api/users) --------

export const getAll = () => {
  return client.get('/users')
}

export const create = (data) => {
  return client.post('/users', data)
}

// Le backend accepte PATCH et PUT ; on utilise PATCH (mise à jour partielle).
export const update = (id, data) => {
  return client.patch(`/users/${id}`, data)
}

export const revoke = (id) => {
  return client.post(`/users/${id}/revoke`)
}

export const reactivate = (id) => {
  return client.post(`/users/${id}/reactivate`)
}

export const remove = (id) => {
  return client.delete(`/users/${id}`)
}

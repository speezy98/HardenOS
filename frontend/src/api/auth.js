import client from './client.js'

export const login = (email, password) => {
  return client.post('/auth/login', { email, password })
}

export const logout = () => {
  return client.post('/auth/logout')
}

// Le refresh s'authentifie avec le REFRESH token (et non l'access token).
// On le passe explicitement en en-tête, et on marque la requête pour que
// l'intercepteur de réponse ne tente pas de la rafraîchir à son tour.
export const refreshToken = (token) => {
  return client.post('/auth/refresh', null, {
    headers: { Authorization: `Bearer ${token}` },
    _skipAuthRefresh: true
  })
}

export const me = () => {
  return client.get('/auth/me')
}

import client from './client.js'

// --- "Mon compte" : self-service pour l'utilisateur courant (/api/account) ----
// Accessible à tout utilisateur authentifié. Agit uniquement sur SON compte
// (identifié par le JWT côté backend) ; le rôle et le statut ne sont pas
// modifiables via ces routes.

export const getAccount = () => {
  return client.get('/account')
}

// Corps : { new_email, current_password } — re-confirmation du mot de passe.
export const changeEmail = (payload) => {
  return client.patch('/account/email', payload)
}

// Corps : { current_password, new_password }.
export const changePassword = (payload) => {
  return client.patch('/account/password', payload)
}

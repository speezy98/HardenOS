import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import * as usersApi from '@/api/users.js'

// Extrait le message d'erreur clair renvoyé par le backend (ex. 409 dernier
// admin, email déjà pris) pour le remonter tel quel à l'interface.
const errorMessage = (err, fallback) =>
  err?.response?.data?.error || fallback

export const useUsersStore = defineStore('users', () => {
  const users = ref([])
  const loading = ref(false)
  const error = ref(null)

  // KPI dérivés pour le sous-titre du header
  const counts = computed(() => ({
    total: users.value.length,
    admin: users.value.filter(u => u.role === 'admin').length,
    auditor: users.value.filter(u => u.role === 'auditor').length,
    readonly: users.value.filter(u => u.role === 'readonly').length
  }))

  // Remplace ou insère un utilisateur dans la liste locale à partir de la
  // réponse backend (source de vérité), sans re-fetch complet.
  const upsert = (user) => {
    const idx = users.value.findIndex(u => u.id === user.id)
    if (idx === -1) users.value = [...users.value, user]
    else users.value[idx] = user
  }

  const fetchUsers = async () => {
    loading.value = true
    error.value = null
    try {
      const { data } = await usersApi.getAll()
      users.value = data
    } catch (err) {
      error.value = errorMessage(err, 'Impossible de charger les utilisateurs')
      users.value = []
      throw err
    } finally {
      loading.value = false
    }
  }

  // Les mutations renvoient l'utilisateur backend (ou rien pour delete) et
  // laissent l'erreur remonter : la vue décide du toast succès/échec.
  const createUser = async (payload) => {
    const { data } = await usersApi.create(payload)
    upsert(data)
    return data
  }

  const updateUser = async (id, payload) => {
    const { data } = await usersApi.update(id, payload)
    upsert(data)
    return data
  }

  const revokeUser = async (id) => {
    const { data } = await usersApi.revoke(id)
    upsert(data)
    return data
  }

  const reactivateUser = async (id) => {
    const { data } = await usersApi.reactivate(id)
    upsert(data)
    return data
  }

  const deleteUser = async (id) => {
    await usersApi.remove(id)
    users.value = users.value.filter(u => u.id !== id)
  }

  return {
    users,
    loading,
    error,
    counts,
    errorMessage,
    fetchUsers,
    createUser,
    updateUser,
    revokeUser,
    reactivateUser,
    deleteUser
  }
})

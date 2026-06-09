import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import * as systemsApi from '@/api/systems.js'

export const useSystemsStore = defineStore('systems', () => {
  // Liste du parc, alimentée par GET /api/systems (aucune donnée mock).
  const systems = ref([])
  const loading = ref(false)
  const error = ref(null)

  // Détail courant, alimenté par GET /api/systems/:id.
  const current = ref(null)
  const currentLoading = ref(false)
  const currentError = ref(null)

  // État de création (ajout de machine, brique 3).
  const creating = ref(false)
  const createError = ref(null)
  // Id de la dernière machine créée (pour la mettre en évidence dans la liste).
  const lastCreatedId = ref(null)

  // État de suppression.
  const deleting = ref(false)
  const deleteError = ref(null)

  const total = computed(() => systems.value.length)

  const fetchSystems = async () => {
    loading.value = true
    error.value = null
    try {
      const { data } = await systemsApi.getAll()
      systems.value = data
    } catch (err) {
      error.value =
        err.response?.data?.error ||
        'Impossible de charger les systèmes (backend injoignable ?)'
      systems.value = []
    } finally {
      loading.value = false
    }
  }

  // Charge le détail d'un système. Retourne le système, ou null si 404/erreur
  // (currentError est positionné, la vue décide quoi afficher).
  const fetchSystem = async (id) => {
    currentLoading.value = true
    currentError.value = null
    current.value = null
    try {
      const { data } = await systemsApi.getById(id)
      current.value = data
      return data
    } catch (err) {
      if (err.response?.status === 404) {
        currentError.value = 'not_found'
      } else {
        currentError.value =
          err.response?.data?.error ||
          'Impossible de charger le système (backend injoignable ?)'
      }
      return null
    } finally {
      currentLoading.value = false
    }
  }

  // Accès synchrone à un système déjà chargé dans la liste (données réelles,
  // sans aucune donnée d'audit). Retourne null si absent. Conservé pour les
  // vues encore en mock (Reports) qui résolvent un système par id ; elles
  // dégradent proprement faute de données d'audit.
  const getById = (id) => {
    return systems.value.find((s) => s.id === Number(id)) || null
  }

  // Création d'une machine EN DEUX TEMPS (brique 3) :
  //   1) POST /api/systems  (champs système, SANS mot de passe SSH)
  //   2) si credentials fournis (Linux) : PUT /api/systems/<id>/credentials
  //      avec le format EXACT { ssh_user, ssh_password } (seul format relu par
  //      le scanner). Jamais de mot de passe dans le POST général.
  //
  // `payload` = { os_type, connection_mode, system:{...}, credentials?:{ssh_user,ssh_password} }
  // (forme émise par AddMachineModal.buildPayload).
  //
  // Résout { system } en cas de succès. Lève une Error au message lisible
  // sinon ; si la machine est créée mais la pose de credentials échoue, le
  // message le signale explicitement (état non silencieux) et la liste est
  // quand même rafraîchie (la machine existe, juste sans credentials).
  const createMachine = async (payload) => {
    creating.value = true
    createError.value = null
    lastCreatedId.value = null

    // --- Étape 1 : créer la machine (sans credentials) ---
    let created
    try {
      const { data } = await systemsApi.create(payload.system)
      created = data
    } catch (err) {
      createError.value =
        err.response?.data?.error ||
        'Échec de la création de la machine (backend injoignable ?)'
      creating.value = false
      throw new Error(createError.value)
    }

    // --- Étape 2 : poser les credentials SSH si fournis (Linux) ---
    const creds = payload.credentials
    if (creds && creds.ssh_user && creds.ssh_password) {
      try {
        const { data } = await systemsApi.setCredentials(created.id, creds)
        created = data
        if (!created.has_credentials) {
          // Le backend a répondu 200 mais n'a pas enregistré le secret : anomalie.
          throw new Error('has_credentials est resté faux après la pose des identifiants.')
        }
      } catch (err) {
        // Machine CRÉÉE mais credentials NON posés : on le signale clairement
        // au lieu de laisser un état incohérent silencieux. La liste est
        // rafraîchie pour que la machine (sans credentials) apparaisse.
        await fetchSystems()
        lastCreatedId.value = created.id
        createError.value =
          `Machine « ${created.hostname} » créée, mais l'enregistrement des ` +
          `identifiants SSH a échoué : ${err.response?.data?.error || err.message}. ` +
          `Vous pourrez les poser à nouveau depuis la machine.`
        creating.value = false
        throw new Error(createError.value)
      }
    }

    // --- Succès : rafraîchir la liste et mémoriser la machine créée ---
    await fetchSystems()
    lastCreatedId.value = created.id
    creating.value = false
    return created
  }

  // Supprime une machine (DELETE /api/systems/<id>). Retire la machine de l'état
  // local et nettoie le détail courant si c'est elle. Lève une Error au message
  // lisible en cas d'échec (l'appelant NE doit pas prétendre que c'est supprimé).
  const deleteMachine = async (id) => {
    deleting.value = true
    deleteError.value = null
    try {
      await systemsApi.remove(id)
      // Mise à jour locale immédiate (pas de re-fetch obligatoire).
      systems.value = systems.value.filter((s) => s.id !== Number(id))
      if (current.value?.id === Number(id)) current.value = null
      if (lastCreatedId.value === Number(id)) lastCreatedId.value = null
    } catch (err) {
      // 403 : le backend réserve la suppression aux admins (DELETE = admin).
      // On l'explicite plutôt que d'afficher une erreur générique.
      if (err.response?.status === 403) {
        deleteError.value = 'Suppression réservée aux administrateurs.'
      } else {
        deleteError.value =
          err.response?.data?.error ||
          'Échec de la suppression de la machine (backend injoignable ?)'
      }
      throw new Error(deleteError.value)
    } finally {
      deleting.value = false
    }
  }

  return {
    systems,
    loading,
    error,
    total,
    current,
    currentLoading,
    currentError,
    creating,
    createError,
    lastCreatedId,
    deleting,
    deleteError,
    fetchSystems,
    fetchSystem,
    getById,
    createMachine,
    deleteMachine
  }
})

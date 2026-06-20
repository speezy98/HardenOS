<script setup>
// Modale d'ajout d'une machine. BRIQUE 2 : affichage + logique de cascade
// (famille -> OS -> version) et validation basique des champs requis.
//
// Les familles / OS / versions viennent de l'API (GET /api/cis-rules/available),
// jamais codées en dur : si un référentiel est ajouté/retiré côté backend, le
// formulaire suit automatiquement.
//
// Le branchement réel de la soumission (POST /api/systems puis
// PUT /api/systems/<id>/credentials au bon format) est préparé ici via l'émission
// d'un payload structuré, mais sera finalisé et testé à la BRIQUE 3.
import { ref, reactive, computed, watch, onMounted } from 'vue'
import * as cisRulesApi from '@/api/cisRules.js'
import OsIcon from '@/components/system/OsIcon.vue'

defineProps({
  // Soumission en cours (création + credentials) : bloque le bouton.
  busy: { type: Boolean, default: false },
  // Erreur backend remontée par le parent/store (POST ou PUT credentials).
  serverError: { type: String, default: null }
})

const emit = defineEmits(['submit', 'cancel'])

// --- Chargement du catalogue auditable (familles/OS/versions) ---------------
const families = ref([]) // liste brute renvoyée par l'API
const catalogLoading = ref(false)
const catalogError = ref(null)

const loadCatalog = async () => {
  catalogLoading.value = true
  catalogError.value = null
  try {
    const { data } = await cisRulesApi.getAvailable()
    families.value = data
  } catch {
    catalogError.value = 'Impossible de charger les OS auditables (backend injoignable ?)'
    families.value = []
  } finally {
    catalogLoading.value = false
  }
}
onMounted(loadCatalog)

// --- Choix du type de système (première décision) ---------------------------
const osType = ref('') // 'linux' | 'windows'

// Familles Linux proposables (os_type=linux), dérivées du catalogue.
const linuxFamilies = computed(() =>
  families.value.filter((f) => f.os_type === 'linux')
)
// Le catalogue expose-t-il Windows ? (pour n'afficher le choix que si dispo)
const windowsAvailable = computed(() =>
  families.value.some((f) => f.os_type === 'windows')
)

// --- Cascade Linux : famille -> OS -> version -------------------------------
const form = reactive({
  family: '', // nom de famille (ex. "Debian")
  osName: '', // nom d'OS (ex. "Ubuntu")
  version: '', // version majeure (ex. "24.04")
  hostname: '',
  ip_address: '',
  ssh_user: '',
  ssh_password: '',
  use_sudo: false,
  // Windows
  win_hostname: '',
  win_ip_address: '',
  win_version: 'Windows Server 2022',
})

// Famille sélectionnée (objet complet du catalogue).
const selectedFamily = computed(
  () => linuxFamilies.value.find((f) => f.family === form.family) || null
)
// OS proposés pour la famille choisie.
const osOptions = computed(() => selectedFamily.value?.operating_systems || [])
// OS sélectionné (objet).
const selectedOs = computed(
  () => osOptions.value.find((o) => o.name === form.osName) || null
)
// Versions proposées pour l'OS choisi.
const versionOptions = computed(() => selectedOs.value?.versions || [])

// Référentiel CIS qui sera appliqué (info affichée à l'utilisateur).
const appliedRuleset = computed(() => selectedFamily.value?.ruleset || null)

// Réinitialisation en cascade : changer la famille remet à zéro OS + version ;
// changer l'OS remet à zéro la version. Évite les états incohérents.
watch(
  () => form.family,
  () => {
    form.osName = ''
    form.version = ''
  }
)
watch(
  () => form.osName,
  () => {
    form.version = ''
  }
)

// --- Validation basique des champs requis -----------------------------------
const localError = ref(null)

const linuxValid = computed(
  () =>
    form.family &&
    form.osName &&
    form.version &&
    form.hostname.trim() &&
    form.ip_address.trim() &&
    form.ssh_user.trim() &&
    form.ssh_password
)
const windowsValid = computed(() => form.win_ip_address.trim())

const canSubmit = computed(() =>
  osType.value === 'linux'
    ? linuxValid.value
    : osType.value === 'windows'
      ? windowsValid.value
      : false
)

// Construit le payload structuré consommé par le store (POST puis credentials).
// os_version est un libellé informatif (ex. "Ubuntu 24.04") ; c'est os_family
// qui choisit EXPLICITEMENT le référentiel côté backend (Debian/Ubuntu ->
// debian ; RHEL/AlmaLinux/Rocky -> rhel). os_family est persisté sur le système.
const buildPayload = () => {
  if (osType.value === 'linux') {
    return {
      os_type: 'linux',
      connection_mode: 'agentless',
      ruleset: appliedRuleset.value,
      system: {
        hostname: form.hostname.trim(),
        ip_address: form.ip_address.trim(),
        os_type: 'linux',
        os_family: selectedFamily.value?.os_family || null,
        os_version: `${form.osName} ${form.version}`.trim(),
        use_sudo: form.use_sudo
      },
      // Credentials à poser via PUT /api/systems/<id>/credentials (deux temps).
      credentials: {
        ssh_user: form.ssh_user.trim(),
        ssh_password: form.ssh_password
      }
    }
  }
  // Windows : pas de credentials SSH, l'agent_token est généré par le backend.
  return {
    os_type: 'windows',
    connection_mode: 'agent',
    system: {
      hostname: form.win_hostname.trim() || null,
      ip_address: form.win_ip_address.trim(),
      os_type: 'windows',
      os_family: 'windows',
      os_version: form.win_version,
      connection_mode: 'agent',
    }
  }
}

const handleSubmit = () => {
  localError.value = null
  if (!canSubmit.value) {
    localError.value = 'Veuillez renseigner tous les champs requis.'
    return
  }
  // BRIQUE 3 : le parent réalisera POST /api/systems + PUT .../credentials.
  emit('submit', buildPayload())
}
</script>

<template>
  <div
    class="modal-overlay"
    @click.self="emit('cancel')"
  >
    <div class="modal-card">
      <h2 class="modal-title">
        Ajouter une machine
      </h2>

      <!-- Chargement / erreur du catalogue -->
      <p
        v-if="catalogLoading"
        class="modal-sub"
      >
        Chargement des OS auditables…
      </p>
      <p
        v-else-if="catalogError"
        class="modal-error"
      >
        {{ catalogError }}
      </p>

      <form
        v-else
        class="modal-form"
        @submit.prevent="handleSubmit"
      >
        <!-- 1. Type de système -->
        <div class="field">
          <label>Type de système</label>
          <div class="type-toggle">
            <button
              type="button"
              class="type-btn"
              :class="{ active: osType === 'linux' }"
              @click="osType = 'linux'"
            >
              <OsIcon
                os-type="linux"
                :size="16"
              /> Linux
            </button>
            <button
              v-if="windowsAvailable"
              type="button"
              class="type-btn"
              :class="{ active: osType === 'windows' }"
              @click="osType = 'windows'"
            >
              <OsIcon
                os-type="windows"
                :size="16"
              /> Windows
            </button>
          </div>
        </div>

        <!-- 2. Branche LINUX : cascade + connexion SSH -->
        <template v-if="osType === 'linux'">
          <div class="cascade">
            <div class="field">
              <label for="family">Famille</label>
              <select
                id="family"
                v-model="form.family"
              >
                <option
                  value=""
                  disabled
                >
                  Choisir…
                </option>
                <option
                  v-for="f in linuxFamilies"
                  :key="f.family"
                  :value="f.family"
                >
                  {{ f.family }}
                </option>
              </select>
            </div>

            <div class="field">
              <label for="os">Système</label>
              <select
                id="os"
                v-model="form.osName"
                :disabled="!form.family"
              >
                <option
                  value=""
                  disabled
                >
                  Choisir…
                </option>
                <option
                  v-for="o in osOptions"
                  :key="o.name"
                  :value="o.name"
                >
                  {{ o.name }}
                </option>
              </select>
            </div>

            <div class="field">
              <label for="version">Version</label>
              <select
                id="version"
                v-model="form.version"
                :disabled="!form.osName"
              >
                <option
                  value=""
                  disabled
                >
                  Choisir…
                </option>
                <option
                  v-for="v in versionOptions"
                  :key="v"
                  :value="v"
                >
                  {{ v }}
                </option>
              </select>
            </div>
          </div>

          <p
            v-if="appliedRuleset"
            class="ruleset-note"
          >
            Référentiel CIS appliqué : <span class="mono">{{ appliedRuleset }}</span>
          </p>

          <div class="field">
            <label for="hostname">Hostname</label>
            <input
              id="hostname"
              v-model="form.hostname"
              type="text"
              placeholder="web01"
              autocomplete="off"
            >
          </div>
          <div class="field">
            <label for="ip">Adresse IP</label>
            <input
              id="ip"
              v-model="form.ip_address"
              type="text"
              placeholder="10.220.0.11"
              autocomplete="off"
            >
          </div>
          <div class="field">
            <label for="ssh-user">Utilisateur SSH</label>
            <input
              id="ssh-user"
              v-model="form.ssh_user"
              type="text"
              placeholder="ghost"
              autocomplete="off"
            >
          </div>
          <div class="field">
            <label for="ssh-pass">Mot de passe SSH</label>
            <input
              id="ssh-pass"
              v-model="form.ssh_password"
              type="password"
              autocomplete="new-password"
            >
          </div>
          <label class="checkbox">
            <input
              v-model="form.use_sudo"
              type="checkbox"
            >
            Utiliser sudo pour les commandes d'audit
          </label>
        </template>

        <!-- 3. Branche WINDOWS -->
        <template v-else-if="osType === 'windows'">
          <p class="win-note">
            L'agent HardenOS doit être démarré sur la machine cible avant l'ajout.
            Le token d'authentification sera généré et envoyé automatiquement à l'agent.
          </p>
          <div class="field">
            <label for="win-version">Version Windows</label>
            <select
              id="win-version"
              v-model="form.win_version"
            >
              <option>Windows Server 2022</option>
              <option>Windows Server 2019</option>
              <option>Windows Server 2016</option>
              <option>Windows 11</option>
              <option>Windows 10</option>
            </select>
          </div>
          <div class="field">
            <label for="win-hostname">Hostname <span class="opt">(optionnel)</span></label>
            <input
              id="win-hostname"
              v-model="form.win_hostname"
              type="text"
              autocomplete="off"
            >
          </div>
          <div class="field">
            <label for="win-ip">Adresse IP</label>
            <input
              id="win-ip"
              v-model="form.win_ip_address"
              type="text"
              placeholder="10.220.0.20"
              autocomplete="off"
            >
          </div>
        </template>

        <!-- Erreur : validation locale, puis erreur backend (POST / credentials) -->
        <p
          v-if="localError"
          class="modal-error"
        >
          {{ localError }}
        </p>
        <p
          v-else-if="serverError"
          class="modal-error"
        >
          {{ serverError }}
        </p>

        <div class="modal-actions">
          <button
            type="button"
            class="btn-ghost"
            :disabled="busy"
            @click="emit('cancel')"
          >
            Annuler
          </button>
          <button
            type="submit"
            class="btn-primary"
            :disabled="!canSubmit || busy"
          >
            {{ busy ? 'Ajout en cours…' : 'Ajouter la machine' }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>

<style scoped>
.modal-overlay {
  position: fixed;
  inset: 0;
  background-color: var(--overlay);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  padding: var(--space-6);
}

.modal-card {
  width: 100%;
  max-width: 480px;
  max-height: 90vh;
  overflow-y: auto;
  background-color: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: var(--space-8);
  box-shadow: var(--shadow-lg);
}

.modal-title {
  font-family: var(--font-mono);
  font-size: var(--text-lg);
  color: var(--text-primary);
  margin: 0 0 var(--space-5) 0;
}

.modal-sub {
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-muted);
  margin: 0 0 var(--space-4) 0;
}

.modal-form { display: flex; flex-direction: column; gap: var(--space-4); }

.field { display: flex; flex-direction: column; gap: var(--space-2); }

.field label {
  font-size: var(--text-xs);
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-secondary);
  font-family: var(--font-ui);
  font-weight: 500;
}

.field .opt {
  text-transform: none;
  letter-spacing: 0;
  color: var(--text-muted);
  font-weight: 400;
}

.field input,
.field select {
  background-color: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
}

.field input:focus,
.field select:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.field select:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Bascule Linux / Windows */
.type-toggle { display: flex; gap: var(--space-3); }

.type-btn {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  background-color: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  color: var(--text-secondary);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  cursor: pointer;
  transition: var(--transition-base);
}
.type-btn:hover { border-color: var(--accent); color: var(--text-primary); }
.type-btn.active {
  border-color: var(--accent);
  color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

/* Cascade sur 3 colonnes, empilée sur petit écran.
   align-items:end -> les selects s'alignent sur la même ligne visuelle même si
   un libellé venait à passer sur deux lignes à largeur réduite. */
.cascade {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: var(--space-3);
  align-items: end;
}
@media (max-width: 520px) { .cascade { grid-template-columns: 1fr; } }

.ruleset-note {
  font-family: var(--font-ui);
  font-size: var(--text-xs);
  color: var(--text-muted);
  margin: calc(-1 * var(--space-2)) 0 0 0;
}

.win-note {
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-muted);
  line-height: 1.5;
  background-color: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-4);
  margin: 0;
}

.mono { font-family: var(--font-mono); color: var(--text-secondary); }

.checkbox {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  color: var(--text-secondary);
  cursor: pointer;
}

.modal-error {
  color: var(--status-fail);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  margin: 0;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  margin-top: var(--space-2);
}

.btn-ghost {
  background-color: transparent;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-5);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  cursor: pointer;
  transition: var(--transition-base);
}
.btn-ghost:hover { border-color: var(--accent); color: var(--accent); }

.btn-primary {
  background-color: var(--accent);
  color: var(--bg-base);
  border: none;
  border-radius: var(--radius-md);
  padding: var(--space-3) var(--space-5);
  font-family: var(--font-ui);
  font-size: var(--text-sm);
  font-weight: 600;
  cursor: pointer;
  transition: var(--transition-base);
}
.btn-primary:hover:not(:disabled) { background-color: var(--accent-hover); }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
</style>

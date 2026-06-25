"""Sauvegarde de la politique de sécurité locale et du registre AVANT une
remédiation — permet un rollback global des zones sauvegardées (pas un
réglage ciblé : limite assumée) si une remédiation pose problème.

secedit est la seule sauvegarde "pleine ruche" (toute la politique de
sécurité locale). Le registre, lui, n'est PAS exporté/ré-importé en entier :
HKLM\\SOFTWARE et HKLM\\SYSTEM contiennent tous deux des clés protégées par
TrustedInstaller, jamais ré-importables même sous SYSTEM (constaté en
conditions réelles le 10/07 — `reg import` échoue avec "Error accessing the
registry" sur la ruche complète, sous Administrateur comme sous SYSTEM).
On se limite donc aux sous-clés que les contrôles CIS de ce référentiel
modifient réellement (cf. _REGISTRY_KEYS) — périmètre réduit mais couverture
inchangée pour ce qui compte pour le durcissement.
"""
import json
import logging
import os
import subprocess

log = logging.getLogger("hardenos_agent")

_BACKUP_DIR = r"C:\HardenOS\backup"

# reg export peut prendre plus que les 30s habituelles d'une commande d'audit
# (ruche potentiellement volumineuse) — timeout dédié, plus généreux, plutôt
# que de réutiliser collector.run_powershell().
_BACKUP_TIMEOUT = 180

# Sous-clés de registre couvrant l'ensemble des contrôles CIS de ce
# référentiel qui écrivent dans HKLM\SOFTWARE ou HKLM\SYSTEM (déterminé en
# analysant les scripts Set-ItemProperty/New-ItemProperty du YAML le 10/07).
# Toutes optionnelles : une clé absente sur une machine donnée (ex. NTDS
# n'existe que sur un contrôleur de domaine) n'est pas une erreur.
_REGISTRY_KEYS = {
    "hklm_software_policies": r"HKLM\SOFTWARE\Policies",
    "hklm_software_cv_policies": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    "hklm_system_control_deviceguard": r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
    # PAS "Control\Lsa" (bare) : reg export est récursif et embarque les
    # sous-clés Data/GBG/JD/Skew1 (secrets LSA), protégées même sous SYSTEM
    # — constaté en conditions réelles le 10/07 (reg import échoue dessus).
    # Ses 2 sous-clés utilisées par le durcissement CIS ne sont PAS protégées :
    "hklm_system_control_lsa_msv1_0": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
    "hklm_system_control_lsa_fips": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy",
    "hklm_system_services_ldap": r"HKLM\SYSTEM\CurrentControlSet\Services\LDAP",
    "hklm_system_services_lanmanserver": r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    "hklm_system_services_lanmanworkstation": r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
    "hklm_system_services_ntds": r"HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
    "hklm_system_services_netlogon": r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
    "hklm_system_services_tcpip6": r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
    "hklm_system_services_tcpip": r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
}

# Valeurs DWORD posées directement sur Control\Lsa (pas dans une sous-clé) par
# des contrôles CIS. On ne peut pas sauvegarder "la clé Lsa" (cf. ci-dessus,
# ses sous-clés protégées la rendent non ré-important en entier) : on capture
# donc individuellement CES valeurs précises et on reconstruit un .reg minimal
# ne contenant qu'elles — reg import de ce fichier ne touche alors jamais aux
# sous-clés protégées, seulement aux valeurs listées ici.
_REGISTRY_VALUE_GROUPS = {
    "hklm_system_lsa_values": (
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        ["RestrictAnonymousSAM", "LimitBlankPasswordUse", "RestrictAnonymous", "LmCompatibilityLevel", "NoLMHash"],
    ),
}

# Valeurs de registre dont la valeur par défaut est ABSENTE (« sortie vide ») et
# que des remédiations CRÉENT. Problème : la sauvegarde peut avoir capturé un
# état déjà durci (cycles de remédiation/rollback répétés), donc `reg import` les
# RESTAURE au lieu de les enlever — le contrôle reste conforme après rollback.
# On les supprime donc EXPLICITEMENT au rollback pour qu'ils reviennent à leur
# état d'origine « sortie vide » (= non conforme), indépendamment de la
# sauvegarde. (clé, valeur). Uniquement des réglages que Windows ne pose pas par
# défaut : les supprimer = revenir au défaut.
_HARDENING_VALUES_TO_CLEAR = [
    (r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DisableIPSourceRouting"),        # 18.5.1
    (r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisableIPSourceRouting"),       # 18.6.19.2.1
    (r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity"),   # 18.9.5.1
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"),   # 18.x.autorun
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer", "NoAutoplayfornonVolume"),              # 18.x.autorun2
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata", "PreventDeviceMetadataFromNetwork"),  # 18.9.7.2
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security", "MaxSize"),                    # 18.10.x.sec
    (r"HKLM\SOFTWARE\Policies\Microsoft\Cryptography", "ForceKeyProtection"),                      # 2.3.14.1
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"),  # 18.x.powershell.log
]

# Services désactivés par des contrôles CIS (Set-Service -StartupType).
_SERVICE_NAMES = [
    "RemoteRegistry", "RemoteAccess", "BTAGService", "bthserv", "MapsBroker",
    "lfsvc", "simptcp", "SNMP", "WMSvc", "sacsvr", "XboxGipSvc", "Spooler",
]

# Profils pare-feu modifiés par des contrôles CIS (Set-NetFirewallProfile).
_FIREWALL_PROFILES = ["Domain", "Private", "Public"]

# Sous-catégories de stratégie d'audit modifiées par des contrôles CIS
# (auditpol /set). Non couvertes par secedit /export (constaté le score qui
# ne redescend pas complètement après un rollback sans cette catégorie).
_AUDITPOL_SUBCATEGORIES = [
    "Logon", "Credential Validation", "Process Creation", "User Account Management",
    "Audit Policy Change", "Sensitive Privilege Use", "Security Group Management",
    "Account Lockout", "Other Logon/Logoff Events", "Authentication Policy Change",
    "Security State Change", "System Integrity", "Removable Storage",
    "Other Policy Change Events",
]


def _run_command(command: str) -> tuple[str, str | None]:
    """Exécute une commande via PowerShell avec le timeout de sauvegarde
    (plus long que celui des commandes d'audit)."""
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_BACKUP_TIMEOUT,
        )
        output = result.stdout.strip()
        if result.returncode != 0 and result.stderr.strip():
            return output, result.stderr.strip()
        return output, None
    except subprocess.TimeoutExpired:
        return "", f"Timeout après {_BACKUP_TIMEOUT}s"
    except FileNotFoundError:
        return "", "PowerShell introuvable sur ce système"
    except Exception as exc:
        return "", str(exc)


def _export_registry_values(key_path: str, names: list[str], out_file: str) -> str | None:
    """Capture individuellement les valeurs `names` de `key_path` (pas la clé
    entière) et écrit un .reg minimal ne contenant que celles-ci — voir
    _REGISTRY_VALUE_GROUPS. Retourne un message d'erreur ou None."""
    ps_path = "HKLM:" + key_path[len("HKLM"):]
    reg_header_key = key_path.replace("HKLM\\", "HKEY_LOCAL_MACHINE\\", 1)
    names_ps = ",".join("'" + n + "'" for n in names)
    script = (
        "$names = @(" + names_ps + "); "
        "$lines = @('Windows Registry Editor Version 5.00', '', '[" + reg_header_key + "]'); "
        "foreach ($n in $names) { "
        "$v = (Get-ItemProperty -Path '" + ps_path + "' -Name $n -ErrorAction SilentlyContinue).$n; "
        "if ($null -ne $v) { $lines += ('\"{0}\"=dword:{1:x8}' -f $n, $v) } "
        "}; "
        "Set-Content -Path '" + out_file + "' -Value $lines -Encoding ASCII"
    )
    _, error = _run_command(script)
    return error


def _export_services(out_file: str) -> str | None:
    """Capture le StartupType actuel des services listés dans _SERVICE_NAMES
    (JSON). N'utilise ni le registre ni secedit — API Get-Service/Set-Service,
    aucune clé protégée en jeu ici."""
    names_ps = ",".join("'" + n + "'" for n in _SERVICE_NAMES)
    script = (
        "$names = @(" + names_ps + "); $result = @{}; "
        "foreach ($n in $names) { "
        "$s = Get-Service -Name $n -ErrorAction SilentlyContinue; "
        "if ($s) { $result[$n] = $s.StartType.ToString() } "
        "}; "
        "$result | ConvertTo-Json -Compress | Set-Content -Path '" + out_file + "' -Encoding ASCII"
    )
    _, error = _run_command(script)
    return error


def _restore_services(path: str) -> str | None:
    script = (
        "$json = Get-Content -Path '" + path + "' -Raw | ConvertFrom-Json; "
        "$json.PSObject.Properties | ForEach-Object { "
        "Set-Service -Name $_.Name -StartupType $_.Value -ErrorAction Stop "
        "}"
    )
    _, error = _run_command(script)
    return error


def _export_firewall(out_file: str) -> str | None:
    """Capture Enabled/DefaultInboundAction des profils listés dans
    _FIREWALL_PROFILES (JSON). API Get-NetFirewallProfile/Set-NetFirewallProfile."""
    profiles_ps = ",".join("'" + p + "'" for p in _FIREWALL_PROFILES)
    script = (
        "$profiles = @(" + profiles_ps + "); $result = @{}; "
        "foreach ($p in $profiles) { "
        "$f = Get-NetFirewallProfile -Name $p -ErrorAction SilentlyContinue; "
        "if ($f) { $result[$p] = @{ Enabled = [bool]$f.Enabled; DefaultInboundAction = $f.DefaultInboundAction.ToString() } } "
        "}; "
        "$result | ConvertTo-Json -Compress | Set-Content -Path '" + out_file + "' -Encoding ASCII"
    )
    _, error = _run_command(script)
    return error


def _restore_firewall(path: str) -> str | None:
    script = (
        "$json = Get-Content -Path '" + path + "' -Raw | ConvertFrom-Json; "
        "foreach ($p in $json.PSObject.Properties) { "
        # -Enabled attend un GpoBoolean (accepté sous forme de chaîne
        # "True"/"False") : un booléen .NET brut issu du JSON désérialisé
        # échoue la conversion de type (constaté en conditions réelles le 10/07).
        "Set-NetFirewallProfile -Profile $p.Name -Enabled $p.Value.Enabled.ToString() "
        "-DefaultInboundAction $p.Value.DefaultInboundAction -ErrorAction Stop "
        "}"
    )
    _, error = _run_command(script)
    return error


def _export_defender(out_file: str) -> str | None:
    """Capture les 3 préférences Defender touchées par des contrôles CIS
    (JSON). API Get-MpPreference/Set-MpPreference."""
    script = (
        "$mp = Get-MpPreference; "
        "$result = @{ DisableRealtimeMonitoring = [bool]$mp.DisableRealtimeMonitoring; "
        "MAPSReporting = $mp.MAPSReporting.ToString(); PUAProtection = [int]$mp.PUAProtection }; "
        "$result | ConvertTo-Json -Compress | Set-Content -Path '" + out_file + "' -Encoding ASCII"
    )
    _, error = _run_command(script)
    return error


def _restore_defender(path: str) -> str | None:
    script = (
        "$json = Get-Content -Path '" + path + "' -Raw | ConvertFrom-Json; "
        "Set-MpPreference -DisableRealtimeMonitoring $json.DisableRealtimeMonitoring "
        "-MAPSReporting $json.MAPSReporting -PUAProtection $json.PUAProtection -ErrorAction Stop"
    )
    _, error = _run_command(script)
    return error


def _export_auditpol(out_file: str) -> str | None:
    """Sauvegarde COMPLÈTE de la stratégie d'audit via le mécanisme NATIF
    `auditpol /backup` (fichier CSV de TOUTES les sous-catégories, avec leur
    réglage exact).

    Remplace l'ancienne capture ciblée `auditpol /get` sous-catégorie par
    sous-catégorie : celle-ci parsait la sortie CSV par position et pouvait
    capturer une valeur vide/erronée → au rollback, `auditpol /set
    /success:disable /failure:disable` remettait TOUT en « No Auditing », même
    les sous-catégories qui étaient activées avant. `/backup` + `/restore`
    restaure l'état à l'identique, sans parsing ni dépendance à la localisation."""
    _, error = _run_command(f'auditpol /backup /file:"{out_file}"')
    return error


def _restore_auditpol(path: str) -> str | None:
    """Restaure la stratégie d'audit COMPLÈTE via `auditpol /restore` : remet
    TOUTES les sous-catégories exactement à l'état de la sauvegarde (y compris
    celles qui étaient activées)."""
    _, error = _run_command(f'auditpol /restore /file:"{path}"')
    return error


def _restore_registry_key(key: str, reg_file: str) -> str | None:
    """Restaure une clé COMPLÈTE à l'état EXACT de la sauvegarde : supprime
    d'abord la clé actuelle (retire donc TOUTE valeur/sous-clé créée depuis la
    sauvegarde — ce que `reg import` seul ne fait jamais, il ne fait que
    fusionner), puis ré-importe le .reg.

    Garde anti-perte de données : on ne supprime QUE si le .reg contient bien un
    bloc de clé à réimporter ([HKEY...]) ; sinon (export vide/malformé) on se
    contente d'importer. `reg delete /f` sur une clé déjà absente est toléré."""
    has_key_block = False
    try:
        with open(reg_file, "r", encoding="utf-8", errors="replace") as f:
            has_key_block = "[HKEY" in f.read()
    except OSError:
        has_key_block = False
    if has_key_block:
        _run_command(f'reg delete "{key}" /f')  # tolère l'absence
    return _run_command(f'reg import "{reg_file}"')[1]


def _restore_registry_value_group(key_path: str, names: list[str], reg_file: str) -> str | None:
    """Restaure un groupe de valeurs CIBLÉES (DWORD sur Control\\Lsa, dont la clé
    ne peut PAS être supprimée — sous-clés protégées) : retire d'abord chaque
    valeur nommée (donc celles créées depuis la sauvegarde), puis ré-importe le
    .reg (qui ne contient que les valeurs présentes au moment de la sauvegarde)."""
    for n in names:
        _run_command(f'reg delete "{key_path}" /v "{n}" /f')  # tolère l'absence
    return _run_command(f'reg import "{reg_file}"')[1]


def _registry_key_exists(key: str) -> bool:
    """True si la clé de registre existe (Test-Path : booléen fiable et non
    localisé, contrairement au parsing d'un message d'erreur reg export)."""
    ps_key = "HKLM:" + key[len("HKLM"):]
    out, _ = _run_command(f"if (Test-Path '{ps_key}') {{ 'EXISTS' }} else {{ 'ABSENT' }}")
    return out.strip() == "EXISTS"


def _delete_key_if_present(key: str) -> str | None:
    """Supprime une clé qui était ABSENTE à la sauvegarde mais qu'une remédiation
    a pu créer (ex. DeviceGuard, NTDS\\Parameters). `reg import` ne la retirerait
    jamais (rien à réimporter). Best-effort : ne fait JAMAIS échouer le rollback."""
    ps_key = "HKLM:" + key[len("HKLM"):]
    _run_command(f"if (Test-Path '{ps_key}') {{ reg delete '{key}' /f | Out-Null }}")
    return None


def _clear_created_hardening_values() -> str | None:
    """Supprime EXPLICITEMENT les valeurs de _HARDENING_VALUES_TO_CLEAR pour
    qu'elles reviennent à « sortie vide » (état par défaut) après un rollback,
    même si la sauvegarde les avait capturées (donc réimportées). C'est la seule
    façon fiable de faire revenir ces contrôles en non conforme quand la
    sauvegarde est « sale ». `reg delete /v /f` tolère une valeur déjà absente.
    Best-effort : ne fait JAMAIS échouer le rollback (retourne toujours None)."""
    for key, value in _HARDENING_VALUES_TO_CLEAR:
        _run_command(f'reg delete "{key}" /v "{value}" /f')
    return None


# Groupes d'état hors registre (services, pare-feu, Defender, auditpol) :
# chaque entrée est (export_fn, restore_fn), toutes deux prenant un chemin de
# fichier JSON. Même statut qu'un groupe de registre : optionnel, jamais
# bloquant.
_STATE_GROUPS = {
    "services": (_export_services, _restore_services),
    "firewall": (_export_firewall, _restore_firewall),
    "defender": (_export_defender, _restore_defender),
    "auditpol": (_export_auditpol, _restore_auditpol),
}


def create_backup(snapshot_name: str) -> dict:
    """Exporte secedit (obligatoire) + les sous-clés de registre listées dans
    _REGISTRY_KEYS (optionnelles) vers des fichiers horodatés par
    `snapshot_name` (fourni par le backend).

    Retourne { "status": "ok", "paths": {...} } ou { "status": "error", "error": ... }.
    Seul secedit peut faire échouer toute la sauvegarde ; une clé de registre
    absente/inaccessible est simplement omise de `paths` (log en warning).
    """
    try:
        os.makedirs(_BACKUP_DIR, exist_ok=True)
    except OSError as exc:
        return {"status": "error", "error": f"Impossible de créer {_BACKUP_DIR} : {exc}"}

    secpol_path = os.path.join(_BACKUP_DIR, f"secpol_{snapshot_name}.inf")
    output, error = _run_command(f'secedit /export /cfg "{secpol_path}"')
    if error:
        log.error("Échec de la sauvegarde (secpol) : %s", error)
        return {"status": "error", "error": f"Échec export secpol : {error}"}
    if not os.path.isfile(secpol_path):
        log.error("Fichier de sauvegarde absent après export (secpol) : %s", secpol_path)
        return {"status": "error", "error": "Fichier de sauvegarde introuvable après export secpol."}

    paths = {"secpol": secpol_path}

    # Clés listées mais ABSENTES au moment de la sauvegarde : une remédiation qui
    # les crée ne serait pas retirée au rollback (aucun .reg à réimporter). On les
    # note pour les supprimer à la restauration (ex. DeviceGuard, NTDS\Parameters).
    absent_keys = []
    for label, key in _REGISTRY_KEYS.items():
        path = os.path.join(_BACKUP_DIR, f"{label}_{snapshot_name}.reg")
        output, error = _run_command(f'reg export "{key}" "{path}" /y')
        if error:
            log.warning("Sauvegarde (%s) ignorée — clé absente ou inaccessible : %s", label, error)
            if not _registry_key_exists(key):  # absente (≠ inaccessible/protégée)
                absent_keys.append(key)
            continue
        if os.path.isfile(path):
            paths[label] = path

    if absent_keys:
        absent_path = os.path.join(_BACKUP_DIR, f"absentkeys_{snapshot_name}.json")
        try:
            with open(absent_path, "w", encoding="ascii") as f:
                json.dump(absent_keys, f)
            paths["_absent_registry_keys"] = absent_path
        except OSError as exc:
            log.warning("Impossible d'écrire la liste des clés absentes : %s", exc)

    for label, (key_path, names) in _REGISTRY_VALUE_GROUPS.items():
        path = os.path.join(_BACKUP_DIR, f"{label}_{snapshot_name}.reg")
        error = _export_registry_values(key_path, names, path)
        if error:
            log.warning("Sauvegarde (%s) ignorée — %s", label, error)
            continue
        if os.path.isfile(path):
            paths[label] = path

    for label, (export_fn, _restore_fn) in _STATE_GROUPS.items():
        path = os.path.join(_BACKUP_DIR, f"{label}_{snapshot_name}.json")
        error = export_fn(path)
        if error:
            log.warning("Sauvegarde (%s) ignorée — %s", label, error)
            continue
        if os.path.isfile(path):
            paths[label] = path

    log.info("Sauvegarde créée avec succès (%s) : %s", snapshot_name, paths)
    return {"status": "ok", "paths": paths}


def restore_backup(paths: dict) -> dict:
    """Réimporte une sauvegarde (secedit + registre) — rollback GLOBAL des
    zones sauvegardées (pas un réglage ciblé : limite assumée, cf. brief
    initial).

    `paths` : {"secpol": "...", <label de _REGISTRY_KEYS ou _REGISTRY_VALUE_GROUPS>: "...",
    <label de _STATE_GROUPS>: "...", ...} (telles que renvoyées par create_backup
    / stockées dans Snapshot.notes). Seul secpol est requis ; tout le reste
    est optionnel (absent si la machine n'avait pas cette donnée au moment de
    la sauvegarde — ex. NTDS\\Parameters sur un serveur qui n'est pas
    contrôleur de domaine).

    Retourne {"status": "ok"} ou {"status": "error", "error": ...}. S'arrête
    au premier échec — une restauration partielle serait pire que pas de
    restauration du tout (état incohérent entre les différentes zones).
    """
    log.info("restore_backup() appelée avec paths=%s", paths)

    secpol_path = paths.get("secpol")
    if not secpol_path:
        return {"status": "error", "error": "Chemins de sauvegarde incomplets (secpol requis)."}

    # Clés complètes et groupes de valeurs se restaurent DIFFÉREMMENT : une clé
    # complète est supprimée puis réimportée (retire ce qui a été créé depuis) ;
    # un groupe de valeurs Lsa ne peut pas être supprimé (sous-clés protégées) —
    # on retire seulement ses valeurs. `reg import` seul ne retirerait jamais une
    # valeur/clé créée par une remédiation (il ne fait que fusionner).
    full_key_paths = {label: paths[label] for label in _REGISTRY_KEYS if paths.get(label)}
    value_group_paths = {label: paths[label] for label in _REGISTRY_VALUE_GROUPS if paths.get(label)}
    state_paths = {label: paths[label] for label in _STATE_GROUPS if paths.get(label)}

    for path in [secpol_path, *full_key_paths.values(), *value_group_paths.values(), *state_paths.values()]:
        if not os.path.isfile(path):
            return {"status": "error", "error": f"Fichier de sauvegarde introuvable : {path}"}

    log.info("Fichiers de sauvegarde vérifiés — début de la restauration.")

    restore_db = os.path.join(_BACKUP_DIR, "restore_tmp.sdb")
    # Chaque étape est (label, fonction sans argument -> message d'erreur ou None) :
    # uniformise l'exécution des commandes reg/secedit et des restaurations
    # d'état (services/pare-feu/Defender), qui n'utilisent pas les mêmes
    # commandes sous-jacentes.
    restores: list[tuple[str, "callable"]] = [
        # /quiet : sans ça, /overwrite déclenche une confirmation interactive
        # [O/N] sur stdin — jamais fournie par subprocess.run(), la commande
        # reste alors bloquée indéfiniment (cause du blocage diagnostiqué
        # manuellement le 10/07).
        ("secpol", lambda: _run_command(
            f'secedit /configure /db "{restore_db}" /cfg "{secpol_path}" /overwrite /quiet'
        )[1]),
    ]
    # Clé complète : suppression + réimport (retire ce qui a été créé depuis).
    for label, path in full_key_paths.items():
        key = _REGISTRY_KEYS[label]
        restores.append((label, lambda p=path, k=key: _restore_registry_key(k, p)))
    # Groupe de valeurs ciblées : suppression des valeurs nommées + réimport.
    for label, path in value_group_paths.items():
        key_path, names = _REGISTRY_VALUE_GROUPS[label]
        restores.append(
            (label, lambda p=path, kp=key_path, ns=names: _restore_registry_value_group(kp, ns, p))
        )
    for label, path in state_paths.items():
        _, restore_fn = _STATE_GROUPS[label]
        restores.append((label, lambda p=path, fn=restore_fn: fn(p)))

    # Clés absentes à la sauvegarde mais potentiellement créées par la remédiation
    # (ex. DeviceGuard, NTDS\Parameters) : suppression best-effort, jamais bloquante.
    absent_path = paths.get("_absent_registry_keys")
    if absent_path and os.path.isfile(absent_path):
        try:
            with open(absent_path, "r", encoding="ascii") as f:
                absent_keys = json.load(f)
        except (OSError, ValueError):
            absent_keys = []
        for key in absent_keys:
            restores.append((f"suppr-clé-créée:{key}", lambda k=key: _delete_key_if_present(k)))

    # EN DERNIER : retirer explicitement les valeurs de durcissement dont l'état
    # d'origine est « sortie vide » (indépendamment de la sauvegarde, qui peut
    # être « sale »). Prime sur les reg import précédents.
    restores.append(("valeurs-durcissement-créées", lambda: _clear_created_hardening_values()))

    for label, run in restores:
        log.info("Restauration (%s) — lancement.", label)
        error = run()
        log.info("Restauration (%s) — commande revenue (error=%s).", label, error)
        if error:
            log.error("Échec de la restauration (%s) : %s", label, error)
            return {"status": "error", "error": f"Échec restauration {label} : {error}"}

    log.info("Restauration effectuée avec succès depuis : %s", paths)
    return {"status": "ok"}

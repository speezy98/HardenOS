"""Rollback INDIVIDUEL d'une remédiation unitaire — couvre désormais toutes
les familles de contrôles automatisables sauf secedit (politique de sécurité
locale, pas de mécanisme de lecture/écriture ciblée fiable par réglage) et
Update-MpSignature (1 contrôle, pas un réglage à proprement parler — mise à
jour de signatures, rien à "annuler") :
- registre (Set-ItemProperty / New-ItemProperty, 43/87)
- `net accounts` (politique mots de passe/verrouillage, 6/87)
- services (Set-Service, 12/87)
- auditpol (stratégie d'audit, 14/87)
- pare-feu (Set-NetFirewallProfile, 5/87)
- Defender (Set-MpPreference, 4/87)
- utilisateur local (Disable-LocalUser, 1/87)
- fonctionnalité Windows optionnelle (Disable-WindowsOptionalFeature, 1/87)
Pour secedit/Update-MpSignature, le rollback global (backup.py) reste la
seule option.

auditpol : la valeur capturée ("Success and Failure" / "No Auditing" / ...)
est comparée à du texte anglais, donc requiert la machine en langue
d'affichage anglaise (déjà nécessaire pour le rollback global).
"""
import logging
import re

import collector

log = logging.getLogger("hardenos_agent")

# Le script reçu ici est le script UNITAIRE complet, avec son wrapper
# try/catch (cf. agents.py::remediate_control) — on cherche la commande
# n'importe où dedans plutôt que d'ancrer en début de chaîne. Un script
# groupé (bulk) contient PLUSIEURS occurrences d'un même motif :
# capture_before_state() retourne alors None (pas d'ambiguïté possible sur
# le contrôle visé).
_REGISTRY_SET_RE = re.compile(
    r"(?:Set-ItemProperty|New-ItemProperty)\s+'([^']+)'\s+-Name\s+(\S+)\s+-Value\s+(\S+)",
    re.IGNORECASE,
)

_NET_ACCOUNTS_RE = re.compile(r"net\s+accounts\s+/(\w+):(\S+)", re.IGNORECASE)

_SET_SERVICE_RE = re.compile(r"Set-Service\s+-Name\s+'([^']+)'\s+-StartupType\s+(\S+)", re.IGNORECASE)

_AUDITPOL_SET_RE = re.compile(r'auditpol\s+/set\s+/subcategory:"([^"]+)"', re.IGNORECASE)

_FIREWALL_SET_RE = re.compile(
    r"Set-NetFirewallProfile\s+-Profile\s+(\w+)\s+-(Enabled|DefaultInboundAction)\s+(\S+)",
    re.IGNORECASE,
)

_DEFENDER_SET_RE = re.compile(
    r"Set-MpPreference\s+-(DisableRealtimeMonitoring|MAPSReporting|PUAProtection)\s+(\S+)",
    re.IGNORECASE,
)

_DISABLE_LOCALUSER_RE = re.compile(r"Disable-LocalUser\s+-Name\s+'([^']+)'", re.IGNORECASE)

_DISABLE_FEATURE_RE = re.compile(
    r"Disable-WindowsOptionalFeature\s+-Online\s+-FeatureName\s+(\S+)", re.IGNORECASE
)

# Option `net accounts /xxx:` -> libellé EXACT de la ligne correspondante
# dans le rapport `net accounts` (sortie en anglais requise — cf. le souci
# de localisation déjà rencontré avec auditpol). Uniquement les 6 options
# utilisées par ce référentiel.
_NET_ACCOUNTS_LABELS = {
    "uniquepw": "Length of password history maintained",
    "minpwlen": "Minimum password length",
    "maxpwage": "Maximum password age (days)",
    "minpwage": "Minimum password age (days)",
    "lockoutthreshold": "Lockout threshold",
    "lockoutduration": "Lockout duration (minutes)",
    "lockoutwindow": "Lockout observation window (minutes)",
}


def _capture_registry(script: str) -> dict | None:
    matches = _REGISTRY_SET_RE.findall(script)
    if len(matches) != 1:
        return None
    path, name, _value = matches[0]

    command = (
        f"$v = Get-ItemProperty -Path '{path}' -Name '{name}' -ErrorAction SilentlyContinue; "
        f"if ($null -eq $v) {{ 'HARDENOS_ABSENT' }} else {{ $v.'{name}' }}"
    )
    actual, error = collector.run_powershell(command)
    if error:
        log.warning("Capture avant rémédiation impossible pour %s\\%s : %s", path, name, error)
        return None
    actual = actual.strip()
    return {
        "kind": "registry",
        "path": path, "name": name,
        "existed": actual != "HARDENOS_ABSENT", "old_value": actual,
    }


def _capture_net_accounts(script: str) -> dict | None:
    matches = _NET_ACCOUNTS_RE.findall(script)
    if len(matches) != 1:
        return None
    option, _value = matches[0]
    label = _NET_ACCOUNTS_LABELS.get(option.lower())
    if not label:
        return None  # option hors des 6 connues — pas de rollback individuel

    # -SimpleMatch : certains libellés contiennent des parenthèses (motif
    # regex sinon), ex. "Maximum password age (days)".
    command = (
        f"$l = net accounts | Select-String -SimpleMatch '{label}:'; "
        "if ($l) { ($l -split ':', 2)[1].Trim() } else { 'HARDENOS_ABSENT' }"
    )
    actual, error = collector.run_powershell(command)
    if error:
        log.warning("Capture avant rémédiation impossible pour net accounts /%s : %s", option, error)
        return None
    actual = actual.strip()
    if actual == "HARDENOS_ABSENT":
        log.warning("Ligne « %s » introuvable dans la sortie net accounts (locale non anglaise ?).", label)
        return None
    # Windows affiche "Never" pour threshold/maxpwage désactivés ; la
    # commande /set correspondante attend 0 dans ce cas (convention native).
    old_value = "0" if actual.lower() == "never" else actual
    return {"kind": "net_accounts", "option": option.lower(), "old_value": old_value}


def _capture_service(script: str) -> dict | None:
    matches = _SET_SERVICE_RE.findall(script)
    if len(matches) != 1:
        return None
    name, _new_type = matches[0]

    command = (
        f"$s = Get-Service -Name '{name}' -ErrorAction SilentlyContinue; "
        "if ($null -eq $s) { 'HARDENOS_ABSENT' } else { $s.StartType.ToString() + '|' + $s.Status.ToString() }"
    )
    actual, error = collector.run_powershell(command)
    if error:
        log.warning("Capture avant rémédiation impossible pour le service %s : %s", name, error)
        return None
    actual = actual.strip()
    if actual == "HARDENOS_ABSENT":
        log.warning("Service %s introuvable — pas de rollback individuel.", name)
        return None
    old_type, _, old_status = actual.partition("|")
    return {"kind": "service", "name": name, "old_type": old_type, "old_status": old_status}


def _capture_auditpol(script: str) -> dict | None:
    matches = _AUDITPOL_SET_RE.findall(script)
    if len(matches) != 1:
        return None
    subcategory = matches[0]

    # Guillemets simples (pas doubles) + découpage texte, comme
    # _capture_net_accounts — PAS de CSV/index positionnel comme avant :
    # capture erronée constatée en conditions réelles le 11/07 avec l'ancien
    # code (CSV + guillemets doubles imbriqués dans -Command), reproductible
    # sans lien avec la localisation ni un rollback global/VMware.
    command = (
        "$l = auditpol /get /subcategory:'" + subcategory + "' | Select-String -SimpleMatch '" + subcategory + "'; "
        "if ($l) { ($l.ToString() -split '\\s{2,}')[-1].Trim() } else { 'HARDENOS_ABSENT' }"
    )
    actual, error = collector.run_powershell(command)
    if error:
        log.warning("Capture avant rémédiation impossible pour auditpol/%s : %s", subcategory, error)
        return None
    actual = actual.strip()
    if actual == "HARDENOS_ABSENT":
        log.warning("Sous-catégorie auditpol « %s » introuvable.", subcategory)
        return None
    return {"kind": "auditpol", "subcategory": subcategory, "old_setting": actual}


def _capture_firewall(script: str) -> dict | None:
    matches = _FIREWALL_SET_RE.findall(script)
    if len(matches) != 1:
        return None
    profile, prop, _new_value = matches[0]

    command = (
        f"$f = Get-NetFirewallProfile -Name '{profile}' -ErrorAction SilentlyContinue; "
        f"if ($null -eq $f) {{ 'HARDENOS_ABSENT' }} else {{ $f.{prop}.ToString() }}"
    )
    actual, error = collector.run_powershell(command)
    if error:
        log.warning("Capture avant rémédiation impossible pour le profil pare-feu %s : %s", profile, error)
        return None
    actual = actual.strip()
    if actual == "HARDENOS_ABSENT":
        log.warning("Profil pare-feu %s introuvable.", profile)
        return None
    return {"kind": "firewall", "profile": profile, "property": prop, "old_value": actual}


def _capture_defender(script: str) -> dict | None:
    matches = _DEFENDER_SET_RE.findall(script)
    if len(matches) != 1:
        return None
    prop, _new_value = matches[0]

    # PUAProtection : caster en entier plutôt que .ToString() (même choix
    # que backup.py::_export_defender — plus fiable pour cette propriété).
    command = (
        f"[int](Get-MpPreference).{prop}" if prop.lower() == "puaprotection"
        else f"(Get-MpPreference).{prop}.ToString()"
    )
    actual, error = collector.run_powershell(command)
    if error:
        log.warning("Capture avant rémédiation impossible pour Defender %s : %s", prop, error)
        return None
    actual = actual.strip()
    if not actual:
        return None
    return {"kind": "defender", "property": prop, "old_value": actual}


def _capture_local_user(script: str) -> dict | None:
    matches = _DISABLE_LOCALUSER_RE.findall(script)
    if len(matches) != 1:
        return None
    name = matches[0]

    command = (
        "$u = Get-LocalUser -Name '" + name + "' -ErrorAction SilentlyContinue; "
        "if ($null -eq $u) { 'HARDENOS_ABSENT' } else { $u.Enabled.ToString() }"
    )
    actual, error = collector.run_powershell(command)
    if error:
        log.warning("Capture avant rémédiation impossible pour l'utilisateur local %s : %s", name, error)
        return None
    actual = actual.strip()
    if actual == "HARDENOS_ABSENT":
        log.warning("Utilisateur local %s introuvable — pas de rollback individuel.", name)
        return None
    return {"kind": "local_user", "name": name, "old_enabled": actual}


def _capture_optional_feature(script: str) -> dict | None:
    matches = _DISABLE_FEATURE_RE.findall(script)
    if len(matches) != 1:
        return None
    feature = matches[0]

    command = (
        "$f = Get-WindowsOptionalFeature -Online -FeatureName '" + feature + "' -ErrorAction SilentlyContinue; "
        "if ($null -eq $f) { 'HARDENOS_ABSENT' } else { $f.State.ToString() }"
    )
    # Get-WindowsOptionalFeature interroge DISM : plus lent qu'une commande
    # habituelle, mais reste dans la marge du timeout (30s) de run_powershell.
    actual, error = collector.run_powershell(command)
    if error:
        log.warning("Capture avant rémédiation impossible pour la fonctionnalité %s : %s", feature, error)
        return None
    actual = actual.strip()
    if actual == "HARDENOS_ABSENT":
        log.warning("Fonctionnalité optionnelle %s introuvable.", feature)
        return None
    return {"kind": "optional_feature", "feature": feature, "old_state": actual}


def capture_before_state(script: str) -> dict | None:
    """Capture la valeur ACTUELLE (avant exécution) du réglage ciblé par
    `script`, si celui-ci correspond à un motif reconnu ET ne contient
    qu'UNE seule commande de ce type. Retourne None sinon (autre famille,
    script composé/groupé, échec de lecture...) — pas de rollback
    individuel proposé dans ce cas (le rollback global reste disponible)."""
    return (
        _capture_registry(script)
        or _capture_net_accounts(script)
        or _capture_service(script)
        or _capture_auditpol(script)
        or _capture_firewall(script)
        or _capture_defender(script)
        or _capture_local_user(script)
        or _capture_optional_feature(script)
    )


def build_undo_script(before_state: dict | None) -> str | None:
    """Construit un script PowerShell qui restaure l'état capturé par
    capture_before_state(). Retourne None si aucun état n'a été capturé."""
    if before_state is None:
        return None

    if before_state["kind"] == "registry":
        path, name = before_state["path"], before_state["name"]
        if not before_state["existed"]:
            return f"Remove-ItemProperty -Path '{path}' -Name '{name}' -ErrorAction SilentlyContinue"
        return f"Set-ItemProperty -Path '{path}' -Name '{name}' -Value {before_state['old_value']}"

    if before_state["kind"] == "net_accounts":
        return f"net accounts /{before_state['option']}:{before_state['old_value']}"

    if before_state["kind"] == "service":
        name, old_type, old_status = before_state["name"], before_state["old_type"], before_state["old_status"]
        undo = f"Set-Service -Name '{name}' -StartupType {old_type}"
        # Redémarre seulement si le service tournait avant ET que le type
        # restauré le permet (un service Disabled ne peut pas être démarré).
        if old_status.lower() == "running" and old_type.lower() != "disabled":
            undo += f"; Start-Service -Name '{name}'"
        return undo

    if before_state["kind"] == "auditpol":
        subcategory, setting = before_state["subcategory"], before_state["old_setting"]
        success = "enable" if "success" in setting.lower() else "disable"
        failure = "enable" if "failure" in setting.lower() else "disable"
        return f'auditpol /set /subcategory:"{subcategory}" /success:{success} /failure:{failure}'

    if before_state["kind"] == "firewall":
        profile, prop, old_value = before_state["profile"], before_state["property"], before_state["old_value"]
        # -Enabled attend un GpoBoolean : une chaîne "True"/"False" passe,
        # un booléen .NET brut échoue la conversion de type (même souci que
        # backup.py::_restore_firewall) — old_value est déjà une chaîne ici
        # (capturé via .ToString()), donc pas de conversion supplémentaire à faire.
        return f"Set-NetFirewallProfile -Profile {profile} -{prop} {old_value}"

    if before_state["kind"] == "defender":
        prop, old_value = before_state["property"], before_state["old_value"]
        return f"Set-MpPreference -{prop} {old_value}"

    if before_state["kind"] == "local_user":
        name = before_state["name"]
        if before_state["old_enabled"].lower() == "true":
            return f"Enable-LocalUser -Name '{name}'"
        return f"Disable-LocalUser -Name '{name}'"

    if before_state["kind"] == "optional_feature":
        feature, old_state = before_state["feature"], before_state["old_state"]
        if old_state.lower() == "enabled":
            return f"Enable-WindowsOptionalFeature -Online -FeatureName {feature} -NoRestart"
        return f"Disable-WindowsOptionalFeature -Online -FeatureName {feature} -NoRestart"

    return None

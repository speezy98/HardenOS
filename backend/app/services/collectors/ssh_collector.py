"""Connecteur SSH réel — exécute les commandes d'audit CIS sur une machine Linux.

`collect()` reste LECTURE SEULE : il n'exécute QUE les commandes d'audit
(`control.audit.command`) et ne modifie jamais la machine cible.

`execute_remediation()` est la SEULE méthode de cette classe qui écrit sur la
machine cible (exécution d'une commande de remédiation) — appelée uniquement
depuis le flux de remédiation explicite, jamais pendant un audit.

Une seule connexion SSH (Paramiko) est ouverte par audit et réutilisée pour
tous les contrôles, puis fermée explicitement via close() ou le context manager.
"""
import re

import paramiko

from app.services.collectors.base import BaseCollector, CollectionResult
from app.utils.ssh_errors import safe_ssh_error_message

# Timeout (s) par commande distante, pour ne pas bloquer indéfiniment l'audit.
_COMMAND_TIMEOUT = 10
# Timeout (s) pour une commande de REMÉDIATION : bien plus long qu'un audit,
# car `apt install` (auditd, aide, rsyslog...) peut prendre plusieurs dizaines
# de secondes. Reste sous le timeout HTTP du frontend (300s) pour un contrôle
# unitaire, en laissant la marge du rejeu.
_REMEDIATION_TIMEOUT = 180
# Timeout (s) d'établissement de la connexion SSH.
_CONNECT_TIMEOUT = 15

# Répertoire des sauvegardes globales Linux (archives /etc) sur la machine cible.
_LINUX_BACKUP_DIR = "/var/backups/hardenos"

# Clés sysctl modifiées par les contrôles CIS. Le rollback global doit
# RÉAPPLIQUER leur valeur d'origine : une remédiation fait `sysctl -w` (change
# le noyau en direct), et supprimer le fichier de conf ne réinitialise PAS la
# valeur vivante (sysctl ne touche pas une clé absente des fichiers). On capture
# donc ces valeurs à la sauvegarde et on les repose à la restauration.
_SYSCTL_KEYS = (
    "kernel.kptr_restrict",
    "kernel.randomize_va_space",
    "kernel.yama.ptrace_scope",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.ip_forward",
    "net.ipv4.tcp_syncookies",
    "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.all.accept_source_route",
)

# Fichiers de configuration cités dans un script de remédiation (chemins absolus
# sous /etc ou /var). Sert au rollback INDIVIDUEL : on sauvegarde ces fichiers
# AVANT la remédiation pour pouvoir les restaurer précisément.
_CONFIG_FILE_RE = re.compile(r"/(?:etc|var)/[A-Za-z0-9._/-]+")

# Paquets installés / services activés par un script de remédiation — pour que
# le rollback individuel puisse DÉSINSTALLER (si le paquet n'était pas là avant)
# et DÉSACTIVER (restaurer l'état enabled/active d'origine du service).
_APT_INSTALL_RE = re.compile(r"\bapt(?:-get)?\s+install\s+([^\n;&|]+)", re.IGNORECASE)
_SYSTEMCTL_ENABLE_RE = re.compile(r"\bsystemctl\s+(?:--now\s+)?enable\s+(\S+)", re.IGNORECASE)

# Paquets qu'on ne DÉSINSTALLE JAMAIS lors d'un rollback individuel : les
# retirer casserait l'administration de la machine (plus de sudo -> plus
# d'élévation ; plus de pam -> plus d'authentification ; systemd/libc -> système
# inutilisable). L'utilisateur peut toujours les retirer manuellement s'il y tient.
_UNDO_NEVER_REMOVE = {
    "sudo", "libpam-runtime", "libpam-modules", "libpam-modules-bin", "libpam0g",
    "systemd", "systemd-sysv", "libc6", "openssh-server",
}


def _extract_config_files(script: str) -> list[str]:
    """Chemins /etc//var uniques cités dans `script` (cibles à sauvegarder pour
    un rollback individuel). Vide si le script ne touche aucun fichier (ex.
    `apt install`, `systemctl enable`) — dans ce cas, seul le rollback global
    s'applique."""
    seen: list[str] = []
    for m in _CONFIG_FILE_RE.findall(script):
        p = m.rstrip(".,;)")
        # On ignore les répertoires génériques (ex. /etc/audit/ dans un find) :
        # on ne sauvegarde que des fichiers, pas des arborescences entières.
        if p.endswith("/"):
            continue
        if p not in seen:
            seen.append(p)
    return seen

# apt en mode NON INTERACTIF pour la remédiation. Trois prompts distincts à
# neutraliser, sinon la commande bloque/échoue en SSH non-interactif :
#   -y                         : la confirmation "[O/n] continuer ?" d'apt
#   DEBIAN_FRONTEND=noninteractive : les prompts debconf de config de paquet
#   -o Dpkg::Options::=--force-conf* : les prompts dpkg de CONFFILE (fichier de
#       conf modifié — fréquent ici car des remédiations éditent /etc/... avant
#       d'installer le paquet qui le fournit). confdef+confold = garder la
#       version actuelle du fichier, ne rien demander.
# On réécrit apt/apt-get install|remove|... pour injecter ces options.
_APT_ACTION_RE = re.compile(
    r"\bapt(?:-get)?\s+(install|remove|purge|upgrade|dist-upgrade|autoremove)\b"
)
_APT_NONINTERACTIVE_OPTS = (
    "-y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
)

# PATH complet préfixé à CHAQUE commande. Paramiko exec_command() ouvre un
# shell NON-interactif / NON-login : sous Debian il n'hérite alors que d'un
# PATH minimal (/usr/bin:/bin), SANS /usr/sbin ni /sbin. Les commandes
# d'administration référencées par leur nom court dans les règles CIS
# (sshd, sysctl, ufw, aa-status, auditctl, ...) y sont donc "command not
# found" alors qu'elles existent bien sur la machine. On rétablit le PATH
# standard d'un shell login pour les rendre trouvables, sans toucher aux
# règles YAML (qui gardent volontairement les noms courts).
_PATH_PREFIX = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; "
# Tronque la sortie observée stockée (les commandes type `find` peuvent être longues).
_MAX_OUTPUT_CHARS = 2000

# Motifs (sur stderr, minuscules) signalant un VRAI échec d'EXÉCUTION qui rend la
# vérification IMPOSSIBLE et non interprétable -> na (exclu du score).
# IMPORTANT : on n'y met QUE les échecs de privilège/transport. On EXCLUT
# volontairement "command not found" et "no such file or directory" : ce sont des
# informations MÉTIER (binaire/paquet absent, fichier de conf absent) que
# _evaluate doit interpréter selon le sens du contrôle (absence -> souvent pass,
# présence requise -> fail). Voir _unverifiable_reason / _evaluate.
_UNVERIFIABLE_STDERR_HINTS = (
    "permission denied",
    "permission non accordée",
    "operation not permitted",
    "not permitted",
    "must be run as root",
    "sudo:",                       # sudo lui-même a échoué (mdp refusé, pas de TTY...)
    "are not allowed to run sudo",
    "a password is required",
    "incorrect password",
    "a terminal is required",
)

# Indices pour l'heuristique des contrôles à condition textuelle (expected null).
# "présence attendue" : une sortie non vide + code 0 tend vers conforme.
_PRESENCE_HINTS = ("installé", "doit être installé", "doit être présent",
                   "doit être activé", "doit être enabled", "enabled et active",
                   "présente", "configuré", "configurée")
# "absence attendue" : une sortie VIDE tend vers conforme.
_ABSENCE_HINTS = ("ne doit pas être installé", "ne doit pas être présent",
                  "doit être désactivé", "désactivé ou absent", "ne doit être",
                  "blacklisté", "non chargeable", "ne doit contenir")

# Contrôles portant sur l'EXISTENCE d'un paquet/fichier (vs un réglage à
# appliquer). Utilisé quand la sortie est vide SANS stderr d'absence explicite :
# un tel contrôle qui ne renvoie rien signifie que la cible est absente
# ("(absent — requis)"), là où un contrôle de directive signifierait plutôt
# "présent mais non configuré". NB : "installé"/"installed" (pas le bare
# "install", pour ne pas capter "Install-Recommends" qui est un réglage).
_INSTALL_HINTS = (
    "installé", "installés", "installée", "installées",
    "installed", "is installed", "are installed",
    "package", "paquet", "exists", "existe",
)

# Motifs stderr (minuscules) signalant que la CIBLE est absente (fichier de
# conf inexistant, paquet/binaire non installé, service inconnu de systemd) —
# et NON un échec d'exécution/privilège (ceux-là -> na, cf.
# _UNVERIFIABLE_STDERR_HINTS). Ici la cible manque parce que le durcissement
# n'est pas en place : c'est un vrai résultat (fail), mais on remplace le
# message brut de grep/stat/find/systemctl par un libellé lisible.
_ABSENT_STDERR_HINTS = (
    "no such file or directory",
    "aucun fichier ou dossier",
    "command not found",
    "commande introuvable",
    "cannot stat",
    "cannot access",
    "impossible d'exécuter statx",
    "impossible d'accéder",
    "failed to get unit file state",   # systemctl : service/unité inconnu
    "could not be found",              # systemctl : "Unit X could not be found."
    "n'a pas pu être trouvé",
    "no packages found",               # dpkg-query : paquet non installé
    "aucun paquet",
    "not installed",
    "n'existe pas",
)


class SSHConnectionError(Exception):
    """Échec d'établissement de la connexion SSH (mappé en erreur d'audit).

    Le message porté est COURT et NON sensible (ni hôte, ni credentials) ; il
    est destiné à être affiché tel quel à l'utilisateur (audits.error_message).
    """


class SSHCollector(BaseCollector):
    """Collecteur exécutant les commandes d'audit via SSH (Paramiko)."""

    def __init__(self, hostname: str, username: str, password: str, port: int = 22):
        self._hostname = hostname
        self._username = username
        self._password = password
        self._port = port
        self._client: paramiko.SSHClient | None = None

    # --- Cycle de vie de la connexion ---------------------------------------

    def connect(self) -> None:
        """Ouvre la connexion SSH (une seule fois pour tout l'audit)."""
        client = paramiko.SSHClient()
        # AutoAddPolicy : on accepte la clé d'hôte au premier contact (contexte
        # d'audit interne / air-gapped). À durcir avec un known_hosts en prod.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self._hostname,
                port=self._port,
                username=self._username,
                password=self._password,
                timeout=_CONNECT_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
            )
        except Exception as exc:  # auth, socket, timeout, DNS, etc.
            # Message court et NON sensible (ni hôte, ni identifiants).
            raise SSHConnectionError(safe_ssh_error_message(exc)) from exc
        self._client = client

    def close(self) -> None:
        """Ferme proprement la connexion SSH."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_exc):
        self.close()

    # --- Collecte d'un contrôle ---------------------------------------------

    def collect(self, system, control: dict) -> CollectionResult:
        if self._client is None:
            raise SSHConnectionError("La connexion SSH n'est pas ouverte.")

        # Contrôle à revue humaine : non évaluable automatiquement -> warn
        # systématique, SANS exécuter de commande ni tenter un jugement pass/fail.
        if control.get("check_type") == "manual":
            return CollectionResult(
                status="warn",
                actual_value="(vérification manuelle) contrôle nécessitant une revue humaine",
            )

        command = (control.get("audit") or {}).get("command")
        if not command:
            return CollectionResult(
                status="na", actual_value="Aucune commande d'audit définie."
            )

        use_sudo = bool(getattr(system, "use_sudo", False))
        try:
            out, err, exit_code = self._exec(command, use_sudo)
        except Exception as exc:  # timeout, canal fermé, etc.
            # Échec d'exécution côté transport : non vérifiable (exclu du score).
            # NB : str(exc) provient de Paramiko/réseau, jamais des credentials.
            return CollectionResult(
                status="na",
                actual_value=f"(non vérifiable) erreur d'exécution : {exc}",
            )

        # Échec d'exécution applicatif (commande absente, droits insuffisants,
        # sudo refusé...) : on ne peut pas mesurer -> non vérifiable (na), JAMAIS
        # un "fail" trompeur ni un "pass".
        unverifiable = self._unverifiable_reason(out, err, exit_code)
        if unverifiable is not None:
            return CollectionResult(status="na", actual_value=unverifiable)

        return self._evaluate(control, out, err, exit_code)

    # --- Exécution d'une remédiation (ÉCRITURE — seule méthode qui modifie) --

    def execute_remediation(self, command: str, use_sudo: bool) -> dict:
        """Exécute une commande de remédiation via SSH.

        Contrairement à collect(), cette méthode MODIFIE la machine cible.
        Retourne la même forme que l'agent Windows (remediate.execute_script)
        pour que le code appelant traite les deux OS de façon uniforme :
          { "status": "ok",    "output": "..." }
          { "status": "error", "output": "...", "error": "..." }
        """
        if self._client is None:
            raise SSHConnectionError("La connexion SSH n'est pas ouverte.")

        # apt non interactif : normalise apt -> apt-get (plus stable en script)
        # et injecte les options qui neutralisent les 3 prompts (cf.
        # _APT_NONINTERACTIVE_OPTS). N'affecte QUE les actions install/remove/...
        prepared = _APT_ACTION_RE.sub(
            lambda m: f"apt-get {m.group(1)} {_APT_NONINTERACTIVE_OPTS}", command
        )
        # DEBIAN_FRONTEND=noninteractive : supprime les prompts debconf émis
        # pendant la configuration de certains paquets. Placé en tête du script
        # exécuté par bash -c.
        prepared = "export DEBIAN_FRONTEND=noninteractive; " + prepared

        # Les scripts de remédiation utilisent couramment des redirections (>>),
        # des séquences (;) ou des pipes qui doivent s'exécuter EN ENTIER sous
        # les privilèges cibles. Avec `sudo <cmd>` seul, seul le premier binaire
        # est élevé : `sudo echo x >> /etc/fichier` fait la redirection dans le
        # shell appelant (non-root) -> "Permission denied" ; un `;` fait de même
        # retomber la 2e commande en non-root. On enveloppe donc toute la
        # commande dans `bash -c '...'` (échappement des ' par '\'') pour qu'elle
        # tourne d'un bloc sous root. Ne concerne QUE la remédiation ; collect()
        # (audit, lecture seule) n'est pas modifié.
        wrapped = "bash -c '" + prepared.replace("'", "'\\''") + "'"

        try:
            # Timeout long : apt install peut durer bien plus que les 10s d'audit.
            out, err, exit_code = self._exec(wrapped, use_sudo, timeout=_REMEDIATION_TIMEOUT)
        except Exception as exc:
            return {"status": "error", "output": "", "error": str(exc)}

        if exit_code != 0:
            return {
                "status": "error",
                "output": out,
                "error": err or f"Code de sortie {exit_code}",
            }

        return {"status": "ok", "output": out}

    # --- Sauvegarde / restauration GLOBALE (Linux) --------------------------

    def create_backup(self, snapshot_name: str, use_sudo: bool) -> dict:
        """Sauvegarde GLOBALE Linux : archive /etc (là où vivent tous les
        réglages CIS) dans une archive horodatée, AVANT une remédiation —
        filet de sécurité pour un rollback global. Équivalent SSH de l'agent
        Windows backup.create_backup.

        Retourne { "status": "ok", "path": "..." } ou { "status": "error", "error": ... }.
        """
        if self._client is None:
            raise SSHConnectionError("La connexion SSH n'est pas ouverte.")

        path = f"{_LINUX_BACKUP_DIR}/{snapshot_name}.tar.gz"
        pkgs = f"{_LINUX_BACKUP_DIR}/{snapshot_name}.pkgs"
        sysctl_path = f"{_LINUX_BACKUP_DIR}/{snapshot_name}.sysctl"
        # `;` (pas &&) après tar : tar peut renvoyer 1 sur simple avertissement
        # (fichier modifié pendant la lecture) sans que l'archive soit invalide.
        # On archive /etc + la liste des paquets (désinstallation au rollback) +
        # les valeurs sysctl actuelles (réappliquées au rollback). On valide via
        # l'existence de l'archive + le marqueur.
        # On archive /etc ET /var/log/audit s'il existe : ce dernier est créé par
        # auditd (installé par une remédiation). Sans lui, le log d'audit reste
        # orphelin après désinstallation d'auditd au rollback, gardant ses
        # permissions durcies (contrôle 6.2.4.1 resté conforme à tort).
        script = (
            f"mkdir -p {_LINUX_BACKUP_DIR}; "
            f"dpkg --get-selections | sort > {pkgs}; "
            f"sysctl {' '.join(_SYSCTL_KEYS)} 2>/dev/null > {sysctl_path}; "
            f"cd /; TP=etc; [ -d var/log/audit ] && TP='etc var/log/audit'; tar czf {path} $TP; "
            f"test -f {path} && echo HARDENOS_OK"
        )
        out, err, code = self._exec(
            "bash -c '" + script.replace("'", "'\\''") + "'", use_sudo, timeout=_REMEDIATION_TIMEOUT
        )
        if "HARDENOS_OK" not in out:
            return {"status": "error", "error": err or "Échec de l'archivage de /etc."}
        return {"status": "ok", "path": path}

    def restore_backup(self, backup_path: str, use_sudo: bool) -> dict:
        """Restaure une sauvegarde GLOBALE Linux — rollback COMPLET, retour à
        l'état de la sauvegarde :
          1. supprime les fichiers /etc CRÉÉS après la sauvegarde (drop-ins
             sysctl, profile.d, règles audit, liens systemd d'activation...) ;
          2. restaure les fichiers modifiés ;
          3. DÉSINSTALLE les paquets installés depuis (hors paquets critiques,
             cf. _UNDO_NEVER_REMOVE) ;
          4. recharge systemd/sysctl/sshd.

        Retourne { "status": "ok" } ou { "status": "error", "error": ... }.
        """
        if self._client is None:
            raise SSHConnectionError("La connexion SSH n'est pas ouverte.")

        base = backup_path[: -len(".tar.gz")] if backup_path.endswith(".tar.gz") else backup_path
        pkgs_path = base + ".pkgs"
        sysctl_path = base + ".sysctl"
        never = "|".join(sorted(_UNDO_NEVER_REMOVE))

        script = (
            f"if [ ! -f {backup_path} ]; then echo HARDENOS_NOFILE; exit 0; fi; "
            # 1. Supprimer les fichiers absents de l'archive (créés depuis) — sous
            #    /etc ET /var/log/audit (log orphelin d'auditd après désinstall).
            "BL=$(mktemp); CUR=$(mktemp); "
            f"tar tzf {backup_path} | grep -v '/$' | sort > $BL; "
            "cd /; find etc var/log/audit \\( -type f -o -type l \\) 2>/dev/null | sort > $CUR; "
            "comm -13 $BL $CUR | while IFS= read -r f; do rm -f \"/$f\"; done; "
            "rm -f $BL $CUR; "
            # 2. Restaurer le contenu des fichiers modifiés.
            f"tar xzf {backup_path} -C /; "
            # 3. Désinstaller les paquets installés depuis la sauvegarde.
            f"if [ -f {pkgs_path} ]; then CURPKG=$(mktemp); dpkg --get-selections | sort > $CURPKG; "
            f"NEW=$(comm -13 {pkgs_path} $CURPKG | grep -P '\\tinstall$' | cut -f1 | grep -vwE '{never}'); "
            "if [ -n \"$NEW\" ]; then DEBIAN_FRONTEND=noninteractive apt-get remove -y $NEW 2>/dev/null || true; fi; "
            "rm -f $CURPKG; fi; "
            # 4. Recharger systemd (liens d'activation restaurés), sysctl, sshd.
            "systemctl daemon-reload 2>/dev/null || true; "
            "sysctl --system >/dev/null 2>&1 || true; "
            # Réappliquer les valeurs sysctl d'origine EN MÉMOIRE (le noyau garde
            # sinon la valeur durcie posée par `sysctl -w` de la remédiation).
            f"if [ -f {sysctl_path} ]; then sysctl -e -p {sysctl_path} >/dev/null 2>&1 || true; fi; "
            "if sshd -t 2>/dev/null; then "
            "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true; "
            "fi; "
            "echo HARDENOS_OK"
        )
        out, err, code = self._exec(
            "bash -c '" + script.replace("'", "'\\''") + "'", use_sudo, timeout=_REMEDIATION_TIMEOUT
        )
        if "HARDENOS_NOFILE" in out:
            return {"status": "error", "error": f"Archive de sauvegarde introuvable : {backup_path}"}
        if "HARDENOS_OK" not in out:
            return {"status": "error", "error": err or "Échec de la restauration."}
        return {"status": "ok"}

    def _run_capture(self, script: str, use_sudo: bool) -> str:
        """Exécute un petit script de CAPTURE d'état (lecture) et retourne stdout."""
        out, _err, _code = self._exec(
            "bash -c '" + script.replace("'", "'\\''") + "'", use_sudo, timeout=_COMMAND_TIMEOUT
        )
        return out

    def build_undo_script(self, script: str, use_sudo: bool) -> str | None:
        """Capture l'état AVANT d'un script de remédiation et renvoie un script
        shell qui restaure l'état INITIAL (rollback INDIVIDUEL Linux) :
          - fichiers /etc,/var modifiés -> contenu + mode restaurés (supprimés
            s'ils n'existaient pas avant) ;
          - services activés -> arrêtés/désactivés s'ils ne l'étaient pas avant ;
          - paquets installés -> DÉSINSTALLÉS s'ils n'étaient pas présents avant.
        Retourne None si rien n'est annulable individuellement. À appeler AVANT
        la remédiation.

        Ordre de l'annulation : services (tant que le paquet est là) → paquets
        → fichiers (dernier mot sur le contenu).
        """
        if self._client is None:
            raise SSHConnectionError("La connexion SSH n'est pas ouverte.")

        service_parts: list[str] = []
        package_parts: list[str] = []
        file_parts: list[str] = []

        # --- Services activés : restaurer l'état enabled/active d'origine ---
        for m in _SYSTEMCTL_ENABLE_RE.finditer(script):
            svc = m.group(1)
            out = self._run_capture(
                f"echo EN=$(systemctl is-enabled {svc} 2>/dev/null); "
                f"echo AC=$(systemctl is-active {svc} 2>/dev/null)",
                use_sudo,
            )
            was_enabled = "EN=enabled" in out
            was_active = "AC=active" in out  # 'inactive'/'failed' ne matchent pas
            undo = []
            if not was_active:
                undo.append(f"systemctl stop {svc}")
            if not was_enabled:
                undo.append(f"systemctl disable {svc}")
            if undo:
                service_parts.append("; ".join(undo) + " 2>/dev/null || true")

        # --- Paquets installés : désinstaller ceux ABSENTS avant la remédiation.
        for m in _APT_INSTALL_RE.finditer(script):
            for pkg in (t for t in m.group(1).split() if not t.startswith("-")):
                if pkg in _UNDO_NEVER_REMOVE:
                    # Paquet critique : le désinstaller verrouillerait la machine
                    # (sudo -> plus d'élévation ; pam -> plus d'auth). On laisse.
                    continue
                out = self._run_capture(
                    f"if dpkg -s {pkg} 2>/dev/null | grep -q 'install ok installed'; "
                    f"then echo INSTALLED; else echo ABSENT; fi",
                    use_sudo,
                )
                if "ABSENT" in out:
                    package_parts.append(f"apt-get remove -y {pkg}")

        # --- Fichiers de config modifiés : restaurer contenu + mode ---
        for path in _extract_config_files(script):
            out = self._run_capture(
                f"if [ -e '{path}' ]; then echo EXISTS; stat -c '%a' '{path}'; base64 '{path}'; "
                f"else echo ABSENT; fi",
                use_sudo,
            )
            lines = out.splitlines()
            if not lines:
                continue
            head = lines[0].strip()
            if head == "ABSENT":
                file_parts.append(f"rm -f '{path}'")
            elif head == "EXISTS" and len(lines) >= 2:
                mode = lines[1].strip()
                b64 = "".join(line.strip() for line in lines[2:])
                file_parts.append(f"printf %s '{b64}' | base64 -d > '{path}'; chmod {mode} '{path}'")

        parts = service_parts + package_parts + file_parts
        return "; ".join(parts) if parts else None

    # --- Exécution d'une commande (avec ou sans sudo) ------------------------

    def _exec(self, command: str, use_sudo: bool, timeout: int = _COMMAND_TIMEOUT) -> tuple[str, str, int]:
        """Exécute `command` et retourne (stdout, stderr, exit_code).

        Si use_sudo : préfixe par `sudo -S -p ''` (mode non interactif, prompt
        supprimé) et injecte le mot de passe UNIQUEMENT sur le canal stdin —
        jamais dans la ligne de commande, jamais dans les logs/actual_value.

        `timeout` : audit court par défaut (_COMMAND_TIMEOUT) ; la remédiation
        passe un délai bien plus long (apt install, cf. execute_remediation).
        """
        if use_sudo:
            # -S : lit le mot de passe sur stdin. -p '' : aucun prompt écrit sur
            # stderr (évite de polluer la sortie observée). Le mot de passe n'est
            # PAS dans cette chaîne : seulement le préfixe sudo.
            # Le PATH est exporté AVANT sudo pour que le binaire cible soit
            # résolu même quand sudo n'élargit pas le PATH (secure_path).
            full_command = _PATH_PREFIX + "sudo -S -p '' " + command
            stdin, stdout, stderr = self._client.exec_command(
                full_command, timeout=timeout
            )
            # Mot de passe injecté sur stdin (canal séparé de stdout/stderr) puis
            # EOF : il n'apparaît donc pas dans `out`. On l'écrit une seule fois.
            try:
                stdin.write(self._password + "\n")
                stdin.flush()
                stdin.channel.shutdown_write()
            except OSError:
                # Canal déjà fermé (sudo n'attendait pas de saisie) : sans effet.
                pass
        else:
            stdin, stdout, stderr = self._client.exec_command(
                _PATH_PREFIX + command, timeout=timeout
            )

        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return out, err, exit_code

    # --- Détection d'un échec d'EXÉCUTION (non vérifiable) -------------------

    @staticmethod
    def _unverifiable_reason(out: str, err: str, exit_code: int) -> str | None:
        """Retourne un libellé `(non vérifiable) ...` si la commande n'a PAS PU
        s'exécuter (résultat non interprétable), sinon None.

        On ne déclenche `na` QUE sur de vrais échecs d'exécution / privilège :
        permission refusée, sudo en échec (mdp refusé, pas de TTY), droits root
        requis. Voir _UNVERIFIABLE_STDERR_HINTS.

        On NE traite PLUS "exit_code != 0 + stdout vide" comme un échec : pour
        grep/dpkg-query/systemctl, c'est un résultat MÉTIER normal (absent /
        inactif). De même, "command not found" et "no such file" ne sont PAS
        traités ici : ce sont des infos métier (binaire/paquet/fichier absent)
        que `_evaluate` interprète selon le sens du contrôle.
        """
        err_low = err.lower()
        if err and any(h in err_low for h in _UNVERIFIABLE_STDERR_HINTS):
            return f"(non vérifiable) {err[:_MAX_OUTPUT_CHARS]}"
        return None

    # --- Détermination du statut --------------------------------------------

    @staticmethod
    def _resolve_check_type(control, expected) -> str | None:
        """Détermine le sens du contrôle : 'comparison' | 'presence' | 'absence'
        | 'manual'.

        PRIORITÉ : si le contrôle porte un `check_type` explicite, il FAIT
        AUTORITÉ (aucune heuristique de mots-clés). Valeurs inconnues ignorées.
          - 'manual' : contrôle NON évaluable automatiquement (jugement humain)
            -> warn systématique, sans exécuter de logique pass/fail.
        Sinon, repli :
          - expected non null                     -> 'comparison'
          - condition matche _ABSENCE_HINTS        -> 'absence'
          - condition matche _PRESENCE_HINTS       -> 'presence'
          - rien de tout ça                        -> None (indéterminé)
        """
        declared = control.get("check_type")
        if declared in ("comparison", "presence", "absence", "manual"):
            return declared

        if expected is not None:
            return "comparison"
        cond = ((control.get("audit") or {}).get("condition", "") or "").lower()
        if any(h in cond for h in _ABSENCE_HINTS):
            return "absence"
        if any(h in cond for h in _PRESENCE_HINTS):
            return "presence"
        return None

    @staticmethod
    def _is_absent_stderr(err: str) -> bool:
        """True si `err` indique que la CIBLE (fichier/paquet/binaire/service)
        est absente — cf. _ABSENT_STDERR_HINTS. Distingue ce cas d'un simple
        "présent mais non configuré". Ne change PAS le statut."""
        low = err.lower()
        return any(h in low for h in _ABSENT_STDERR_HINTS)

    def _fail_label(self, control, out: str, err: str) -> str:
        """Valeur observée LISIBLE pour un contrôle EN ÉCHEC (presence/comparison).
        Distingue les deux causes attendues par l'utilisateur :
          - cible ABSENTE (paquet/fichier/binaire/service non installé)
            -> "(absent — requis)"
          - présent mais réglage NON APPLIQUÉ (fichier là, directive manquante)
            -> "(non configuré)"
          - présent avec une valeur observable mais incorrecte -> la valeur brute
        """
        if out:
            return out[:_MAX_OUTPUT_CHARS]
        # stderr explicite "cible manquante" (no such file, command not found,
        # no packages found, unit not found...) : absence certaine.
        if err and self._is_absent_stderr(err):
            return "(absent — requis)"
        # Sortie vide sans stderr d'absence (souvent car la commande masque
        # stderr via 2>/dev/null) : on tranche d'après le SENS du contrôle —
        # un contrôle d'installation/existence -> absent ; un contrôle de
        # réglage/directive -> non configuré.
        text = " ".join([
            control.get("title") or "",
            (control.get("audit") or {}).get("condition") or "",
        ]).lower()
        if any(h in text for h in _INSTALL_HINTS):
            return "(absent — requis)"
        return "(non configuré)"

    def _evaluate(self, control, out, err, exit_code) -> CollectionResult:
        observed_trunc = out[:_MAX_OUTPUT_CHARS] if out else ""
        non_empty = bool(out)

        expected = (control.get("audit") or {}).get("expected")
        check_type = self._resolve_check_type(control, expected)

        if check_type == "comparison":
            # Comparaison de valeur à l'attendu. Tolérante : casse + espaces
            # normalisés, "contient". Un écart = vraie non-conformité -> fail.
            # (On arrive ici seulement si la commande a pu s'exécuter : na filtré
            #  en amont.)
            exp_norm = " ".join(str(expected).lower().split()) if expected is not None else ""
            out_norm = " ".join(out.lower().split())
            if exp_norm and exp_norm in out_norm:
                return CollectionResult(status="pass", actual_value=observed_trunc or "(sortie vide)")
            return CollectionResult(status="fail", actual_value=self._fail_label(control, out, err))

        if check_type == "absence":
            # L'élément NE DOIT PAS exister. Sortie vide (exit 0 OU 1 : grep/dpkg
            # renvoient 1 quand rien n'est trouvé) -> absent -> pass. Sortie non
            # vide montrant la présence -> fail.
            if not non_empty:
                return CollectionResult(status="pass", actual_value="(rien — conforme)")
            return CollectionResult(status="fail", actual_value=observed_trunc or "(présent)")

        if check_type == "presence":
            # L'élément DOIT exister/être configuré. Présent ET sortie exploitable
            # (exit 0) -> pass. Sinon fail avec un libellé distinguant cible
            # absente (paquet/fichier non installé) de présent-mais-non-configuré.
            # Un VRAI échec de droits reste na, filtré en amont.
            if non_empty and exit_code == 0:
                return CollectionResult(status="pass", actual_value=observed_trunc)
            return CollectionResult(status="fail", actual_value=self._fail_label(control, out, err))

        # Sens indéterminé (aucun check_type, aucune hint) : sortie exploitable
        # -> warn (vérification manuelle) ; sinon na (exclu du score).
        if non_empty:
            note = "vérification manuelle recommandée"
            return CollectionResult(status="warn", actual_value=f"{observed_trunc} · {note}")
        return CollectionResult(
            status="na", actual_value="(non vérifiable) sens du contrôle indéterminé, sortie vide"
        )

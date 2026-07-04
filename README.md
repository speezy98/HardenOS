# 🛡️ HardenOS

Scanner de configuration sécurité automatique basé sur les référentiels **CIS Benchmark**.  
Audite la conformité des systèmes Windows et Linux, score par domaine, propose des scripts de remédiation.

---

## Statut du projet

| Composant | Statut |
|---|---|
| Frontend — structure & design system | ✅ Fait |
| Frontend — layout (Sidebar, TopBar, AppLayout) | ✅ Fait |
| Frontend — vue Login (formulaire, gestion d'erreur, redirection) | ✅ Fait |
| Frontend — Dashboard (KPI parc + liste systèmes réels) | ✅ Fait |
| Frontend — vue détail système | ✅ Fait |
| Frontend — vue remédiation (dry-run, apply, rollback) | ✅ Fait |
| Frontend — vue comparaison d'audits (score, domaines, contrôles) | ✅ Fait |
| Frontend — vue rapports (aperçu structuré + exports JSON / CSV / HTML imprimable) | ✅ Fait |
| Frontend — vue gestion utilisateurs (CRUD, rôles, garde admin) | ✅ Fait |
| Gestion utilisateurs admin (backend `/api/users` + UI : lister, créer, modifier, révoquer/réactiver, supprimer ; garde-fous) | ✅ Fait |
| Écran « Mon compte » — self-service email + mot de passe pour tous les rôles (`/api/account`) | ✅ Fait |
| Comparaison d'audits (backend `/api/comparison` + UI : score global, domaines, contrôles ; agnostique OS) | ✅ Fait |
| Rapport de conformité par audit (backend `/api/reports` + UI : synthèse, domaines, non-conformités + remédiation ; agnostique OS) | ✅ Fait |
| Exports de rapport JSON / CSV / HTML autonome imprimable (PDF via impression navigateur) | ✅ Fait |
| Backend — socle MVC + modèles + connexion PostgreSQL | ✅ Fait |
| Backend — authentification JWT (tokens, bcrypt, rôles, CLI admin) | ✅ Fait |
| Backend — CRUD systèmes (credentials SSH chiffrés Fernet) | ✅ Fait |
| Référentiels CIS — 300 contrôles YAML (Debian 13, AlmaLinux 10, Windows Server 2022) | ✅ Fait |
| Backend — moteur d'audit + scoring CIS (6 domaines, niveau de risque) | ✅ Fait |
| Backend — scanner SSH réel Linux (Paramiko, lecture seule, sudo optionnel, async) | ✅ Fait |
| Classification déclarative des contrôles (`check_type`) — Debian annoté | ✅ Fait |
| Annotation `check_type` — AlmaLinux 10 & Windows Server 2022 | ⏳ À venir |
| Backend — audit Windows via agent HTTP (agent poussant ses résultats) | ✅ Fait |
| Intégration auth frontend ↔ backend (login graphique réel, JWT) | ✅ Fait |
| Intégration affichage systèmes frontend ↔ backend (lecture seule) | ✅ Fait |
| Base de données (PostgreSQL — provisionnée sur VM Debian) | ✅ Fait |

---

## Stack technique

| Rôle | Technologie |
|---|---|
| Frontend | Vue.js 3 + Pinia + Vue Router + Vite |
| Backend | Flask (Python 3.11) + SQLAlchemy + Flask-Migrate (Alembic) |
| Base de données | PostgreSQL 16 |
| Scan Linux | Paramiko (SSH, lecture seule) ✅ |
| Scan Windows | pywinrm + PowerShell |
| Rapports | Assemblage backend (`/api/reports`) + génération client JSON / CSV / HTML autonome (PDF via impression navigateur) |
| Auth | JWT + bcrypt |

---

## Structure du projet

```
HardenOS/
├── frontend/                    ← Vue.js 3
    ├── src/
    │   ├── main.js              Point d'entrée (Pinia + Router)
    │   ├── App.vue              Composant racine
    │   ├── router/              Vue Router 4 + navigation guards
    │   ├── stores/              Stores Pinia (auth ✅ + systems ✅ + users ✅ branchés backend ; audits en mock, ui local)
    │   ├── views/               Pages (Login ✅, Dashboard ✅, SystemDetail ✅, Remediation ✅, Compare ✅, Reports ✅, Users ✅)
    │   ├── components/
    │   │   ├── charts/          DomainBar ✅ — ScoreGauge 
    │   │   ├── audit/           RiskBadge ✅, StatusBadge ✅, RoleBadge ✅ — ControlTable 
    │   │   ├── system/          SystemCard ✅, OsIcon ✅ — SystemForm (à venir)
    │   │   ├── icons/           LinuxIcon ✅, WindowsIcon ✅ (logos officiels via CDN)
    │   │   └── layout/          AppLayout (+ toast global) ✅, Sidebar ✅, TopBar ✅
    │   ├── api/                 Couche API axios (client + intercepteurs JWT, modules auth ✅ + systems ✅ + users ✅ + account ✅)
    │   ├── services/            exportService.js (rapport JSON/CSV/HTML + téléchargement Blob)
    │   ├── utils/               auditDiff.js (comparaison de snapshots)
    │   └── assets/styles/       tokens.css, reset.css, global.css
    ├── public/
    ├── index.html
    ├── package.json
    └── vite.config.js
└── backend/                     ← Flask (Python 3.11) — MVC
    ├── app/
    │   ├── __init__.py          App factory Flask (create_app)
    │   ├── config.py            Configs dev/prod/test + URL PostgreSQL + JWT
    │   ├── cli.py               Commandes CLI (flask create-admin)
    │   ├── models/              M — modèles SQLAlchemy (un fichier par entité)
    │   │   ├── user.py          User (+ hachage bcrypt, to_dict)
    │   │   ├── system.py        System (+ to_dict sans credentials)
    │   │   ├── audit.py         Audit
    │   │   ├── audit_result.py  AuditResult
    │   │   ├── snapshot.py      Snapshot
    │   │   └── remediation_log.py  RemediationLog
    │   ├── controllers/         C — Blueprints Flask
    │   │   ├── health.py        GET /api/health
    │   │   ├── auth.py          /api/auth (login, refresh, logout, me, admin-check)
    │   │   ├── systems.py       /api/systems (CRUD + credentials SSH dédié)
    │   │   └── audits.py        /api/audits (déclenchement async, détail, historique)
    │   ├── services/            Logique métier
    │   │   ├── auth.py          Authentification, génération de tokens, create_admin
    │   │   ├── systems.py       Validation, chiffrement credentials, CRUD systèmes
    │   │   ├── rules_loader.py  Chargement/sélection des référentiels CIS (YAML)
    │   │   ├── audit_engine.py  Moteur d'audit + scoring CIS (6 domaines, risque)
    │   │   ├── audit_service.py Orchestration : credentials, choix collecteur, async (thread)
    │   │   └── collectors/      Connecteurs de collecte (interface commune)
    │   │       ├── base.py      BaseCollector (interface) + CollectionResult
    │   │       ├── stub.py      StubCollector (bouchon, démos/tests, sans réseau)
    │   │       └── ssh_collector.py  SSHCollector (Paramiko, lecture seule, sudo optionnel)
    │   └── utils/               Helpers transverses
    │       ├── db.py            Instance SQLAlchemy partagée
    │       ├── jwt.py           JWTManager + blocklist des tokens révoqués
    │       ├── auth.py          Décorateur role_required (hiérarchie des rôles)
    │       ├── crypto.py        Chiffrement Fernet (primitives encrypt/decrypt)
    │       ├── ssh_credentials.py  (dé)chiffrement du couple {ssh_user, ssh_password}
    │       └── ssh_errors.py    Messages d'erreur SSH courts et non sensibles
    ├── cis_rules/               Référentiels CIS (300 contrôles, 100 par OS)
    │   ├── debian13.yaml        CIS Debian Linux 13
    │   ├── almalinux10.yaml     CIS AlmaLinux OS 10
    │   └── windows_server2022.yaml  CIS Windows Server 2022
    ├── migrations/              Migrations Alembic / Flask-Migrate
    │   └── versions/            … + add_error_message_to_audits, add_use_sudo_to_systems
    ├── wsgi.py                  Point d'entrée (port 5001 en dev)
    ├── requirements.txt
    └── .env.example
```

> Détails d'installation, routes d'auth et commande `create-admin` :
> voir [`backend/README.md`](backend/README.md).

---

## Référentiels CIS

Le moteur d'audit s'appuie sur **300 contrôles de sécurité** définis en YAML dans
[`backend/cis_rules/`](backend/cis_rules/), soit **100 contrôles par système d'exploitation** :

| Référentiel | Fichier | Source |
|---|---|---|
| Debian Linux 13 | `debian13.yaml` | CIS Debian Linux 13 Benchmark v1.0.0 |
| AlmaLinux OS 10 | `almalinux10.yaml` | CIS AlmaLinux OS 10 Benchmark v1.0.0 |
| Windows Server 2022 | `windows_server2022.yaml` | CIS Microsoft Windows Server 2022 Benchmark v5.0.0 |

Les contrôles sont **sélectionnés parmi les contrôles automatisés** des benchmarks
CIS officiels, en **priorisant les impacts `critical` et `high`**, et **répartis sur
6 domaines** : `access`, `network`, `logging`, `crypto`, `updates`, `services`. Chaque
contrôle est **rattaché à une technique MITRE ATT&CK** et, le cas échéant, à une **CVE
vérifiée** (ex. Baron Samedit `CVE-2021-3156` côté Linux, PrintNightmare `CVE-2021-34527`
et EternalBlue/SMBv1 `CVE-2017-0144` côté Windows).

Chaque contrôle décrit : identifiant CIS, domaine, niveau (L1/L2), poids, impact, commande
d'audit, valeur/condition attendue, un champ **`check_type`** indiquant au scanner comment
interpréter la sortie (voir [Scanner SSH](#scanner-ssh-audit-réel-des-machines-linux)),
script de remédiation, et le contexte de menace (technique ATT&CK, CVE/CVSS éventuelles).

> **Extensible sans toucher au code** : ajouter des contrôles ou prendre en charge un
> nouveau référentiel se fait en **éditant ou en ajoutant un fichier YAML** dans
> `backend/cis_rules/` — aucune modification du code applicatif n'est nécessaire.

---

## Scanner SSH (audit réel des machines Linux)

HardenOS **audite réellement les machines Linux via SSH** (Paramiko), en **lecture
seule** : le scanner exécute uniquement les **commandes d'audit** des contrôles CIS
sur la machine distante et n'applique **jamais** de remédiation.

**Fonctionnement :**

- **Exécution des contrôles CIS** : pour le système ciblé, le moteur charge le bon
  référentiel (`rules_loader`) puis le `SSHCollector` ouvre **une seule connexion**
  Paramiko et exécute la commande d'audit de chaque contrôle, collectant
  `stdout` / `stderr` / code de sortie.
- **Élévation de privilège optionnelle (`sudo`)** : un flag **`use_sudo`** par
  système (colonne dédiée) permet d'exécuter les commandes via `sudo`. Le mot de
  passe est transmis **de façon sécurisée sur l'entrée standard** (`sudo -S -p ''`)
  et **n'apparaît jamais dans la ligne de commande**, ni dans les résultats, logs
  ou messages d'erreur.
- **Exécution asynchrone** : l'audit tourne **en arrière-plan** (thread + contexte
  applicatif et session SQLAlchemy dédiés). Le déclenchement renvoie immédiatement
  un audit en statut **`running`**, qui passe ensuite à **`done`** ou à **`error`**
  (avec un `error_message` court et non sensible).
- **Classification déclarative via `check_type`** : chaque contrôle du YAML
  déclare son **sens d'évaluation** dans un champ `check_type`, qui **fait
  autorité** (plus de devinette par mots-clés). Quatre valeurs :
  - **`comparison`** : la sortie est comparée à une **valeur attendue**
    (`audit.expected`) → conforme si elle correspond (`pass`), sinon `fail` ;
  - **`presence`** : l'élément/réglage **doit** exister/être configuré → présent
    (`pass`), **absent = non conforme** (`fail`) ;
  - **`absence`** : l'élément **ne doit pas** exister → **absent = conforme**
    (`pass`), présent (`fail`) ;
  - **`manual`** : contrôle **non évaluable automatiquement** (jugement humain) →
    **avertissement** (`warn`), sans exécuter de jugement pass/fail.
  - Si un contrôle **n'a pas** de `check_type`, le scanner applique un **repli
    heuristique** (mots-clés de la condition) pour rester rétro-compatible.
- **Statuts résultants** : **non conforme** (`fail`), **conforme** (`pass`),
  **non vérifiable** (`na`, exclu du score) et **vérification manuelle** (`warn`).
  Le statut **`na`** est réservé aux **vrais échecs d'exécution** non
  interprétables (permission refusée malgré sudo, sudo en échec, timeout), de
  sorte que le score ne reflète **que ce qui a pu être réellement mesuré**.

Le référentiel **Debian 13 est entièrement annoté** avec `check_type` (100 %
des contrôles) ; **AlmaLinux 10 et Windows Server 2022 restent à annoter** et
fonctionnent en attendant sur le **repli heuristique**.

**Credentials SSH** : stockés **chiffrés (Fernet)** dans la colonne
`ssh_credentials_enc` (jamais exposés par l'API, seul le booléen `has_credentials`
l'est) et posés via l'**endpoint dédié** `PUT /api/systems/<id>/credentials`
(`{ ssh_user, ssh_password }`), au format relu par le scanner.

> **Mode démo / tests** : un `StubCollector` (sans réseau) permet d'exécuter un
> audit synthétique reproductible sans connexion SSH (`use_stub`), utile pour les
> démonstrations et les tests.

### Limites connues (actuelles)

- **Authentification par mot de passe uniquement** : l'authentification SSH par
  **clé privée** n'est pas encore prise en charge (à venir).
- **Contrôles non vérifiables** : certains contrôles restent **non vérifiables**
  si l'**outil requis est absent** de la machine ou en cas de **droits
  insuffisants** — ils sont exclus du score plutôt que comptés à tort.
- **Contrôles « presence-as-configured »** : quelques contrôles vérifient
  aujourd'hui qu'un **réglage existe** (présence de la directive) mais **pas
  encore sa valeur exacte** ; leur durcissement en comparaison de valeur est
  prévu dans une passe ultérieure.
- **Annotation `check_type` incomplète hors Debian** : AlmaLinux 10 et Windows
  Server 2022 ne sont **pas encore annotés** et reposent sur le repli heuristique.
- **Scanner Windows (WinRM) non implémenté** : seul l'audit Linux via SSH est
  fonctionnel ; les systèmes Windows ne sont pas encore audités.

---

## Architecture du frontend

L'application est construite autour d'un layout principal qui orchestre :
- une **Sidebar** de navigation à gauche (240px)
- une **TopBar** avec breadcrumb et déconnexion (56px)
- une zone de contenu centrale qui accueille les vues via `<router-view />`

Toutes les routes protégées sont des enfants d'`AppLayout`. Seul `/login` reste à la racine, sans layout.

L'authentification est **réellement branchée sur le backend** : le store Pinia `auth.js` appelle `POST /api/auth/login` et persiste l'**access token** (`hardenos_access_token`), le **refresh token** (`hardenos_refresh_token`) et l'utilisateur (`hardenos_user`) dans `localStorage`. L'intercepteur de requête axios (`api/client.js`) ajoute l'access token sur chaque appel ; l'intercepteur de réponse, sur un `401`, tente automatiquement **un** refresh via `POST /api/auth/refresh` puis rejoue la requête — et déconnecte l'utilisateur (purge du `localStorage` + redirection `/login`) si le refresh échoue. Le `logout` appelle `POST /api/auth/logout` pour révoquer le token côté serveur, puis nettoie l'état local même si l'appel échoue.

> Les **systèmes**, les **utilisateurs** et les **audits** sont désormais lus/écrits depuis le backend. Le **moteur d'audit et le scanner SSH** (`/api/audits`) alimentent réellement le détail système, la comparaison d'audits (`/api/comparison`) et les rapports (`/api/reports`). Plus aucune donnée en mock côté frontend.

Le **Dashboard** est **branché sur le backend réel** (store `systems.js` → `GET /api/systems`). Il affiche les KPI réellement disponibles sur le parc (total systèmes, en ligne, Linux, Windows) et un tableau des systèmes réels (hostname, IP, OS, mode de connexion, statut, dernier audit). Filtrage par OS et par statut. Il gère explicitement le **chargement**, l'**erreur** (backend injoignable, avec bouton « Réessayer ») et la **liste vide** (« Aucun système enregistré »).

> Les données d'audit (score de conformité, niveau de risque, nombre de contrôles) sont **désormais produites côté backend** (moteur d'audit + scanner SSH) mais **pas encore affichées dans ce Dashboard** : tant que l'intégration frontend n'est pas branchée, le Dashboard signale chaque machine comme **« non auditée »** plutôt que d'inventer ou d'afficher un zéro ambigu.

La **vue détail système** (`/systems/:id`) est branchée sur `GET /api/systems/<id>` et gère le **chargement**, le **404** (système inexistant → message + retour) et l'**erreur** réseau. Elle affiche :
- **Bandeau système** : hostname (monospace), adresse IP, OS avec icône, statut (point coloré)
- **Carte Informations** : OS/version, mode de connexion, statut, présence d'identifiants SSH et de jeton d'agent (via les booléens `has_credentials` / `has_agent_token` — **jamais** le secret lui-même), date d'ajout
- **Bloc audit** : encart explicite **« Aucun audit disponible pour ce système »** (les scores par domaine, contrôles CIS et historique apparaîtront une fois l'**intégration frontend** des audits backend branchée)

La **vue remédiation** (`/remediation/:auditId`) liste les contrôles non conformes du dernier audit et permet de les corriger :
- **Warning au chargement** : modal de précautions (snapshots VM, backup des configs, accès console) avec option "Ne plus afficher" persistée en `localStorage`
- **Bloc diff** rouge → vert pour chaque contrôle (valeur actuelle / valeur attendue)
- **Script bash** de correction affiché en monospace pour chaque contrôle
- **Dry-run** : simulation sans modification, sortie cyan confirmant ce qui serait changé
- **Appliquer** : correction simulée, bordure verte, sortie de confirmation
- **Rollback** : bouton visible après chaque apply, permet de revenir à l'état précédent (bordure orange), puis de ré-appliquer si besoin
- Note : le rollback est simulé côté frontend. La gestion réelle des snapshots système sera traitée lors de l'implémentation backend.

La **vue comparaison de snapshots** (`/compare`) permet à l'opérateur de visualiser l'évolution de la conformité entre deux audits — typiquement avant / après remédiation. Elle s'articule en quatre sections empilées :
- **Sélecteurs A / B** : deux pickers côte à côte permettent de choisir le système comparé. Pour l'instant chaque sélecteur charge une paire de snapshots mock (avant / après) ; plus tard ces snapshots seront versionnés en BDD par système.
- **Bandeau de score** : deux cercles SVG côte à côte (avant / après) reliés par une flèche directionnelle (▲ vert / ▼ rouge / = gris) indiquant le delta global en points. Les chiffres s'animent à l'ouverture via un tween en `requestAnimationFrame` (ease-out quad).
- **3 cartes de comptage** : Améliorations (vert), Régressions (rouge), Inchangés (gris). Bordure colorée selon la sémantique, grands chiffres en mono.
- **Tableau diff** filtrable : par défaut, n'affiche que les changements (améliorations + régressions) pour la lisibilité. Filtres : *Changements / Améliorations / Régressions / Inchangés / Tout*. Colonnes ID, Titre, AVANT (StatusBadge), APRÈS (StatusBadge), Évolution (icône + label colorés).

Le calcul de la diff vit dans un utilitaire pur `frontend/src/utils/auditDiff.js` (et non dans un store) — c'est une fonction sans état, réutilisable plus tard côté Dashboard ou Rapports. La catégorisation s'appuie sur un rang de sévérité (`pass=0, na=0, warn=1, fail=2`) qui couvre uniformément toutes les transitions, y compris `fail→warn` (amélioration) et `warn→fail` (régression).

La **vue rapports** (`/reports`) présente le rapport de conformité d'un audit. On choisit une **machine** (`GET /api/systems`) puis **un de ses audits terminés** (`GET /api/audits?system_id=`), et le rapport est assemblé par le backend via **`GET /api/reports/<audit_id>`**. L'aperçu est structuré du général au détail : **synthèse** (score global `/100` via `ScoreGauge`, niveau de risque via `RiskBadge`, compteurs conformes / non conformes / avertissements / non vérifiables / total) ; **scores par domaine** (`DomainRadar` + barres) ; **non-conformités mises en avant** (chaque contrôle `fail` avec observé vs attendu et sa **recommandation de remédiation** issue du référentiel CIS) ; puis le **reste en secondaire** (conformes, avertissements, non vérifiables repliés). Accessible à **tous les rôles** (lecture) et **indépendant de l'OS** — une machine Windows produit un rapport identique à une Linux.

Le rapport backend joint la **remédiation par contrôle** depuis le référentiel YAML du système (résolution `os_family`, mêmes règles que l'audit) et calcule les **compteurs** depuis les résultats. Trois **exports**, générés côté client dans `frontend/src/services/exportService.js` (`generateJSON`, `generateCSV`, `generateHTML`, `downloadFile`, `estimateSize`, `buildFilename` — fonctions pures) et téléchargés via `Blob` (`hardenos_<host>_<timestamp>.<ext>`) : **JSON** (structuré meta/system/audit/summary/controls), **CSV** (une ligne par contrôle) et **HTML** — un **document autonome** (styles inline, aucune dépendance à l'app) **optimisé pour l'impression** (`@media print`) et donc **convertible en PDF via « Imprimer → Enregistrer en PDF »** du navigateur. **Les trois exports incluent la recommandation de remédiation.** Il n'y a **pas de génération PDF serveur** : le HTML imprimable couvre ce besoin.

La **vue gestion utilisateurs** (`/users`) est **réservée aux administrateurs** et **branchée sur le backend réel** (`/api/users`, store `users.js`). Elle affiche le parc de comptes (rôle, dernière connexion, statut) avec filtres rôle / statut, et permet de : **créer** un compte (email, rôle, mot de passe initial), **modifier** un compte (rôle, email, **réinitialisation du mot de passe**), **révoquer / réactiver** (un compte révoqué ne peut plus se connecter, l'action est réversible), et **supprimer définitivement** (irréversible, confirmation via `ConfirmDialog` en bouton *danger*). Trois rôles : `admin`, `auditor`, `readonly`, matérialisés par le composant `RoleBadge`.

Les **garde-fous de sécurité** sont appliqués côté backend et remontés fidèlement dans l'UI (message d'erreur clair en toast, sans faux « succès ») : un admin **ne peut ni se supprimer ni se révoquer lui-même**, et **le dernier administrateur actif est protégé** (impossible à supprimer, révoquer, ou rétrograder vers un rôle non-admin). Sur sa propre ligne, l'admin ne voit **aucune action** (un tag *vous* les remplace) : il gère son propre compte via l'écran « Mon compte ».

L'écran **« Mon compte »** (`/account`) est accessible à **tous les rôles** (admin, auditor, readonly) via un clic sur son email dans la TopBar. Il affiche ses infos (email, **rôle en lecture seule**, statut) et permet de **modifier son propre email** et **son propre mot de passe** — chaque modification exigeant une **re-confirmation du mot de passe actuel** (une action sensible ne repose pas sur le seul token). Le **rôle n'y est jamais modifiable** (seuls les endpoints admin le changent), et les erreurs backend (mauvais mot de passe actuel, email déjà pris) s'affichent clairement.

L'accès à `/users` est gardé par le navigation guard du router : la route déclare `meta.role: 'admin'`, et toute tentative d'accès depuis un compte non-admin **redirige vers `/dashboard`** avec une notification d'erreur — l'entrée de menu « Utilisateurs » est par ailleurs **masquée** pour les non-admins. Le rendu des notifications est centralisé dans `AppLayout` (toast en bas-droite, transition fade + slide), donc toute vue peut notifier sans renderer local.

---

## Design system

Ambiance dark inspirée des outils SOC/SIEM industriels.

| Élément | Valeur |
|---|---|
| Fond principal | `#0d1117` |
| Surface | `#161b22` |
| Accent | `#00d4aa` (vert conformité) |
| Police UI | DM Sans |
| Police technique | JetBrains Mono |

Toutes les valeurs sont centralisées dans `frontend/src/assets/styles/tokens.css` et utilisables via `var(--nom-token)`.

---

## Lancer le projet (dev)

Le login étant désormais réel, il faut lancer **le backend et le frontend en parallèle** (deux terminaux).

**Terminal 1 — backend** (port 5001 ; le port 5000 est pris par AirPlay sur macOS) :
```bash
cd backend
source venv/bin/activate
python wsgi.py
# → http://localhost:5001
```
Voir [`backend/README.md`](backend/README.md) pour l'installation et la création du premier admin (`flask create-admin`).

**Terminal 2 — frontend** :
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
# → http://localhost:5173
```

Le proxy Vite redirige `/api` vers `http://localhost:5001`. L'application redirige automatiquement vers `/login` ; il faut s'authentifier avec un compte réel créé dans le backend.

---

## Roadmap

- [x] Initialisation structure frontend Vue.js
- [x] Design system & tokens CSS
- [x] Stores Pinia avec données mock
- [x] Navigation guards & routing
- [x] Composants de layout (Sidebar, TopBar, AppLayout)
- [x] Vue Login fonctionnelle (mock auth)
- [x] Vue Dashboard avec KPI et liste systèmes
- [x] Composants atomiques (RiskBadge, SystemCard, StatusBadge, DomainBar)
- [x] Vue détail système (infos réelles ; radar des 6 domaines et tableau CIS prêts, en attente des données d'audit)
- [x] Vue remédiation (dry-run, apply, rollback, warning précautions)
- [x] Vue comparaison de snapshots (diff statuts, score animé, filtres)
- [x] Vue rapports — aperçu structuré (synthèse, domaines, non-conformités + remédiation) sur audits réels
- [x] Vue gestion utilisateurs (CRUD, rôles, garde admin, toast global)
- [x] Backend — gestion utilisateurs admin (`/api/users` : lister, créer, modifier rôle/email/mot de passe, révoquer/réactiver, supprimer) avec garde-fous (pas d'auto-suppression, protection du dernier admin actif)
- [x] Backend — self-service « Mon compte » (`/api/account` : email + mot de passe avec re-confirmation ; rôle non modifiable)
- [x] Intégration frontend gestion utilisateurs ↔ backend (page Utilisateurs réservée aux admins + écran « Mon compte » pour tous)
- [x] Backend — socle MVC (Flask + SQLAlchemy + Alembic + connexion PostgreSQL)
- [x] Backend — authentification JWT (access/refresh, bcrypt, rôles, CLI admin)
- [x] Backend — CRUD systèmes (gestion du parc, credentials SSH chiffrés Fernet)
- [x] Référentiels CIS — 300 contrôles YAML (Debian 13, AlmaLinux 10, Windows Server 2022)
- [x] Backend — moteur d'audit + scoring CIS (6 domaines, niveau de risque)
- [x] Scan Linux réel via SSH (Paramiko, lecture seule, sudo optionnel, async)
- [x] Classification déclarative `check_type` — Debian 13 et AlmaLinux 10 annotés
- [x] Scan Windows (Server 2022, WinRM)
- [ ] Authentification SSH par clé (en plus du mot de passe)
- [ ] Backend — remédiation (dry-run / apply, logs de traçabilité)
- [x] Intégration auth frontend ↔ backend (login réel, gestion JWT access/refresh)
- [x] Intégration affichage systèmes frontend ↔ backend ( Dashboard + détail)
- [x] Intégration CRUD systèmes côté frontend (création / édition / suppression depuis l'UI)
- [x] Intégration des données d'audit frontend ↔ backend (audits, rapports)
- [x] Backend — assemblage du rapport d'un audit (`/api/reports` : synthèse, compteurs, contrôles + remédiation jointe au référentiel CIS)
- [x] Exports de rapport JSON / CSV / HTML autonome imprimable (PDF via impression navigateur ; pas de génération PDF serveur)
- [ ] Humanisation visuelle (status bar, densité, raffinements)
- [ ] Déploiement air-gapped

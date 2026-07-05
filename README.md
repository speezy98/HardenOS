# HardenOS

HardenOS est un scanner de conformité qui audite des serveurs Linux et Windows
au regard des référentiels **CIS Benchmark**, attribue un score de conformité par
domaine de sécurité, et corrige les écarts constatés — avec sauvegarde préalable
et possibilité de retour arrière.

L'outil couvre le cycle complet : inventaire du parc, collecte des contrôles sur
la machine réelle, scoring pondéré, rapport de conformité exportable, remédiation
(unitaire ou groupée), annulation, et comparaison de deux audits pour mesurer
l'effet du durcissement.

---

## Sommaire

- [Fonctionnement d'ensemble](#fonctionnement-densemble)
- [Stack technique](#stack-technique)
- [Référentiels CIS](#référentiels-cis)
- [Collecte : SSH pour Linux, agent pour Windows](#collecte--ssh-pour-linux-agent-pour-windows)
- [Scoring](#scoring)
- [Remédiation, sauvegarde et retour arrière](#remédiation-sauvegarde-et-retour-arrière)
- [Sécurité](#sécurité)
- [Rapports et comparaison d'audits](#rapports-et-comparaison-daudits)
- [Interface](#interface)
- [API HTTP](#api-http)
- [Structure du dépôt](#structure-du-dépôt)
- [Installation](#installation)
- [Limites connues](#limites-connues)
- [Feuille de route](#feuille-de-route)
- [Licence](#licence)

---

## Fonctionnement d'ensemble

Trois composants, déployés séparément :

```
    ┌───────────────┐   JWT / HTTPS   ┌───────────────┐   SQLAlchemy   ┌──────────────┐
    │   Frontend    │ ◄─────────────► │    Backend    │ ◄────────────► │  PostgreSQL  │
    │    Vue 3      │                 │  Flask (API)  │                │      16      │
    └───────────────┘                 └───────┬───────┘                └──────────────┘
                                              │
                        ┌─────────────────────┴─────────────────────┐
                        │                                           │
                 SSH (Paramiko)                            HTTPS + token d'agent
                  lecture seule                            (scripts signés Ed25519)
                        │                                           │
                        ▼                                           ▼
              ┌───────────────────┐                     ┌──────────────────────┐
              │   Serveur Linux   │                     │    Agent Windows     │
              │  Debian / RHEL    │                     │  service, port 8585  │
              └───────────────────┘                     └──────────────────────┘
```

Le **backend** est la seule source de vérité : il détient les référentiels CIS,
calcule les scores, signe les scripts de remédiation et journalise chaque action.
Le frontend n'est qu'une vue — aucune donnée d'audit n'y est fabriquée. Les
machines cibles, elles, ne décident jamais de ce qu'elles exécutent : un serveur
Linux reçoit des commandes d'audit en lecture seule via SSH, et un agent Windows
refuse tout script dont il ne peut pas vérifier la signature.

La distinction entre les deux OS s'arrête à la collecte. Une fois les résultats
en base, tout le reste — scoring, rapport, comparaison, journalisation — est
strictement agnostique : un rapport Windows et un rapport Debian ont la même
forme et suivent le même chemin de code.

---

## Stack technique

| Composant | Technologies |
|---|---|
| Frontend | Vue 3 (Composition API), Pinia, Vue Router 4, Vite 5, axios, Chart.js |
| Backend | Python 3.11, Flask 3, SQLAlchemy 2, Flask-Migrate (Alembic), Flask-JWT-Extended |
| Base de données | PostgreSQL 16 |
| Collecte Linux | Paramiko (SSH, lecture seule) |
| Collecte Windows | Agent autonome (`http.server`, service Windows via pywin32) |
| Cryptographie | `cryptography` — Fernet (secrets au repos), X.509 (PKI interne), Ed25519 (signature de scripts) |
| Référentiels | YAML (PyYAML) |

---

## Référentiels CIS

Le moteur d'audit s'appuie sur **300 contrôles** décrits en YAML dans
[`backend/cis_rules/`](backend/cis_rules/), à raison de 100 par système
d'exploitation :

| Fichier | Système | Source |
|---|---|---|
| `debian13.yaml` | Debian 13 (couvre aussi Ubuntu 22.04 / 24.04) | CIS Debian Linux 13 Benchmark v1.0.0 |
| `almalinux10.yaml` | AlmaLinux 10 (couvre aussi RHEL et Rocky 9 / 10) | CIS AlmaLinux OS 10 Benchmark v1.0.0 |
| `windows_server2022.yaml` | Windows Server 2022 | CIS Microsoft Windows Server 2022 Benchmark v5.0.0 |

Les contrôles retenus sont ceux que les benchmarks officiels classent comme
automatisables, sélectionnés en priorisant les impacts `critical` et `high`, puis
répartis sur six domaines : `access`, `network`, `logging`, `crypto`, `updates` et
`services`. Chacun est rattaché à une technique MITRE ATT&CK, et quelques-uns à
une CVE documentée lorsque le lien est direct (Baron Samedit `CVE-2021-3156` côté
Linux, PrintNightmare `CVE-2021-34527` et SMBv1 / EternalBlue `CVE-2017-0144` côté
Windows).

Un contrôle décrit son identifiant CIS, son domaine, son niveau (L1/L2), son
poids, son impact, la commande d'audit à exécuter, la valeur ou la condition
attendue, le script de remédiation associé, et le contexte de menace.

Ajouter des contrôles ou prendre en charge un nouveau référentiel se fait
**en éditant ou en déposant un fichier YAML**, sans toucher au code : le
`rules_loader` dérive dynamiquement la liste des familles auditables des fichiers
présents dans le dossier, et le formulaire d'ajout de machine s'y adapte seul.

---

## Collecte : SSH pour Linux, agent pour Windows

Le moteur d'audit ne connaît qu'une interface, `BaseCollector`. Trois
implémentations la satisfont, ce qui rend le scoring indifférent à la manière dont
les données ont été obtenues.

### Linux — connexion SSH sortante, en lecture seule

Le `SSHCollector` ouvre **une seule connexion** Paramiko vers la machine cible et
y exécute les commandes d'audit du référentiel, en collectant `stdout`, `stderr` et
le code de sortie. Il n'écrit rien : la remédiation est un chemin distinct,
déclenché explicitement.

Quand le compte SSH n'est pas root mais sudoer, le drapeau `use_sudo` du système
fait passer les commandes par `sudo -S -p ''` : le mot de passe transite par
l'entrée standard et **n'apparaît jamais** dans la ligne de commande, ni dans les
résultats, les journaux ou les messages d'erreur.

L'audit s'exécute en arrière-plan (thread avec contexte applicatif et session
SQLAlchemy dédiés). Le déclenchement renvoie immédiatement un audit en statut
`running`, qui bascule ensuite vers `done` ou `error` — ce dernier accompagné d'un
message court et volontairement non sensible.

L'interprétation de la sortie est **déclarative**. Chaque contrôle porte un champ
`check_type` qui fait autorité et détermine le sens de l'évaluation :

- `comparison` : la sortie est comparée à `audit.expected` ;
- `presence` : le réglage doit exister — son absence est une non-conformité ;
- `absence` : le réglage ne doit pas exister — sa présence est une non-conformité ;
- `manual` : contrôle non évaluable par une machine, remonté en avertissement sans
  jugement de conformité.

Un contrôle dépourvu de `check_type` retombe sur une heuristique par mots-clés,
conservée pour compatibilité. Les référentiels Debian et AlmaLinux sont annotés
(respectivement 99 et 100 contrôles sur 100).

### Windows — agent local, résultats poussés vers le backend

Windows ne se prête pas au même modèle : l'agent HardenOS est un service Windows
qui écoute sur le port 8585 et exécute les contrôles PowerShell localement, puis
**pousse** ses résultats vers `POST /api/agent/audit`. Le backend l'appelle pour
déclencher un scan, exécuter un script de remédiation, rejouer un contrôle,
sauvegarder ou restaurer — jamais pour lire des secrets.

L'agent télécharge son référentiel depuis le backend (`GET /api/rules/<os>`), ce
qui garantit qu'il audite exactement les mêmes règles que celles servant au
scoring, sans copie de fichier à maintenir sur chaque machine.

Deux modes d'appairage, tous deux menant au même état :

- **Ajout depuis l'interface** : le backend contacte l'agent sur `:8585/setup` et
  lui pousse `system_id`, `agent_token` et le certificat public de la CA. Si l'agent
  ne répond pas, l'entrée créée en base est annulée — pas de machine fantôme.
- **Auto-enregistrement** : l'agent contacte le backend au premier démarrage avec un
  jeton d'enregistrement partagé (`X-Registration-Token`), et reçoit en retour son
  `system_id` et son `agent_token`.

### Mode démonstration

Un `StubCollector` produit un audit synthétique reproductible (paramétrable par
`seed`) sans aucune connexion réseau. Il sert aux démonstrations et aux tests, et
s'exécute de façon synchrone.

### Statut de joignabilité

L'état en ligne / hors ligne d'une machine est vérifié **à la consultation**, par
une poignée de main TCP (port 22 pour Linux, 8585 pour Windows), sans
authentification ni échange applicatif. Le ping ICMP a été écarté : trop souvent
filtré, il produit des faux « hors ligne » sur des machines parfaitement joignables.
Le port testé est aussi celui dont dépend l'audit, ce qui rend l'indicateur
réellement prédictif.

---

## Scoring

Le score d'un domaine est le rapport entre le crédit obtenu et le poids total des
contrôles évaluables :

```
score_domaine = Σ(crédit × poids) / Σ(poids)   ×  100
```

Un contrôle conforme vaut son poids entier, un avertissement la moitié, une
non-conformité rien. Les contrôles **non vérifiables** (`na`) sont exclus du
numérateur *comme* du dénominateur : le score ne reflète que ce qui a pu être
réellement mesuré, plutôt que de pénaliser une machine pour un outil manquant.

Le score global agrège l'ensemble des contrôles selon la même formule, et détermine
le niveau de risque : `low` à partir de 90, `moderate` à partir de 70, `high` à
partir de 50, `critical` en deçà.

Le statut `na` est réservé aux véritables échecs d'exécution — permission refusée
malgré `sudo`, `sudo` en échec, dépassement de délai. Une sortie ambiguë n'y donne
pas droit.

---

## Remédiation, sauvegarde et retour arrière

La remédiation applique le script du référentiel CIS aux contrôles en échec, à
l'unité ou par lot. La chaîne est identique sur les deux OS, seul le transport
diffère : SSH pour Linux, agent pour Windows.

**Aucune remédiation ne démarre sans sauvegarde réussie.** C'est une règle
bloquante : si la sauvegarde échoue, la remédiation est annulée et rien n'est
modifié sur la machine — sans filet, on ne touche pas à une configuration de
production.

- Sur Linux, la sauvegarde est une archive de `/etc` créée sur la connexion SSH
  déjà ouverte.
- Sur Windows, l'agent exporte la politique de sécurité locale (`secedit`) et les
  sous-clés de registre effectivement modifiées par les contrôles du référentiel.
  L'export intégral de `HKLM\SOFTWARE` et `HKLM\SYSTEM` a été écarté après essai :
  ces ruches contiennent des clés protégées par TrustedInstaller que `reg import`
  refuse de restaurer, y compris sous SYSTEM.

Après exécution, **chaque contrôle remédié est rejoué immédiatement** sur la même
connexion (ou via l'agent) pour vérifier qu'il est réellement conforme. Le résultat
du rejeu — et non le simple succès du script — décide du statut journalisé, met à
jour l'`AuditResult` correspondant et déclenche un recalcul du score. Un script
qui « réussit » sans corriger le contrôle est donc enregistré comme un échec.

Deux niveaux de retour arrière coexistent :

- **Rollback global** : restauration d'une sauvegarde entière (archive `/etc`, ou
  `secedit` + registre). Il rend la machine à son état antérieur mais ne cible pas
  un réglage précis. Comme il modifie la machine réelle sans toucher aux résultats
  déjà en base, un **nouvel audit est relancé automatiquement** derrière — sans quoi
  le score affiché resterait calculé sur des données devenues fausses.
- **Rollback unitaire** : réexécution d'un script d'annulation capturé *avant* la
  remédiation, qui ne défait que ce contrôle-là. Côté Windows, il couvre le registre,
  `net accounts`, les services, `auditpol`, le pare-feu, Defender, les comptes locaux
  et les fonctionnalités optionnelles ; `secedit` et la mise à jour des signatures
  Defender en restent exclus, faute de mécanisme de lecture/écriture ciblée fiable.

Tout passe par la table `remediation_logs` (mode, script, sortie, statut, auteur,
horodatage). Ces journaux **survivent à la suppression de l'audit associé** — la
clé étrangère passe à `NULL` plutôt que d'entraîner la ligne — afin de préserver la
traçabilité.

Certains contrôles CIS n'ont pas de remédiation automatisable : leur script est en
réalité une consigne rédigée en commentaire. Plutôt que de les ignorer
silencieusement, HardenOS les remonte comme **actions manuelles**, accompagnées de
la condition à satisfaire.

---

## Sécurité

**Authentification et rôles.** Accès par JWT (access token court, refresh token
long), mots de passe hachés avec bcrypt. Trois rôles hiérarchisés : `readonly` <
`auditor` < `admin`. La consultation est ouverte à tous les comptes ; déclencher un
audit ou une remédiation exige `auditor` ; la gestion des utilisateurs et la
suppression d'une machine exigent `admin`. La révocation au logout passe par une
blocklist de `jti`.

**Secrets au repos.** Les identifiants SSH sont chiffrés avec Fernet dans la colonne
`ssh_credentials_enc` et posés par un endpoint dédié. L'API ne les renvoie jamais,
sous aucune forme : elle n'expose que les booléens `has_credentials` et
`has_agent_token`.

**PKI interne.** Une autorité de certification locale signe le certificat serveur
du backend (`flask issue-backend-cert`) et les certificats des agents. Chaque agent
génère sa clé privée **sur sa propre machine** — elle n'en sort jamais — et n'envoie
qu'une CSR. Le backend impose lui-même les SAN du certificat émis, à partir de l'IP
réellement enregistrée en base : un agent ne peut donc pas s'attribuer l'identité
d'un autre en la demandant dans sa CSR. Le TLS sert ici au chiffrement du transport ;
l'authentification applicative reste portée par les tokens.

**Signature des scripts.** Les scripts de remédiation envoyés aux agents Windows
sont signés en Ed25519 par une clé **distincte de la CA TLS** (`flask
issue-signing-key`) — compromettre l'une n'entame pas l'autre. L'agent vérifie la
signature avec la clé publique reçue du backend **avant même d'écrire le script sur
disque** : un script non signé, ou dont la signature ne correspond pas, est rejeté
sans jamais être exécuté.

Enfin, la garde des comptes est appliquée côté serveur et non dans l'interface : un
administrateur ne peut ni se supprimer ni se révoquer lui-même, et le dernier
administrateur actif est protégé contre la suppression, la révocation et la
rétrogradation.

---

## Rapports et comparaison d'audits

Le **rapport de conformité** (`GET /api/reports/<audit_id>`) est assemblé côté
backend : identité de la machine, synthèse (score global, niveau de risque,
compteurs), scores par domaine, et détail des contrôles enrichi de la recommandation
de remédiation, jointe depuis le référentiel YAML par `control_id`. Il est lisible
par tous les rôles.

L'interface le présente du général au particulier — synthèse, radar des six
domaines, non-conformités mises en avant avec valeur observée face à la valeur
attendue, puis le reste replié. Trois exports sont produits côté client : **JSON**
(structuré), **CSV** (une ligne par contrôle) et **HTML** — un document autonome,
sans dépendance à l'application, dont la feuille de style d'impression permet
d'obtenir un PDF via « Imprimer → Enregistrer en PDF ». Il n'y a délibérément pas de
génération PDF serveur : le HTML imprimable couvre ce besoin sans ajouter de
dépendance. Les trois exports embarquent la remédiation.

La **comparaison d'audits** (`GET /api/comparison`) met deux audits terminés face à
face : delta du score global, évolution par domaine, et diff contrôle par contrôle.
La catégorisation repose sur un rang de sévérité (`pass` et `na` = 0, `warn` = 1,
`fail` = 2) qui couvre uniformément toutes les transitions, y compris les cas
intermédiaires comme `fail → warn` (amélioration) ou `warn → fail` (régression). Ce
même rang est appliqué côté frontend, dans `utils/auditDiff.js`, afin que les deux
implémentations ne puissent pas diverger.

---

## Interface

Application Vue 3 en Composition API, organisée autour d'un `AppLayout` (sidebar de
navigation, barre supérieure, zone de contenu). Toutes les routes protégées en sont
enfants ; seul `/login` vit à la racine.

L'authentification est réellement branchée sur le backend. L'intercepteur de requête
axios ajoute l'access token à chaque appel ; l'intercepteur de réponse, sur un `401`,
tente **un** refresh puis rejoue la requête — et déconnecte proprement si le refresh
échoue. Le logout révoque le token côté serveur, puis nettoie l'état local même si
l'appel réseau a échoué.

Les vues couvrent le tableau de bord (KPI du parc, filtres), le détail d'une machine,
la remédiation, la comparaison d'audits, les rapports, la gestion des utilisateurs
(réservée aux administrateurs, avec les garde-fous décrits plus haut) et l'écran
« Mon compte », accessible à tous les rôles, où chacun modifie son email et son mot
de passe — chaque changement exigeant une **re-confirmation du mot de passe actuel**,
parce qu'une action sensible ne doit pas reposer sur la seule possession d'un token.
Le rôle n'y est jamais modifiable.

Côté style, tout passe par des tokens sémantiques (`assets/styles/tokens.css`) :
aucune couleur n'est codée en dur dans un composant. Deux thèmes partagent la même
identité — bleu de marque, ambre d'action, conventions de couleur pour les statuts —
et ne diffèrent que par la clarté des fonds. Le thème sombre est le défaut ; le choix
vit en `sessionStorage` et se réinitialise à la déconnexion. Typographies : Space
Grotesk pour l'interface, JetBrains Mono pour les valeurs techniques.

---

## API HTTP

Toutes les routes de l'API applicative exigent un access token, sauf le login et le
health check. Les routes de l'agent s'authentifient, elles, par `X-Agent-Token`.

| Préfixe | Rôle minimal | Contenu |
|---|---|---|
| `/api/health` | — | Disponibilité de l'API |
| `/api/auth` | — / authentifié | `login`, `refresh`, `logout`, `me` |
| `/api/systems` | `readonly` (lecture), `auditor` (écriture), `admin` (suppression) | Parc de machines, credentials SSH, test de joignabilité |
| `/api/cis-rules/available` | authentifié | Familles et OS auditables, dérivés des YAML présents |
| `/api/audits` | `readonly` (lecture), `auditor` (déclenchement) | Déclenchement, détail, historique |
| `/api/reports/<audit_id>` | `readonly` | Rapport de conformité assemblé |
| `/api/comparison` | `readonly` | Diff de deux audits |
| `/api/users` | `admin` | Création, modification, révocation, suppression |
| `/api/account` | authentifié | Email et mot de passe de son propre compte |
| `/api/agent/*` | token d'agent, ou `auditor` selon la route | Enrôlement, certificat, ingestion d'audit, remédiation, sauvegardes, rollback |
| `/api/rules/<os>` | token d'agent | Distribution du référentiel CIS à l'agent |

Le détail des corps de requête et des codes de retour est documenté dans
[`backend/README.md`](backend/README.md).

---

## Structure du dépôt

```
HardenOS/
├── frontend/                   Application Vue 3 (Vite)
│   └── src/
│       ├── api/                Couche axios : client + intercepteurs JWT, un module par ressource
│       ├── stores/             Pinia (auth, systems, audits, users, comparison, ui)
│       ├── views/              Login, Dashboard, SystemDetail, Audit, Remediation, Compare, Reports, Users, Account
│       ├── components/         layout, charts, audit, system, icons, common
│       ├── services/           exportService.js — génération JSON / CSV / HTML autonome
│       ├── utils/              auditDiff.js — diff de deux audits (fonction pure)
│       └── assets/styles/      tokens.css, reset.css, global.css
│
├── backend/                    API Flask (MVC)
│   ├── app/
│   │   ├── controllers/        Blueprints : health, auth, systems, audits, cis_rules, agents, users, account, comparison, reports
│   │   ├── models/             SQLAlchemy : User, System, Audit, AuditResult, Snapshot, RemediationLog
│   │   ├── services/           Logique métier
│   │   │   ├── audit_engine.py     Scoring pondéré, niveau de risque, recalcul post-remédiation
│   │   │   ├── audit_service.py    Orchestration : credentials, choix du collecteur, exécution asynchrone
│   │   │   ├── rules_loader.py     Chargement, cache et résolution des référentiels YAML
│   │   │   ├── agent_ingest.py     Réception et validation des audits poussés par un agent
│   │   │   ├── reachability.py     Test TCP de joignabilité (22 / 8585)
│   │   │   ├── comparison.py       Diff de deux audits
│   │   │   ├── reports.py          Assemblage du rapport + jointure de la remédiation
│   │   │   └── collectors/         BaseCollector, SSHCollector (Paramiko), StubCollector
│   │   ├── utils/
│   │   │   ├── crypto.py           Chiffrement Fernet
│   │   │   ├── pki.py              CA interne, émission de certificats, signature Ed25519
│   │   │   ├── jwt.py              JWTManager + blocklist des tokens révoqués
│   │   │   ├── auth.py             Décorateur role_required (hiérarchie des rôles)
│   │   │   └── ssh_credentials.py  (Dé)chiffrement du couple utilisateur / mot de passe SSH
│   │   ├── cli.py              create-admin, issue-backend-cert, issue-signing-key
│   │   └── config.py           Configurations dev / prod / test
│   ├── cis_rules/              debian13.yaml, almalinux10.yaml, windows_server2022.yaml
│   └── migrations/             Alembic
│
└── agent/                      Agent Windows (service, port 8585)
    ├── hardenos_agent.py       Serveur HTTP(S), bascule TLS à chaud, service pywin32
    ├── collector.py            Exécution des contrôles PowerShell et évaluation
    ├── remediate.py            Vérification de signature Ed25519 puis exécution
    ├── backup.py               Sauvegarde secedit + registre
    ├── undo.py                 Capture du script d'annulation ciblé
    ├── tls.py                  Clé privée locale, CSR, certificat
    └── register.py             Enrôlement et récupération du certificat
```

---

## Installation

### Backend

Prérequis : Python 3.11 et un accès réseau à PostgreSQL 16.

```bash
cd backend
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
```

Renseigner ensuite le `.env` : identifiants PostgreSQL, `SECRET_KEY`,
`JWT_SECRET_KEY` et `FERNET_KEY`. Les deux premières se génèrent avec
`python -c "import secrets; print(secrets.token_hex(32))"`, la troisième avec
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
Sans `FERNET_KEY`, l'enregistrement d'identifiants SSH échoue.

Appliquer les migrations, créer le premier administrateur, puis démarrer :

```bash
flask --app wsgi db upgrade
flask --app wsgi create-admin
python wsgi.py          # http://localhost:5001
```

Le port 5001 est retenu parce que le 5000 est occupé par AirPlay sur macOS. Le
serveur passe automatiquement en HTTPS si `BACKEND_TLS_CERT` et `BACKEND_TLS_KEY`
pointent vers des fichiers existants, et reste en HTTP sinon — un clone neuf
fonctionne donc sans certificat.

### Frontend

```bash
cd frontend
npm install
cp .env.example .env
npm run dev             # http://localhost:5173
```

Le proxy Vite redirige `/api` vers le backend. L'application redirige vers `/login` :
il faut s'authentifier avec un compte réellement créé côté backend.

### PKI (pour les agents Windows)

Une fois la CA en place (`AGENT_CA_KEY` / `AGENT_CA_CERT`), deux commandes à
exécuter une seule fois :

```bash
flask --app wsgi issue-backend-cert --san <ip-ou-hostname-du-backend>
flask --app wsgi issue-signing-key
```

La première émet le certificat serveur HTTPS du backend, la seconde la clé de
signature des scripts de remédiation. La clé publique correspondante est ensuite
distribuée automatiquement aux agents ; il n'y a aucun fichier à copier à la main.

### Agent Windows

Sur la machine cible, en tant qu'administrateur :

```bat
copy agent.conf.example agent.conf
:: renseigner backend_url, puis :
install.bat
```

Le script installe les dépendances, enregistre le service `HardenOSAgent` et le
démarre. `system_id` et `agent_token` sont remplis automatiquement, soit par le
backend lors de l'ajout de la machine depuis l'interface, soit par
l'auto-enregistrement si un `registration_token` est fourni.

---

## Limites connues

- **Blocklist des tokens en mémoire.** La révocation au logout s'appuie sur un `set`
  Python : elle est perdue au redémarrage et n'est pas partagée entre plusieurs
  workers. Suffisant en développement, à remplacer par Redis ou une table en base
  avant une mise en production.
- **SSH par mot de passe uniquement.** L'authentification par clé privée n'est pas
  encore prise en charge.
- **Contrôles « presence-as-configured ».** Quelques contrôles vérifient aujourd'hui
  qu'un réglage existe, sans encore comparer sa valeur exacte.
- **Rollback global non ciblé.** La restauration d'une sauvegarde rend toute la zone
  sauvegardée à son état antérieur, et pas seulement le contrôle concerné. Le rollback
  unitaire couvre ce besoin, mais pas sur toutes les familles de contrôles.
- **Agent Windows en anglais.** Les valeurs renvoyées par `auditpol` sont comparées à
  du texte anglais : la machine doit être en langue d'affichage anglaise.
- **Sauvegarde Windows partielle par conception.** Seules les sous-clés de registre
  réellement modifiées par le référentiel sont exportées (voir plus haut).

---

## Feuille de route

Réalisé :

- Socle backend MVC, PostgreSQL, migrations Alembic
- Authentification JWT, rôles hiérarchisés, gestion des utilisateurs et self-service
- CRUD du parc, chiffrement Fernet des identifiants SSH
- 300 contrôles CIS en YAML, chargeur et catalogue de familles dynamique
- Moteur d'audit et scoring pondéré sur six domaines
- Scanner SSH Linux (lecture seule, sudo optionnel, asynchrone)
- Agent Windows : collecte, enrôlement, ingestion des résultats
- PKI interne : HTTPS backend et agents, signature Ed25519 des scripts
- Remédiation unitaire et groupée sur les deux OS, avec rejeu et journalisation
- Sauvegarde bloquante avant remédiation, rollback global et unitaire
- Rapports de conformité et exports JSON / CSV / HTML
- Comparaison de deux audits

À venir :

- Authentification SSH par clé privée
- Annotation `check_type` du référentiel Windows
- Blocklist de tokens persistante
- Déploiement air-gapped


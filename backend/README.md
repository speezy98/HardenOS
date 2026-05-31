# HardenOS — Backend

API Flask du scanner de conformité CIS HardenOS : structure MVC, app factory
Flask, connexion PostgreSQL, modèles SQLAlchemy, migrations Alembic,
**authentification JWT** (access/refresh tokens, hachage bcrypt, protection des
routes par rôle) et **CRUD des systèmes** (machines cibles, credentials SSH
chiffrés au repos via Fernet). Pas encore de scan ni de scoring.

## Stack

- Python 3.11
- Flask + Flask-SQLAlchemy (ORM SQLAlchemy 2.x)
- Flask-Migrate (Alembic) pour les migrations
- Flask-JWT-Extended (tokens) + bcrypt (hachage des mots de passe)
- cryptography / Fernet (chiffrement symétrique des credentials SSH)
- PostgreSQL 16 (conteneur Docker sur la VM Debian `10.220.0.11:5432`)

> **Port local :** le serveur de dev écoute sur le **port 5001**. Le port 5000
> est occupé par AirPlay sur macOS. Toutes les commandes ci-dessous utilisent
> donc `localhost:5001`.

## Architecture (MVC)

```
backend/
  app/
    __init__.py        App factory Flask (create_app)
    config.py          Configs dev/prod/test + URL PostgreSQL + JWT depuis l'env
    cli.py             Commandes CLI (flask create-admin)
    models/            M — modèles SQLAlchemy (un fichier par entité)
    controllers/       C — Blueprints Flask (health.py, auth.py, systems.py)
    services/          Logique métier (auth.py, systems.py)
    utils/db.py        Instance SQLAlchemy partagée (db)
    utils/jwt.py       JWTManager + blocklist des tokens révoqués
    utils/auth.py      Décorateur role_required (hiérarchie des rôles)
    utils/crypto.py    Chiffrement Fernet des credentials SSH (encrypt/decrypt)
  migrations/          Migrations Alembic / Flask-Migrate
  tests/
  wsgi.py              Point d'entrée (app = create_app())
  requirements.txt
  .env.example
```

Les **vues (V)** du MVC sont assurées par le frontend Vue.js (`../frontend`) ;
le backend expose une API JSON.

## Modèle de données

Six entités : `User`, `System`, `Audit`, `AuditResult`, `Snapshot`,
`RemediationLog`. Règles de suppression :

- Supprimer un **système** → cascade sur ses `audits`, `audit_results` et
  `snapshots`.
- Les **remediation_logs** sont conservés (la FK `audit_id` passe à `NULL`
  via `ON DELETE SET NULL`) pour préserver la traçabilité de sécurité.

## Prérequis

- Python 3.11 (`python3.11 --version`)
- Accès réseau à la base PostgreSQL `10.220.0.11:5432`

## Installation

```bash
cd backend

# 1. Environnement virtuel
python3.11 -m venv venv
source venv/bin/activate

# 2. Dépendances
pip install --upgrade pip
pip install -r requirements.txt

# 3. Configuration
cp .env.example .env
# Éditer .env : renseigner POSTGRES_PASSWORD et SECRET_KEY
```

Variables d'environnement (`.env`) :

| Variable | Rôle |
|---|---|
| `POSTGRES_HOST` | Hôte de la base (`10.220.0.11`) |
| `POSTGRES_PORT` | Port (`5432`) |
| `POSTGRES_DB` | Nom de la base (`hardenos`) |
| `POSTGRES_USER` | Utilisateur (`hardenos`) |
| `POSTGRES_PASSWORD` | **À renseigner** localement |
| `SECRET_KEY` | **À renseigner** (clé Flask) |
| `FLASK_ENV` | `development` / `production` / `testing` |
| `JWT_SECRET_KEY` | Clé de signature JWT — si vide, dérivée de `SECRET_KEY` (clé dédiée recommandée) |
| `JWT_ACCESS_TOKEN_EXPIRES` | Durée de l'access token en secondes (défaut `3600` = 1 h) |
| `JWT_REFRESH_TOKEN_EXPIRES` | Durée du refresh token en secondes (défaut `604800` = 7 j) |
| `FERNET_KEY` | **À renseigner** — clé de chiffrement des credentials SSH (voir ci-dessous) |

L'URL construite est `postgresql://USER:PASSWORD@HOST:PORT/DB`.

## Générer `SECRET_KEY` et `JWT_SECRET_KEY`

`SECRET_KEY` signe les sessions Flask et sert de secret de repli pour les JWT ;
`JWT_SECRET_KEY` signe les tokens d'authentification (access/refresh). Ce
doivent être des valeurs aléatoires cryptographiquement sûres, **jamais**
committées et **différentes entre dev et production**.

Générer une clé (chaîne hexadécimale de 64 caractères, 256 bits d'entropie) :

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Lancer la commande **deux fois** pour obtenir deux clés distinctes et les
placer dans le `.env` local :

```
SECRET_KEY=<première clé générée>
JWT_SECRET_KEY=<seconde clé générée>
```

> `JWT_SECRET_KEY` est facultative : si elle est vide, elle est dérivée de
> `SECRET_KEY` (voir `app/config.py`). Une clé dédiée reste **recommandée**.
> Changer `JWT_SECRET_KEY` invalide tous les tokens déjà émis (reconnexion
> requise).

## Chiffrement des credentials SSH (Fernet)

Les credentials SSH (mot de passe ou clé privée de la machine cible) sont des
secrets : ils ne sont **jamais** stockés en clair ni renvoyés par l'API. Ils
sont chiffrés avec **Fernet** (chiffrement symétrique authentifié) avant
stockage dans la colonne `ssh_credentials_enc`.

Générer une clé une fois et la placer dans le `.env` local (`FERNET_KEY=`) :

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

- À la création/modification d'un système, le credential fourni (`ssh_credentials`)
  est chiffré par `app/utils/crypto.py` (`encrypt`).
- Les réponses de l'API n'exposent jamais le credential ni `ssh_credentials_enc` :
  seulement un booléen `has_credentials`.
- `decrypt` n'est destiné qu'à un **usage interne futur** (le scanner, au moment
  de se connecter à la machine) ; il n'alimente aucune réponse d'API.

> ⚠️ Sans `FERNET_KEY`, créer/modifier un système **avec** credentials échoue
> (les opérations sans credentials restent possibles).

## Migrations

Le dossier `migrations/` est déjà initialisé (`flask db init`). Pour générer
et appliquer la migration initiale (crée les six tables sur la base distante) :

```bash
flask --app wsgi db migrate -m "init schema"
flask --app wsgi db upgrade
```

> L'authentification JWT **n'ajoute aucune table** : elle réutilise la colonne
> `password_hash` du modèle `User` existant. Aucune migration supplémentaire
> n'est nécessaire pour cette fonctionnalité.

## Créer le premier administrateur

Sur une base vierge, aucun compte n'existe. La commande CLi `create-admin`
crée le premier utilisateur (rôle `admin`, status `active`, mot de passe haché
avec bcrypt) :

```bash
# Mode interactif (saisie de l'email et du mot de passe masquée)
flask --app wsgi create-admin

# Ou en passant les options directement
flask --app wsgi create-admin --email admin@hardenos.local --password 'MotDePasseFort!'
```

La commande refuse de créer un compte si l'email existe déjà.

## Lancer le serveur

```bash
python wsgi.py
# → http://localhost:5001
```

## Routes disponibles

### `GET /api/health`

Vérifie la disponibilité de l'API.

```bash
curl http://localhost:5001/api/health
# {"status": "ok"}
```

### Authentification — préfixe `/api/auth`

| Méthode | Route | Protection | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | publique | Reçoit `{email, password}`, retourne `access_token`, `refresh_token` et `user` (id, email, role, status). `401` générique si échec. |
| `POST` | `/api/auth/refresh` | refresh token | Retourne un nouvel `access_token`. |
| `POST` | `/api/auth/logout` | access token | Révoque le token courant (ajout du `jti` à la blocklist). |
| `GET` | `/api/auth/me` | access token | Retourne l'utilisateur authentifié (sans le hash). |
| `GET` | `/api/auth/admin-check` | rôle `admin` | Route de démonstration du décorateur `role_required`. |

**Hiérarchie des rôles** (décorateur `role_required`) :
`readonly` < `auditor` < `admin`. Un `admin` accède donc à toute route
exigeant `auditor` ou `readonly`. Un utilisateur authentifié mais au rôle
insuffisant reçoit un `403`.

**Tokens** : l'access token (courte durée, 1 h) accompagne chaque requête
authentifiée via l'en-tête `Authorization: Bearer <token>`. Le refresh token
(7 j) sert uniquement à obtenir un nouvel access token sans ressaisir le mot
de passe.

### Systèmes — préfixe `/api/systems`

Gestion des machines cibles à auditer. Toutes les routes exigent un access token.

| Méthode | Route | Rôle requis | Description |
|---|---|---|---|
| `GET` | `/api/systems` | authentifié (readonly+) | Liste tous les systèmes (sans credentials, avec `has_credentials`). |
| `GET` | `/api/systems/<id>` | authentifié (readonly+) | Détail d'un système. `404` si inexistant. |
| `POST` | `/api/systems` | `auditor` / `admin` | Crée un système. `201` avec le système (sans credentials). |
| `PUT` | `/api/systems/<id>` | `auditor` / `admin` | Met à jour un système. `404` si inexistant. |
| `DELETE` | `/api/systems/<id>` | `admin` | Supprime un système. `404` si inexistant. |

**Corps JSON (création)** : `hostname`, `ip_address`, `os_type`
(`linux`/`windows`), `os_version`, `connection_mode` (`agentless`/`agent`,
défaut `agentless`), et optionnellement `ssh_credentials` (chiffré au stockage)
et `agent_token`. Les champs obligatoires manquants ou les valeurs d'enum
invalides renvoient un `400` explicite.

**Mise à jour** : seuls les champs présents dans le corps sont modifiés. Si
`ssh_credentials` est **absent**, les credentials existants sont conservés ;
s'il est présent et non vide, ils sont rechiffrés et remplacés.

**Suppression** : supprime en cascade les `audits`, `audit_results` et
`snapshots` du système (`ON DELETE CASCADE`) ; les `remediation_logs` sont
conservés (`audit_id` → `NULL`) pour la traçabilité.

> Le CRUD des systèmes **n'ajoute aucune table ni colonne** : le modèle
> `System` (dont `ssh_credentials_enc`) existe déjà. **Aucune migration** n'est
> nécessaire pour cette fonctionnalité.

## Limitations connues

- **Blocklist des tokens en mémoire** : la révocation au logout s'appuie sur un
  simple `set` Python (`app/utils/jwt.py`). Cette blocklist est **perdue au
  redémarrage du serveur** et n'est pas partagée entre plusieurs processus ou
  workers. Volontairement minimale pour le développement, elle devra être
  remplacée par **Redis** ou une **table en base** en production.

# AzuGet — spécification du protocole, version 1

AzuGet est un **flux de mises à jour statique et signé**. Il n'y a pas de serveur applicatif : des fichiers JSON et des archives, servis par n'importe quel serveur web (nginx sur un Raspberry Pi, GitHub Pages, un CDN). La confiance ne vient pas de l'hébergeur mais d'une **signature Ed25519** vérifiée par le lanceur avec une clé publique qu'il embarque. Un hébergeur compromis peut au pire empêcher une mise à jour, jamais en forger une.

## 1. Vocabulaire

| Terme | Sens |
|---|---|
| **flux** (feed) | une URL de base `B` sous laquelle on trouve `B/v1/...` |
| **projet** | un logiciel distribué, identifié par un `id` : `[a-z0-9][a-z0-9-]{0,63}` (ex. `mon-jeu`, `azuget-demo`) |
| **manifeste** | le JSON qui décrit une version d'un projet et ses fichiers |
| **asset** | un fichier téléchargeable décrit dans un manifeste (archive, installeur, correctif) |
| **hub** | le Raspberry Pi qui reçoit les publications (dépôt git central + boîte de dépôt) |
| **miroir** | une machine qui recopie le flux (manifestes vérifiés + fichiers) et le sert |
| **lanceur** | le programme côté utilisateur qui interroge le flux avant de lancer le jeu |

## 2. Arborescence d'un flux

```
B/v1/index.json            liste des projets et de leur dernière version
B/v1/keys.json             clés publiques actives (rotation)
B/v1/<id>/latest.json      manifeste de la dernière version du canal par défaut
B/v1/<id>/versions.json    historique (du plus récent au plus ancien)
B/v1/<id>/releases/<version>.json   manifeste figé de chaque version
B/v1/<id>/files/<version>/<nom>     copie des fichiers (miroirs seulement, jamais dans git)
B/status.json              état d'un miroir (hôte, date de synchronisation, erreurs, pairs)
B/health                   « ok » (miroirs nginx)
```

**Chaque fichier `*.json` sous `v1/` est accompagné de `*.json.sig`.** Un JSON sans `.sig` valide n'existe pas pour un lanceur.

## 3. Le manifeste

```json
{
  "azuget": 1,
  "project": "azuget-demo",
  "name": "AzuGet - projet de démonstration",
  "channel": "stable",
  "version": "0.1.0",
  "published": "2026-10-23T22:10:00Z",
  "notes": "Première version.",
  "notes_url": null,
  "min_launcher": null,
  "assets": [
    {
      "name": "azuget-demo-0.1.0-windows-x64.zip",
      "platform": "windows-x64",
      "kind": "full",
      "size": 1234,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "urls": [
        "http://omnipi-pi4.local/v1/azuget-demo/files/0.1.0/azuget-demo-0.1.0-windows-x64.zip",
        "https://github.com/<owner>/azuget/releases/download/azuget-demo-v0.1.0/azuget-demo-0.1.0-windows-x64.zip"
      ]
    }
  ]
}
```

| Champ | Obligatoire | Sens |
|---|---|---|
| `azuget` | oui | version du format, toujours `1` ; un lanceur refuse une autre valeur |
| `project` | oui | identifiant ; le lanceur refuse un manifeste dont le projet n'est pas celui attendu |
| `name` | non | nom affiché |
| `channel` | oui | `stable` par défaut ; `beta`, etc. (un canal = un `latest.json` ; v1 n'en sert qu'un) |
| `version` | oui | voir § 6 |
| `published` | oui | date UTC ISO 8601 (`...Z`), sert à l'anti-retour en arrière |
| `notes`, `notes_url` | non | notes de version, texte brut ; lien facultatif |
| `min_launcher` | non | version minimale du lanceur capable d'appliquer cette mise à jour (sinon : « mets d'abord à jour le lanceur ») |
| `assets[]` | oui | liste, éventuellement vide |
| `assets[].name` | oui | nom de fichier : `[A-Za-z0-9][A-Za-z0-9._+-]{0,199}` |
| `assets[].platform` | non | `windows-x64`, `linux-x64`, `any`… (`any` = pour tout le monde) |
| `assets[].kind` | non | `full` (défaut), `delta`, `installer`, `portable`, libre |
| `assets[].size` | oui | taille exacte en octets |
| `assets[].sha256` | oui | empreinte SHA-256 en hexadécimal minuscule |
| `assets[].urls` | oui | URL absolues, par ordre de préférence |

Les champs inconnus sont ignorés par les lanceurs (le format peut s'enrichir sans changer de numéro).

### `versions.json`
```json
{ "azuget": 1, "project": "azuget-demo", "generated": "…",
  "versions": [ { "version": "0.1.1", "channel": "stable", "published": "…", "manifest": "releases/0.1.1.json" }, … ] }
```

### `index.json`
```json
{ "azuget": 1, "generated": "…",
  "projects": [ { "id": "azuget-demo", "name": "…", "channel": "stable", "version": "0.1.1", "published": "…", "manifest": "azuget-demo/latest.json" } ] }
```

### `keys.json`
```json
{ "azuget": 1, "generated": "…",
  "keys": [ { "key_id": "1d7f8d4df56c906a", "pubkey": "<64 hexadécimaux>", "status": "active", "since": "…" } ] }
```

## 4. Signature

* Algorithme : **Ed25519** (RFC 8032), signature des **octets exacts** du fichier JSON tel qu'il est servi. Aucune canonicalisation côté lanceur : on vérifie ce qu'on a reçu, puis seulement on parse.
* Clé publique : 32 octets, notée en hexadécimal (64 caractères). `key_id` = les 8 premiers octets de SHA-256(clé publique), en hexadécimal (16 caractères).
* Fichier `X.json.sig` :
  ```json
  { "azuget_sig": 1, "alg": "ed25519", "key_id": "1d7f8d4df56c906a", "sig": "<128 hexadécimaux>" }
  ```
* Le producteur (`azuget publish`) écrit les JSON en UTF-8, indentés de 2 espaces, clés triées, fin de ligne `\n` ; cela ne fait pas partie du contrat, seule l'égalité des octets compte.
* **La clé privée ne quitte jamais le PC de publication.** Les Pi, GitHub et les miroirs n'ont que la clé publique. Ils peuvent être compromis sans qu'une mise à jour puisse être forgée.

## 5. Ce que fait un lanceur (algorithme de référence)

L'implémentation de référence est `azuget check` dans `tools/azuget.py` (Python). Un lanceur dans un autre langage reproduit ceci :

1. **Essayer les flux dans l'ordre** configuré (ex. l'adresse du Pi, puis GitHub Pages). Premier flux joignable qui fournit un manifeste valide : on s'arrête là.
2. Télécharger `B/v1/<id>/latest.json` et `latest.json.sig` (quelques Ko ; délai court, 10 à 20 s).
3. **Vérifier la signature** avec les clés publiques embarquées dans le lanceur (plus celles apprises via `keys.json`, § 7). Refus = on ignore ce flux et on passe au suivant.
4. Parser. Refuser si `azuget != 1` ou si `project` n'est pas l'identifiant attendu.
5. **Anti-retour en arrière** : le lanceur mémorise la date `published` du dernier manifeste accepté. Un manifeste plus ancien est refusé (quelqu'un rejoue une vieille version, un miroir est en retard).
6. Si `min_launcher` est présent et supérieur à la version du lanceur : proposer de mettre à jour le lanceur, ne pas appliquer.
7. Comparer `version` à la version installée (§ 6). Plus récente : proposer la mise à jour (ou l'appliquer selon le réglage de l'utilisateur). Le lanceur **démarre le jeu même si aucun flux ne répond** : une panne du flux n'empêche jamais de jouer.
8. Téléchargement d'un asset : essayer d'abord `B/v1/<id>/files/<version>/<nom>` (le miroir qui a servi le manifeste), puis chaque entrée de `urls`. Écrire dans un fichier temporaire, vérifier **taille et SHA-256** avant de s'en servir, puis seulement remplacer.
9. Installer de façon atomique et garder la version précédente pour revenir en arrière.

Codes de sortie de `azuget check` : `0` à jour, `10` mise à jour disponible, `2` erreur (flux injoignables), `3` signature refusée.

## 6. Versions

Grammaire : `N(.N)*` suivi d'un suffixe de pré-version facultatif `-xxx.yyy` et de métadonnées facultatives `+build`. Exemples : `1.2.3`, `0.9`, `1.0.0-beta.2`, `2.0.0-rc.1+win`.

Ordre : comparaison numérique composant par composant (`1.10 > 1.9`), `1.2 == 1.2.0`, une pré-version est **inférieure** à la version finale (`1.0.0-beta < 1.0.0`), les identifiants de pré-version se comparent numériquement s'ils sont numériques, sinon en texte ; `+build` est ignoré. Un `v` initial est toléré en entrée.

## 7. Rotation et perte de clé

* `keys.json` (signé) liste les clés actives. Un lanceur qui fait confiance à une clé K peut adopter une nouvelle clé K' si `keys.json` signé par K la déclare `active`. Pour retirer K : publier `keys.json` sans K (signé par K'), puis une version du lanceur qui n'embarque plus que K'.
* Perdre la clé privée sans en avoir déclaré une seconde = ne plus jamais pouvoir mettre à jour les lanceurs déjà distribués. D'où : **sauvegarde de la clé privée dans un gestionnaire de mots de passe**, et dès qu'un vrai projet est distribué, génération d'une clé de secours gardée hors ligne, déclarée dans `keys.json`.

## 8. Hébergement de référence

* **Source de vérité** : un dépôt git (le « dépôt de flux ») dont le dossier `docs/` contient le flux. Il est hébergé sur le hub (un Raspberry Pi : `/srv/git/azuget.git`, poussé en SSH, servi en lecture seule en HTTP) et sur GitHub, où `docs/` est servi par GitHub Pages ; chaque miroir suit l'un ou l'autre (`source` dans `/etc/azuget/mirror.json`).
* **Fichiers** : déposés par `azuget publish` dans la boîte de dépôt du hub (`/srv/azuget-inbox`, adoptés par le miroir après vérification de l'empreinte) et dans une **GitHub Release** ; chaque URL figure dans `urls`.
* **Miroir** (`azuget mirror`, toutes les 2 min, et immédiatement sur le hub à chaque publication) : clone ou met à jour le dépôt, **vérifie la signature de chaque JSON** avec les clés de `/etc/azuget/mirror.json` (jamais celles du dépôt), ne publie que ce qui est valide, télécharge les fichiers de la dernière version et des `keep_versions - 1` précédentes en vérifiant leur SHA-256, élague le reste, interroge ses pairs et écrit `status.json`.
* **HTTP ou HTTPS** : la signature protège l'intégrité et l'authenticité même en HTTP (réseau local). HTTPS reste souhaitable pour la confidentialité (qui télécharge quoi) : il viendra avec le tunnel (cloudflared / tailscale funnel) ou GitHub Pages.

## 9. Évolution

Un changement incompatible changera le préfixe (`/v2/`) ; `/v1/` restera servi tant que des lanceurs l'utilisent. Les ajouts compatibles (nouveaux champs, nouveaux `kind`) se font sans changer de numéro.

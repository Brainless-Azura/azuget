# AzuGet

Flux de mises à jour **signées** pour les projets d'Azura. Un lanceur demande « y a-t-il une nouvelle version ? », vérifie la réponse avec une clé publique qu'il embarque, puis télécharge des fichiers dont l'empreinte SHA-256 est annoncée. Tout est statique : des fichiers JSON et des archives servis par n'importe quel serveur web (GitHub Pages, un Raspberry Pi derrière nginx, un CDN). Pas de base de données, pas de serveur applicatif.

* Protocole : [SPEC.md](SPEC.md)
* Outil unique : [tools/azuget.py](tools/azuget.py) (Python 3.9 ou plus récent, dépendance `cryptography`)
* Flux public de ce dépôt : <https://brainless-azura.github.io/azuget/v1/index.json>

## 1. Principe

```
poste de publication (clé privée)
   azuget publish ──▶ fichiers : boîte de dépôt du hub (tar/SSH) et/ou GitHub Release
                  ──▶ manifestes signés dans docs/v1/, commit, push vers les dépôts distants
                                   │
          ┌────────────────────────┴───────────────────────┐
   hub Raspberry Pi                                   GitHub
   dépôt git central + nginx                          Pages sert docs/ ; Releases servent les fichiers
   azuget mirror (à chaque push, et toutes les 2 min)
          │
   miroir(s) : azuget mirror suit le hub ou GitHub, recopie manifestes vérifiés et fichiers
          │
   lanceur : GET /v1/<projet>/latest.json + .sig ──▶ vérifie la signature ──▶ télécharge ──▶ vérifie le SHA-256
```

* Le **dépôt de flux** est ce dépôt : `docs/v1/` contient les manifestes et leurs signatures, servis tels quels par GitHub Pages (`main:/docs`) et par les miroirs.
* Un **miroir** (`azuget mirror`) ne sert jamais un JSON dont la signature n'est pas valide avec la clé de sa configuration (`/etc/azuget/mirror.json`), jamais celle du dépôt. Il télécharge les fichiers de la dernière version et des précédentes (`keep_versions`), vérifie leur SHA-256, élague le reste et écrit `status.json`.
* Les fichiers binaires ne vont jamais dans git : ils passent par la boîte de dépôt du hub et par les GitHub Releases.

## 2. Poste de publication

**Installation.** Windows : `powershell -ExecutionPolicy Bypass -File deploy\windows\install-cli.ps1` crée un environnement Python dans `%USERPROFILE%\Tools\azuget\.venv` et pose la commande `azuget` dans `%USERPROFILE%\Tools\bin`. Ailleurs : `python3 -m venv ~/.azuget/venv && ~/.azuget/venv/bin/pip install -r tools/requirements.txt`, puis un alias vers `tools/azuget.py`.

**Clé de signature.** `azuget keygen` écrit `~/.azuget/keys/azuget-signing.key` (privée, lisible par le compte seulement) et `azuget-signing.pub`. La clé privée se sauvegarde dans un gestionnaire de mots de passe et ne se copie jamais sur un serveur : perdue, aucune mise à jour ne peut plus être signée pour les lanceurs qui la connaissent (voir SPEC § 7 pour la rotation).

**Configuration** `~/.azuget/config.json` :

```json
{
  "feed_dir": "<dossier du clone de ce dépôt>",
  "feed_subdir": "docs",
  "key_file": "<chemin>/azuget-signing.key",
  "hub": { "ssh": "<utilisateur>@<hub>", "inbox": "/srv/azuget-inbox", "url": "http://<hub>" },
  "feed_urls": ["https://<compte>.github.io/azuget", "http://<hub>", "http://<miroir>"],
  "kick": ["<utilisateur>@<miroir>"],
  "default_hosts": ["github", "pi"],
  "github_repo": "<compte>/azuget"
}
```

`azuget` appelle `ssh` en mode non interactif (`BatchMode=yes`) : la clé SSH doit être portée par un agent. Pour qu'il demande plutôt la phrase de passe : `"ssh_opts": ["-o", "ConnectTimeout=15"]`.

## 3. Publier une version

```bash
azuget publish --project mon-jeu --version 1.4.0 \
  --name "Mon jeu" \
  --asset "build/mon-jeu-1.4.0-win64.zip|windows-x64|full" \
  --notes-file CHANGELOG-1.4.0.md --wait 120
```

Dans l'ordre : empreintes SHA-256 des fichiers ; téléversement vers la boîte de dépôt du hub et/ou création d'une GitHub Release (`--host pi`, `github` ou `github,pi`) ; vérification que chaque URL publiée répond avec la bonne taille ; écriture de `docs/v1/mon-jeu/releases/1.4.0.json`, `latest.json`, `versions.json`, mise à jour de `index.json` et `keys.json`, chaque fichier signé ; commit `azuget: mon-jeu 1.4.0` ; push vers tous les dépôts distants ; attente que le hub serve la version ; réveil des miroirs ; avec `--wait`, attente que chaque flux de `feed_urls` la serve.

Options : `--dry-run` (montre le manifeste, ne touche à rien), `--channel beta`, `--repo compte/projet` (release dans le dépôt du projet, tag `vVERSION` ; dans le dépôt du flux le tag est `PROJET-vVERSION`), `--force` (réécrire une version), `--force-latest`, `--no-push`, `--no-kick`.

Règles : identifiant de projet en minuscules, chiffres et tirets ; version `1.2.3` ou `1.2.3-beta.1` ; une version déjà publiée n'est pas réécrite sans `--force` ; une version plus ancienne que la dernière n'est pas promue `latest` sans `--force-latest`.

Vérifier tout le flux local : `azuget verify`. État des miroirs : `azuget status`.

## 4. Côté lanceur

Implémentation de référence : `azuget check`.

```bash
azuget check --project mon-jeu --installed 1.3.0             # code 10 = mise à jour disponible, 0 = à jour
azuget check --project mon-jeu --download ./maj --json       # télécharge et vérifie les fichiers
```

Un lanceur dans un autre langage suit [SPEC.md § 5](SPEC.md) : essayer les flux dans l'ordre, vérifier la signature Ed25519 des octets exacts de `latest.json`, refuser un autre projet ou un manifeste plus ancien que le dernier accepté, comparer les versions, télécharger en vérifiant taille et SHA-256, installer de façon atomique en gardant la version précédente, et **lancer le jeu quoi qu'il arrive** si le flux ne répond pas. Des bibliothèques Ed25519 existent partout : libsodium, .NET (NSec, BouncyCastle), Rust (`ed25519-dalek`), Go (`crypto/ed25519`), Python (`cryptography`).

Clé publique du flux de ce dépôt (aussi dans `keys/azuget-signing.pub` et `docs/v1/keys.json`) :

```
key_id 1d7f8d4df56c906a
pubkey 4f2cd390551c4d8ada264e9ca65da96f737be289a6fedbf5c655658f5cd7744f
```

## 5. Hub et miroirs (Raspberry Pi, Debian)

Installation ou mise à jour, en root, depuis une copie de `tools/` et `deploy/` :

```bash
# hub : reçoit les publications (dépôt git central + boîte de dépôt), se synchronise à chaque push
sh deploy/pi/install-mirror.sh --role hub --source http://127.0.0.1/git/azuget.git --pubkey <hex> --public-base http://<hub> --peer http://<miroir>
# miroir : suit le hub (ou GitHub : --source https://github.com/<compte>/azuget.git)
sh deploy/pi/install-mirror.sh --role mirror --source http://<hub>/git/azuget.git --pubkey <hex> --public-base http://<miroir> --peer http://<hub>
```

| Élément | Chemin |
|---|---|
| Outil | `/usr/local/lib/azuget/azuget.py` (lien `/usr/local/bin/azuget`) |
| Configuration | `/etc/azuget/mirror.json` : source git, clés publiques, pairs, `keep_versions`, tailles maximales |
| Racine servie par nginx (port 80) | `/srv/azuget` (site `/etc/nginx/sites-available/azuget`) |
| Boîte de dépôt (hub) | `/srv/azuget-inbox`, groupe `azuget`, l'utilisateur SSH de publication y écrit |
| Dépôt git central (hub) | `/srv/git/azuget.git`, servi en lecture seule sur `/git/azuget.git/` (protocole git « dumb HTTP ») |
| Unités systemd | `azuget-sync.service` (oneshot, compte `azuget` sans droits), `azuget-sync.timer` (2 min), `azuget-sync.path` (hub : à chaque push) |
| État | `/var/lib/azuget/` (clone du flux, `verified.json`) |

```bash
sudo systemctl start azuget-sync.service        # synchroniser maintenant
journalctl -u azuget-sync.service -n 30 -o cat  # journal
curl -s http://127.0.0.1/status.json            # date, erreurs, projets, pairs
```

Le réveil immédiat d'un miroir par `azuget publish` exécute `sudo -n systemctl start azuget-sync.service` sur ce miroir via SSH : prévoir pour l'utilisateur SSH une règle sudoers limitée à cette commande (`<utilisateur> ALL=(root) NOPASSWD: /usr/bin/systemctl start azuget-sync.service`). Sans règle, le réveil échoue proprement et le timer prend le relais.

## 6. GitHub

Une fois, sur le poste de publication : `gh auth login`, puis `azuget github-setup --repo azuget --visibility public`. La commande crée le dépôt, ajoute le distant `github`, pousse le flux, active GitHub Pages sur `main:/docs` et met la configuration à jour (Pages devient le premier flux, les publications vont aussi dans des GitHub Releases). Le dépôt doit être public pour que Pages et les téléchargements anonymes fonctionnent. GitHub Pages met jusqu'à dix minutes à refléter un push.

## 7. Exposer un hub sur Internet

Pas d'ouverture de port sur la box : un tunnel sortant (Cloudflare Tunnel avec un nom de domaine, ou Tailscale Funnel pour un trafic léger) vers le port 80 du hub, HTTPS compris. Les gros fichiers restent de préférence sur GitHub Releases ou un stockage objet si le débit montant de la connexion est faible.

## 8. Limites connues

* HTTP sur le réseau local pour les miroirs tant qu'il n'y a pas de tunnel ; la signature protège déjà l'intégrité, HTTPS vient avec Pages ou le tunnel.
* Un seul canal servi par `latest.json` ; le champ `channel` existe, plusieurs canaux viendront avec `latest-<canal>.json`.
* Pas de mises à jour différentielles (champ `kind` prévu).
* Pas d'alerte quand un miroir tombe : `status.json` de chaque miroir indique si ses pairs répondent.

## 9. Fichiers

```
tools/azuget.py          l'outil (poste de publication et miroirs)
SPEC.md                  le protocole v1
docs/                    le flux servi (GitHub Pages : main:/docs) : v1/index.json, v1/keys.json, v1/<projet>/...
keys/azuget-signing.pub  clé publique du flux
deploy/pi/               installeur, nginx, systemd, configuration modèle
deploy/windows/          installeur du CLI
demo/                    projet de démonstration (make-demo.ps1 construit l'archive)
```

Licence : non définie pour l'instant (tous droits réservés).

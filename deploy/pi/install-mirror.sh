#!/bin/sh
# AzuGet - installe ou met à jour un miroir sur un Raspberry Pi (Debian / Raspberry Pi OS).
# À lancer en root, depuis une copie du dépôt (deploy/pi/ et tools/ côte à côte).
#
#   sh install-mirror.sh --source URL_GIT --pubkey HEX [--role hub|mirror] [--public-base URL]
#                        [--peer URL]... [--push-user omnipi] [--timer 2min]
#
# hub    : ce Pi reçoit les publications (dépôt git central /srv/git/azuget.git, boîte de dépôt
#          /srv/azuget-inbox) et se synchronise dès qu'une publication arrive.
# mirror : ce Pi suit un autre dépôt (le hub ou GitHub) et recopie manifestes et fichiers.
#
# Exemples :
#   hub    : --role hub --source http://127.0.0.1/git/azuget.git --public-base http://omnipi-pi4.local --peer http://omnipi-pi3.local
#   miroir : --source http://omnipi-pi4.local/git/azuget.git --public-base http://omnipi-pi3.local --peer http://omnipi-pi4.local
set -eu

ROLE=mirror; SOURCE=""; PUBKEY=""; PUBLIC_BASE=""; PEERS=""; PUSH_USER=omnipi; TIMER=2min
while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --pubkey) PUBKEY="$2"; shift 2 ;;
    --public-base) PUBLIC_BASE="$2"; shift 2 ;;
    --peer) PEERS="${PEERS:+$PEERS, }\"$2\""; shift 2 ;;
    --push-user) PUSH_USER="$2"; shift 2 ;;
    --timer) TIMER="$2"; shift 2 ;;
    *) echo "argument inconnu : $1" >&2; exit 2 ;;
  esac
done
if [ -z "$SOURCE" ] || [ -z "$PUBKEY" ]; then
  echo "usage : install-mirror.sh --source URL_GIT --pubkey HEX [--role hub|mirror] [--public-base URL] [--peer URL]..." >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then echo "à lancer en root (sudo)" >&2; exit 2; fi
case "$ROLE" in hub|mirror) ;; *) echo "--role doit valoir hub ou mirror" >&2; exit 2 ;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$HERE/../../tools"
if [ ! -f "$TOOLS/azuget.py" ]; then echo "tools/azuget.py introuvable (lance le script depuis une copie complète du dépôt)" >&2; exit 2; fi
if [ -z "$PUBLIC_BASE" ]; then PUBLIC_BASE="http://$(hostname).local"; fi

echo "== paquets"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx git python3 python3-cryptography curl >/dev/null

echo "== compte azuget et dossiers"
if ! id -u azuget >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/azuget --shell /usr/sbin/nologin azuget
fi
install -d -o azuget -g azuget -m 755 /srv/azuget /var/lib/azuget
install -d -o azuget -g azuget -m 2775 /srv/azuget-inbox
install -d -m 755 /etc/azuget /usr/local/lib/azuget /etc/nginx/azuget.d
install -m 755 "$TOOLS/azuget.py" /usr/local/lib/azuget/azuget.py
ln -sf /usr/local/lib/azuget/azuget.py /usr/local/bin/azuget

echo "== /etc/azuget/mirror.json"
sed -e "s|__SOURCE__|$SOURCE|" -e "s|__PUBKEY__|$PUBKEY|" -e "s|__PUBLIC_BASE__|$PUBLIC_BASE|" -e "s|__PEERS__|$PEERS|" \
    "$HERE/mirror.example.json" > /etc/azuget/mirror.json.new
if [ -f /etc/azuget/mirror.json ] && ! cmp -s /etc/azuget/mirror.json /etc/azuget/mirror.json.new; then
  cp /etc/azuget/mirror.json "/etc/azuget/mirror.json.bak-$(date +%Y%m%d%H%M%S)"
fi
mv /etc/azuget/mirror.json.new /etc/azuget/mirror.json
chmod 644 /etc/azuget/mirror.json

if [ "$ROLE" = hub ]; then
  echo "== dépôt git central /srv/git/azuget.git (poussé par $PUSH_USER)"
  if ! id -u "$PUSH_USER" >/dev/null 2>&1; then echo "utilisateur $PUSH_USER inexistant" >&2; exit 2; fi
  usermod -aG azuget "$PUSH_USER"
  install -d -m 755 /srv/git
  if [ ! -d /srv/git/azuget.git ]; then
    install -d -o "$PUSH_USER" -g "$PUSH_USER" -m 755 /srv/git/azuget.git
    runuser -u "$PUSH_USER" -- git init -q --bare --initial-branch=main /srv/git/azuget.git
  fi
  runuser -u "$PUSH_USER" -- git -C /srv/git/azuget.git config receive.updateServerInfo true
  runuser -u "$PUSH_USER" -- git -C /srv/git/azuget.git update-server-info
  chmod -R o+rX /srv/git/azuget.git
  install -m 644 "$HERE/git.conf" /etc/nginx/azuget.d/git.conf
  install -m 644 "$HERE/azuget-sync.path" /etc/systemd/system/azuget-sync.path
else
  rm -f /etc/nginx/azuget.d/git.conf
  if [ -f /etc/systemd/system/azuget-sync.path ]; then
    systemctl disable -q --now azuget-sync.path || true
    rm -f /etc/systemd/system/azuget-sync.path
  fi
fi

echo "== nginx"
install -m 644 "$HERE/azuget-nginx.conf" /etc/nginx/sites-available/azuget
ln -sf /etc/nginx/sites-available/azuget /etc/nginx/sites-enabled/azuget
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable -q nginx
systemctl restart nginx

echo "== systemd"
install -m 644 "$HERE/azuget-sync.service" /etc/systemd/system/azuget-sync.service
sed "s|__TIMER__|$TIMER|" "$HERE/azuget-sync.timer" > /etc/systemd/system/azuget-sync.timer
chmod 644 /etc/systemd/system/azuget-sync.timer
systemctl daemon-reload
systemctl enable -q --now azuget-sync.timer
if [ "$ROLE" = hub ]; then systemctl enable -q --now azuget-sync.path; fi

echo "== première synchronisation"
systemctl start azuget-sync.service || true
systemctl --no-pager --lines=12 status azuget-sync.service || true
echo "== installé : $PUBLIC_BASE/status.json  (rôle $ROLE, source $SOURCE)"

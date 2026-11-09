#!/usr/bin/env bash
set -euo pipefail

stage=/home/marwanserver/ps5-pup14-staging/site
root=/var/www/ps5-research
data=/var/lib/ps5-research
backup="$root/source-backups/pup14-20261020-$(date -u +%H%M%S)"
mkdir -p "$backup/server" "$backup/web/relapse" "$backup/deploy"
cp -a "$root/server/server.py" "$backup/server/server.py"
cp -a "$root/web/index.html" "$backup/web/index.html"
cp -a "$root/web/relapse/launch.js" "$backup/web/relapse/launch.js"
cp -a "$root/deploy/ps5-research.service" "$backup/deploy/ps5-research.service"
cp -a /etc/systemd/system/ps5-research.service "$backup/systemd-ps5-research.service"
cp -a "$root/release-manifest.json" "$backup/release-manifest.json"

install -d -o www-data -g www-data -m 0750 "$root/private/pup14" "$data/pup-source" "$data/pup-runs"
install -o www-data -g www-data -m 0640 /home/marwanserver/ps5-pup14-staging/PS5UPDATE_14.10_RECOVERY.PUP "$data/pup-source/PS5UPDATE_14.10_RECOVERY.PUP"
printf '%s  %s\n' '9f3a0b8811c00ab52b092d2e9f0f13dd4515f018361ff38e4be43fd8c18b21de' "$data/pup-source/PS5UPDATE_14.10_RECOVERY.PUP" | sha256sum -c -
printf '%s  %s\n' 'f76ed6d9ca93fb687dadfcd261900264e4fc57077eee79b6bba02a4d7dcdaad0' "$stage/private/pup14/PS5_1410_RESEARCH_LAN.elf" | sha256sum -c -

install -o www-data -g www-data -m 0644 "$stage/server/server.py" "$root/server/server.py"
install -o www-data -g www-data -m 0644 "$stage/server/pup_bridge.py" "$root/server/pup_bridge.py"
install -o www-data -g www-data -m 0644 "$stage/web/index.html" "$root/web/index.html"
install -o www-data -g www-data -m 0644 "$stage/web/relapse/launch.js" "$root/web/relapse/launch.js"
install -o www-data -g www-data -m 0644 "$stage/deploy/ps5-research.service" "$root/deploy/ps5-research.service"
install -o root -g root -m 0644 "$stage/deploy/ps5-research.service" /etc/systemd/system/ps5-research.service
install -o www-data -g www-data -m 0640 "$stage/private/pup14/PS5_1410_RESEARCH_LAN.elf" "$root/private/pup14/PS5_1410_RESEARCH_LAN.elf"
install -o www-data -g www-data -m 0750 "$stage/private/pup14/pup_unpacker_linux" "$root/private/pup14/pup_unpacker_linux"

python3 - "$root" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
path = root / 'release-manifest.json'
manifest = json.loads(path.read_text(encoding='utf-8'))
for relative in ('server/server.py', 'server/pup_bridge.py', 'web/index.html',
                 'web/relapse/launch.js', 'deploy/ps5-research.service',
                 'private/pup14/PS5_1410_RESEARCH_LAN.elf',
                 'private/pup14/pup_unpacker_linux'):
    manifest['files'][relative] = hashlib.sha256((root / relative).read_bytes()).hexdigest()
manifest['pup14_source_sha256'] = '9f3a0b8811c00ab52b092d2e9f0f13dd4515f018361ff38e4be43fd8c18b21de'
path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
PY

python3 -m py_compile "$root/server/server.py" "$root/server/pup_bridge.py"
systemctl daemon-reload
systemctl restart ps5-research.service
systemctl is-active --quiet ps5-research.service
echo "Deployed. Backup: $backup"

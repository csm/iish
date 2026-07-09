#!/bin/sh
# Fetch the installer-script corpus into corpus/cache/ for analysis and
# (eventually) integration testing. Scripts are pulled from their source
# repos on raw.githubusercontent.com rather than their vanity URLs
# (sh.rustup.rs, get.docker.com, ...) so a single host allowlist works.
# The cache is not committed; re-run this to (re)populate it.
set -eu
cd "$(dirname "$0")"
mkdir -p cache

while IFS='	' read -r name url; do
    case "$name" in \#*|'') continue ;; esac
    if [ -f "cache/$name.sh" ]; then
        echo "have $name"
        continue
    fi
    if curl -fsSL --retry 6 --retry-delay 8 --retry-all-errors \
            --max-time 120 -o "cache/$name.sh" "$url"; then
        echo "OK   $name"
    else
        echo "FAIL $name  $url" >&2
        rm -f "cache/$name.sh"
    fi
done <<'EOF'
rustup	https://raw.githubusercontent.com/rust-lang/rustup/master/rustup-init.sh
nvm	https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh
homebrew	https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh
deno	https://raw.githubusercontent.com/denoland/deno_install/master/install.sh
ohmyzsh	https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh
pnpm	https://raw.githubusercontent.com/pnpm/get.pnpm.io/main/install.sh
volta	https://raw.githubusercontent.com/volta-cli/volta/main/dev/unix/volta-install.sh
starship	https://raw.githubusercontent.com/starship/starship/master/install/install.sh
tailscale	https://raw.githubusercontent.com/tailscale/tailscale/main/scripts/installer.sh
docker	https://raw.githubusercontent.com/docker/docker-install/master/install.sh
k3s	https://raw.githubusercontent.com/k3s-io/k3s/master/install.sh
helm	https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
nix-determinate	https://raw.githubusercontent.com/DeterminateSystems/nix-installer/main/nix-installer.sh
ollama	https://raw.githubusercontent.com/ollama/ollama/main/scripts/install.sh
rvm	https://raw.githubusercontent.com/rvm/rvm/master/binscripts/rvm-installer
zoxide	https://raw.githubusercontent.com/ajeetdsouza/zoxide/main/install.sh
atuin	https://raw.githubusercontent.com/atuinsh/atuin/main/install.sh
EOF

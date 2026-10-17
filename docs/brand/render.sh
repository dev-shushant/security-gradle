#!/usr/bin/env bash
# Re-renders every PNG in docs/brand from the HTML/SVG sources. Needs Google Chrome.
set -euo pipefail
cd "$(dirname "$0")"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
mkdir -p out
shot() { # name width height
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
    --window-size="$2,$3" --screenshot="$PWD/out/$1.png" "file://$PWD/src/$1.html" >/dev/null 2>&1
  echo "out/$1.png"
}
shot banner-linkedin 1584 396
shot social-card 1200 630
shot medium-hero 1400 788
shot attack-vs-block 1200 675
shot architecture 1600 900
"$CHROME" --headless=new --disable-gpu --force-device-scale-factor=1 --window-size=512,512 --default-background-color=00000000 --screenshot="$PWD/out/logo-512.png" "file://$PWD/logo-mark.svg" >/dev/null 2>&1 && echo out/logo-512.png

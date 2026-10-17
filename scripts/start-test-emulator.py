#!/usr/bin/env python3
"""Start one AppArmorX test AVD headlessly in the background, preserving app data.
This launcher refuses a second running emulator to keep local RAM/CPU bounded.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--avd', choices=['Pixel_10a', 'AppArmorX_Rooted_API35'], default='Pixel_10a')
    args = parser.parse_args()
    sdk = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or
               Path.home() / 'Library/Android/sdk')
    emulator = sdk / 'emulator/emulator'
    adb = shutil.which('adb') or str(sdk / 'platform-tools/adb')
    if not emulator.is_file():
        parser.error('Android emulator not found in configured SDK')
    inventory = subprocess.check_output([adb, 'devices'], text=True, timeout=15)
    if any(line.startswith('emulator-') for line in inventory.splitlines()):
        parser.error('An emulator is already running. Stop it before switching AVDs; this tool does not stop devices.')
    # Also catch emulators still booting before they register with ADB (macOS/Linux).
    processes = subprocess.check_output(['ps', '-A', '-o', 'comm='], text=True, timeout=10)
    if any('qemu-system-' in line for line in processes.splitlines()):
        parser.error('An emulator process is still starting/stopping; wait until it exits before retrying.')
    command = [str(emulator), '-avd', args.avd, '-no-window', '-no-audio', '-no-boot-anim',
               '-no-snapshot', '-memory', '2048', '-cores', '2', '-gpu', 'host',
               '-camera-back', 'none', '-camera-front', 'none']
    log = Path(tempfile.gettempdir()) / ('apparmorx-headless-' + args.avd + '.log')
    # Detached launch: never hold a shell/PTY open for the emulator's lifetime.
    with log.open('ab') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
    print(json.dumps({'avd': args.avd, 'pid': process.pid, 'headless': True,
                      'guestMemoryMiB': 2048, 'cores': 2, 'log': str(log),
                      'note': 'Boot is asynchronous. Verify ADB and sys.boot_completed before testing.'}, indent=2))


if __name__ == '__main__':
    main()

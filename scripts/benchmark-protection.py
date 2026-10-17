#!/usr/bin/env python3
"""Prepare a matched, signed minimal-app baseline/protected pair from an independent consumer.
Fixture-only application ID and signer; never modifies the source consumer or installed user apps.
"""
import argparse
import os
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import math
import statistics
import time
import zipfile


def prepare(args):
    source = args.consumer.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise SystemExit('Output must be empty')
    fixture = args.application_id
    if not re.fullmatch(r'com[.]apparmorx[.]consumer[.]benchmark[A-Za-z0-9_]*', fixture):
        raise SystemExit('Application ID must stay in the owned benchmark namespace')
    summary = {'applicationId': fixture, 'artifacts': {}, 'response': 'OBSERVE' if args.observe else 'STANDARD default',
               'scope': 'Minimal rendered Activity with the source consumer dependency graph; warm dependency cache; fixture signer only.',
               'benchmarkOverrides': ['OBSERVE', 'enforceIndeterminate=false', 'failClosedOnStartup=false', 'secureScreen=false'] if args.observe else []}
    main = '''package com.apparmorx.consumer;
public class MainActivity extends android.app.Activity {
 @Override public void onCreate(android.os.Bundle state) {
  super.onCreate(state);
  android.widget.TextView text = new android.widget.TextView(this);
  text.setText("AppArmorX benchmark ready"); text.setTextSize(22);
  setContentView(text);
 }
}
'''
    for mode in ['baseline', 'protected']:
        work = output / mode
        work.mkdir()
        for name in ['gradlew', 'settings.gradle.kts', 'gradle.properties', 'local.properties', 'fixture.jks', 'fixture-rules.pro', 'vendor.jar']:
            shutil.copy2(source / name, work / name)
        shutil.copytree(source / 'gradle', work / 'gradle')
        shutil.copytree(source / 'src', work / 'src')
        (work / 'src/main/java/com/apparmorx/consumer/MainActivity.java').write_text(main)
        build = re.sub(r'applicationId = "[A-Za-z0-9_.]+"', 'applicationId = "' + fixture + '"', (source / 'build.gradle.kts').read_text())
        # Generated consumers may include explicit security DSL. Remove it from the shared
        # input before disabling the plugin or selecting a named benchmark-only posture.
        build = re.sub(r'(?m)^[ \t]*security[ \t]*\{[^\n]*\}[ \t]*\n?', '', build)
        if re.search(r'\bsecurity\s*\{', build):
            raise SystemExit('Unsupported multiline security DSL: use an owned generated consumer')
        if mode == 'baseline':
            build, count = re.subn(r'^\s*id\("com\.apparmorx\.security"\) version "[^"]+"\n', '', build, flags=re.MULTILINE)
            assert count == 1
        elif args.observe:
            build += '\nsecurity { restrictedAction.set("OBSERVE"); enforceIndeterminate.set(false); failClosedOnStartup.set(false); secureScreen.set(false) }\n'
        (work / 'build.gradle.kts').write_text(build)
        with (work / 'build.log').open('w') as log:
            subprocess.run([str(work / 'gradlew'), '-p', str(work), 'assembleRelease', '--configuration-cache',
                            '--configuration-cache-problems=fail', '--no-daemon'], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
        apks = list((work / 'build/outputs/apk/release').glob('*.apk'))
        assert len(apks) == 1
        apk = apks[0]
        summary['artifacts'][mode] = {'path': str(apk), 'bytes': apk.stat().st_size,
            'sha256': hashlib.sha256(apk.read_bytes()).hexdigest()}
        with zipfile.ZipFile(apk) as archive:
            names = archive.namelist()
            dex = b''.join(archive.read(n) for n in names if re.fullmatch(r'classes\d*\.dex', n))
            sdk_present = b'com/apparmorx/runtime/SecurityGuard' in dex
            policy_present = 'assets/apparmorx/policy.properties' in names
            native_present = any(n.endswith('/libapparmorx.so') for n in names)
            assert (sdk_present, policy_present, native_present) == ((False, False, False) if mode == 'baseline' else (True, True, True))
            summary['artifacts'][mode]['sdkInventoryVerified'] = True
        sdk = Path((work/'local.properties').read_text().split('sdk.dir=',1)[1].splitlines()[0])
        signer = sorted((sdk/'build-tools').glob('*/apksigner'))[-1]
        signature = subprocess.check_output([str(signer),'verify','--verbose','--print-certs',str(apk)], text=True)
        (work/'signature.log').write_text(signature)
        certificates = re.findall(r'certificate SHA-256 digest:\s*([a-fA-F0-9]+)', signature)
        assert len(certificates) == 1
        summary['artifacts'][mode]['signerSha256'] = certificates[0].lower()
    assert summary['artifacts']['baseline']['signerSha256'] == summary['artifacts']['protected']['signerSha256']
    summary['sharedMainActivitySha256'] = hashlib.sha256(main.encode()).hexdigest()
    (output / 'prepared.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('Prepared matched rendered-Activity baseline/protected APKs.')


def measure(args):
    prepared = json.loads(args.prepared.read_text())
    package = prepared['applicationId']
    assert re.fullmatch(r'com[.]apparmorx[.]consumer[.]benchmark[A-Za-z0-9_]*', package)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise SystemExit('Output must be empty')
    def adb(*command):
        return subprocess.run(['adb', '-s', args.device, *command], capture_output=True, text=True, timeout=40)
    assert adb('shell', 'getprop', 'sys.boot_completed').stdout.strip() == '1'
    summary = {'status': 'incomplete', 'prepared': prepared, 'samples': [], 'settleSeconds': 3,
               'blockOrder': ['baseline', 'protected', 'protected', 'baseline'] * 2,
               'performanceBudgetEstablished': False, 'hostLoadAverageStart': os.getloadavg(),
               'avd': adb('emu', 'avd', 'name').stdout.splitlines()[0],
               'scope': 'Force-stopped process starts with warm OS caches; minimal rendered Activity; emulator only. OBSERVE is not default blocking-profile performance.',
               'limits': ['No reboot/disk-cold, physical OEM, battery or real host-workload claim.',
                          'am start TotalTime is launch timing, not full business readiness or isolated scan duration.',
                          'PSS sampled after a three-second post-launch settle; CPU ticks cover process lifetime up to sampling.',
                          'OS caches, compilation state, emulator scheduling and host pressure are not fully controlled.',
                          'Warmup after each install excluded; p95 is nearest-rank over twenty included samples per mode.']}
    def save():
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    hz = adb('shell', 'getconf', 'CLK_TCK').stdout.strip()
    summary['clockTicksPerSecond'] = int(hz) if hz.isdigit() else None
    save()
    try:
        for block, mode in enumerate(summary['blockOrder']):
            artifact = prepared['artifacts'][mode]
            assert hashlib.sha256(Path(artifact['path']).read_bytes()).hexdigest() == artifact['sha256']
            install = adb('install', '-r', artifact['path'])
            assert install.returncode == 0 and 'Success' in install.stdout
            installed = adb('shell','pm','path',package).stdout.strip().removeprefix('package:')
            assert installed and adb('shell','sha256sum',installed).stdout.split()[0] == artifact['sha256']
            for iteration in range(6):  # First process start after every install is excluded.
                assert adb('shell', 'am', 'force-stop', package).returncode == 0
                deadline = time.monotonic() + 15
                while True:
                    stopped = not adb('shell', 'pidof', package).stdout.strip()
                    activities = adb('shell', 'dumpsys', 'activity', 'activities').stdout
                    foreground = any('topResumedActivity=' in line and package in line for line in activities.splitlines())
                    if stopped and not foreground:
                        break
                    assert time.monotonic() < deadline, 'Fixture did not finish stopping'
                    time.sleep(0.1)
                started = time.monotonic()
                launch = adb('shell', 'am', 'start', '-S', '-W', '-n', package + '/com.apparmorx.consumer.MainActivity')
                stem = f'{block}-{mode}-{iteration}'
                (output / (stem + '-launch.log')).write_text(launch.stdout + launch.stderr)
                match = re.search(r'TotalTime:\s*(\d+)', launch.stdout)
                assert launch.returncode == 0 and 'Status: ok' in launch.stdout and match
                assert 'LaunchState: COLD' in launch.stdout
                time.sleep(3)
                state = adb('shell', 'dumpsys', 'activity', 'activities').stdout
                assert any('topResumedActivity=' in line and package + '/com.apparmorx.consumer.MainActivity' in line
                           for line in state.splitlines()), 'App did not stay on the benchmark Activity; do not measure a blocked screen'
                pid = adb('shell', 'pidof', package).stdout.strip()
                assert pid.isdigit()
                stat = adb('shell', 'cat', '/proc/' + pid + '/stat')
                cpu_ticks = None
                if stat.returncode == 0 and ')' in stat.stdout:
                    fields = stat.stdout.rsplit(')', 1)[1].split()
                    cpu_ticks = int(fields[11]) + int(fields[12])
                (output / (stem + '-stat.log')).write_text(stat.stdout + stat.stderr)
                memory = adb('shell', 'dumpsys', 'meminfo', package)
                (output / (stem + '-memory.log')).write_text(memory.stdout + memory.stderr)
                pss = re.search(r'TOTAL PSS:\s*([\d,]+)', memory.stdout)
                assert memory.returncode == 0 and pss, 'PSS unavailable; never substitute zero'
                row = {'mode': mode, 'block': block, 'iteration': iteration, 'excludedWarmup': iteration == 0,
                       'pid': int(pid), 'startupTotalTimeMs': int(match.group(1)),
                       'pssKiB': int(pss.group(1).replace(',', '')), 'processCpuTicks': cpu_ticks,
                       'sampleWallSeconds': round(time.monotonic() - started, 3)}
                summary['samples'].append(row)
                save()
            print('Measured block', block + 1, mode, flush=True)
        def stats(values):
            values = sorted(values)
            return {'n': len(values), 'p50': statistics.median(values),
                    'p95NearestRank': values[math.ceil(0.95 * len(values)) - 1], 'min': values[0], 'max': values[-1]}
        summary['statistics'] = {}
        summary['cpuSamplesAvailable'] = {}
        for mode in ['baseline', 'protected']:
            rows = [r for r in summary['samples'] if r['mode'] == mode and not r['excludedWarmup']]
            summary['statistics'][mode] = {key: stats([r[key] for r in rows if r[key] is not None])
                                          for key in ['startupTotalTimeMs', 'pssKiB', 'processCpuTicks']
                                          if any(r[key] is not None for r in rows)}
            summary['cpuSamplesAvailable'][mode] = sum(r['processCpuTicks'] is not None for r in rows)
        summary['hostLoadAverageEnd'] = os.getloadavg()
        summary['status'] = 'measurement-complete'
        save()
        print(json.dumps(summary['statistics'], indent=2), flush=True)
    except Exception as error:
        summary['status'] = 'failed'
        summary['failure'] = str(error)
        save()
        raise
    finally:
        adb('shell', 'am', 'force-stop', package)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--consumer', type=Path)
    group.add_argument('--prepared', type=Path)
    parser.add_argument('--device')
    parser.add_argument('--application-id', default='com.apparmorx.consumer.benchmark20261020', help='Owned benchmark-only fixture ID; use a fresh suffix to preserve earlier fixtures')
    parser.add_argument('--observe', action='store_true', help='Explicit benchmark-only response; needed on a detected emulator')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.prepared:
        if not args.device:
            parser.error('--prepared requires --device')
        measure(args)
    else:
        prepare(args)


if __name__ == '__main__':
    main()

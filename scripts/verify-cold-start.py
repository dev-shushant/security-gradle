#!/usr/bin/env python3
"""Real framework Application dispatch with synthetic initial evidence; restores normal debug APKs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error('Output must be empty')
    summary = {'status': 'incomplete', 'cases': [], 'scope': 'Framework Application dispatch, controlled evidence; no detector-accuracy claim.'}

    def save():
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')

    def adb(*command, timeout=90):
        return subprocess.run(['adb', '-s', args.device, *command], capture_output=True, text=True,
                              timeout=timeout, check=True).stdout

    def build(mode, cold, directory):
        directory.mkdir()
        command = [str(root / 'gradlew'), '-p', str(root / 'sample'), 'assemble' + mode.title(),
                   'assemble' + mode.title() + 'AndroidTest', '-Psample.testBuildType=' + mode,
                   '-Psample.coldStart=' + str(cold).lower(), '-Psample.processDeath=false',
                   '-Psample.restrictedAction=BLOCK_SCREEN', '--configuration-cache', '--configuration-cache-problems=fail']
        with (directory / 'build.log').open('w') as log:
            subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
        artifacts = []
        for path in [root / f'sample/build/outputs/apk/{mode}/apparmorx-sample-{mode}.apk',
                     root / f'sample/build/outputs/apk/androidTest/{mode}/apparmorx-sample-{mode}-androidTest.apk']:
            target = directory / path.name
            shutil.copyfile(path, target)
            artifacts.append(target)
        return artifacts

    def install(artifacts):
        for path in artifacts:
            assert 'Success' in adb('install', '-r', '-t', str(path), timeout=180)

    restore = []
    save()
    try:
        assert adb('get-state').strip() == 'device'
        summary['avd'] = adb('emu', 'avd', 'name').splitlines()[0]
        summary['sdk'] = adb('shell', 'getprop', 'ro.build.version.sdk').strip()
        summary['shellIdentity'] = adb('shell', 'id').strip()
        restore = build('debug', False, output / 'restore-debug')
        for mode in ['debug', 'release']:
            directory = output / mode
            artifacts = build(mode, True, directory)
            install(artifacts)
            for initial in ['pending', 'clear', 'unknown', 'restricted']:
                adb('shell', 'am', 'force-stop', 'com.apparmorx.sample')
                raw = adb('shell', 'am', 'instrument', '-w', '-r', '-e', 'initial', initial,
                          'com.apparmorx.sample.test/com.apparmorx.sample.ColdStartInstrumentation')
                (directory / (initial + '.log')).write_text(raw)
                rows = [json.loads(line.partition('AAX_COLD_START ')[2]) for line in raw.splitlines()
                        if 'AAX_COLD_START ' in line]
                assert len(rows) == 1 and rows[0]['status'] == 'passed', 'Inspect ' + mode + '/' + initial
                row = rows[0]
                denied = mode == 'release' and initial in ['unknown', 'restricted']
                assert row['debuggable'] is (mode == 'debug') and row['initial'] == initial
                assert row['frameworkApplicationDispatch'] and row['requiresFreshProcess'] is denied
                assert row['applicationBodyRuns'] == row['targetLaunches'] == (0 if denied else 1)
                summary['cases'].append({'mode': mode, **row,
                    'artifactSha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts}})
                save()
                print('PASS:', mode, initial, flush=True)
    finally:
        adb('shell', 'am', 'force-stop', 'com.apparmorx.sample')
        if restore:
            install(restore)
            summary['normalRunnerRestored'] = 'com.apparmorx.sample.test/androidx.test.runner.AndroidJUnitRunner' in adb('shell', 'pm', 'list', 'instrumentation')
        save()
    assert summary.get('normalRunnerRestored')
    summary['status'] = 'passed'
    save()


if __name__ == '__main__':
    main()

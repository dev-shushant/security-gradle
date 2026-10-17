#!/usr/bin/env python3
"""Qualify process-local startup tickets across real process termination and own-task relaunch.
Dedicated test instrumentation; synthetic CHECKING/READY evidence, never detector-accuracy proof.
One explicit device, debug + signed minified release, normal debug/JUnit fixture restored afterward.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', required=True)
    parser.add_argument('--mode', choices=['debug', 'release', 'both'], default='both')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = (args.output or Path(tempfile.mkdtemp(prefix='apparmorx-process-death-'))).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error('Output must be empty')
    summary = {'schema': 1, 'status': 'incomplete', 'device': args.device, 'modes': [],
               'scope': 'Controlled CHECKING/READY snapshots; runner terminates an already stopped app process. Same task/root Intent relaunch, not proof of low-memory saved-instance restoration or real cold-start detection.'}
    restore = []

    def save():
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')

    def adb(*commands, timeout=30):
        return subprocess.run(['adb', '-s', args.device, *commands], capture_output=True, text=True,
                              timeout=timeout, check=False)

    def build(mode, directory, protocol):
        directory.mkdir()
        command = [str(root / 'gradlew'), '-p', str(root / 'sample'), 'assemble' + mode.title(),
                   'assemble' + mode.title() + 'AndroidTest', '-Psample.testBuildType=' + mode,
                   '-Psample.processDeath=' + str(protocol).lower(), '-Psample.restrictedAction=BLOCK_SCREEN',
                   '--configuration-cache', '--configuration-cache-problems=fail', '--stacktrace']
        with (directory / 'build.log').open('w') as log:
            subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
        artifacts = []
        for original in [root / f'sample/build/outputs/apk/{mode}/apparmorx-sample-{mode}.apk',
                         root / f'sample/build/outputs/apk/androidTest/{mode}/apparmorx-sample-{mode}-androidTest.apk']:
            target = directory / original.name
            shutil.copyfile(original, target)
            artifacts.append(target)
        return artifacts

    def install(artifacts):
        for artifact in artifacts:
            result = adb('install', '-r', '-t', str(artifact), timeout=180)
            if result.returncode or 'Success' not in result.stdout:
                raise RuntimeError('Install failed; no automatic uninstall: ' + artifact.name)

    def phase(name, session, mode, directory):
        run = adb('shell', 'am', 'instrument', '-w', '-r', '-e', 'phase', name, '-e', 'session', session,
                  'com.apparmorx.sample.test/com.apparmorx.sample.ProcessDeathInstrumentation', timeout=90)
        raw = run.stdout + run.stderr
        (directory / (name + '.log')).write_text(raw)
        results = [json.loads(line.partition('AAX_PROCESS_DEATH ')[2]) for line in raw.splitlines()
                   if 'AAX_PROCESS_DEATH ' in line]
        if run.returncode or len(results) != 1 or results[0].get('status') != 'passed' or results[0].get('phase') != name:
            raise RuntimeError('Process-death protocol failed: ' + mode + '/' + name + '; inspect retained log')
        if results[0].get('debuggable') is not (mode == 'debug'):
            raise RuntimeError('Unexpected target build type')
        return results[0]

    print('Evidence directory:', output, flush=True)
    save()
    try:
        state = adb('get-state')
        if state.returncode or state.stdout.strip() != 'device':
            raise RuntimeError('Explicit device is not ready; diagnose before retrying')
        summary['control'] = {key: adb('shell', 'getprop', key).stdout.strip() for key in
                              ['ro.build.type', 'ro.debuggable', 'ro.build.version.sdk', 'ro.product.cpu.abi']}
        summary['avd'] = adb('emu', 'avd', 'name').stdout.splitlines()[0]
        restore = build('debug', output / 'restore-debug', False)
        for mode in (['debug', 'release'] if args.mode == 'both' else [args.mode]):
            directory = output / mode
            artifacts = build(mode, directory, True)
            install(artifacts)
            session = str(uuid.uuid4())
            row = {'mode': mode, 'artifactSha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts}}
            summary['modes'].append(row)
            prepared = phase('prepare', session, mode, directory)
            row['prepare'] = prepared
            if (not prepared.get('ticketValidBeforeDeath') or not prepared.get('stoppedBeforeFinish') or
                    not prepared.get('allActivitiesStopped') or prepared.get('targetLaunches') != 0):
                raise RuntimeError('Preparation did not establish a live ticket and stopped task')
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                live = adb('shell', 'pidof', 'com.apparmorx.sample')
                if not live.stdout.strip():
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('App process did not disappear before verification')
            row['appProcessAbsentBetweenPhases'] = True
            save()
            verified = phase('verify', session, mode, directory)
            row['verify'] = verified
            if (verified.get('oldPid') != prepared.get('pid') or verified.get('pid') == prepared.get('pid') or
                    verified.get('taskId') != prepared.get('taskId') or not verified.get('originalIntentRestored') or
                    verified.get('ticketValidAfterDeath') is not False or verified.get('targetLaunches') != 0 or
                    verified.get('screen') != 'UNAVAILABLE'):
                raise RuntimeError('Process, task, capability or host-body invariant not established')
            row['passed'] = True
            save()
            print('PASS:', mode, 'old PID', prepared['pid'], 'new PID', verified['pid'],
                  'task', prepared['taskId'], 'old ticket rejected; host body did not run', flush=True)
    finally:
        # Only the owned sample fixture; no device/root changes, user-data wipe or SDK process-kill feature.
        adb('shell', 'am', 'force-stop', 'com.apparmorx.sample')
        if restore:
            try:
                install(restore)
                registration = adb('shell', 'pm', 'list', 'instrumentation').stdout
                if 'com.apparmorx.sample.test/androidx.test.runner.AndroidJUnitRunner' not in registration:
                    raise RuntimeError('Normal JUnit runner not restored')
                summary['debugFixtureRestored'] = True
            except Exception as failure:
                summary['restoreError'] = type(failure).__name__
        save()
    if summary.get('debugFixtureRestored') is not True:
        raise SystemExit('Debug/JUnit fixture restoration incomplete')
    summary['status'] = 'passed'
    save()
    print('Process-death task/Intent protocol passed; normal debug/JUnit fixture restored.', flush=True)


if __name__ == '__main__':
    main()

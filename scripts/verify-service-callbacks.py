#!/usr/bin/env python3
"""Qualify Service callbacks, security UI or startup recovery in debug and signed minified release fixtures.
Uses explicit devices, test-only signing and a known mismatched fixture pin. Restores debug sample.
No publication, rooting, response-policy mutation on installed builds or automatic uninstall.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile


def provider_cases_valid(cases, debuggable):
    states = {'clear': ['READY'] * 3, 'restricted': ['RESTRICTED'] * 3,
              'unknown-pending': ['INDETERMINATE'] * 2 + ['CHECKING'] * 2,
              'cached-client': ['READY', 'RESTRICTED', 'READY'],
              'inherited-library': ['READY', 'READY', 'RESTRICTED', 'READY']}
    if len(cases) != 5 or {c.get('case') for c in cases} != set(states):
        return False
    for case in cases:
        calls = case.get('calls', [])
        if (case.get('debuggable') is not debuggable or case.get('providerInitialized') is not True or
                case.get('libraryProviderInitialized') is not True or
                case.get('uid', 0) < 10000 or case.get('syntheticEvidence') is not True or
                [c.get('observedState') for c in calls] != states[case['case']]):
            return False
        for call in calls:
            if (not isinstance(call.get('expectedAllowed'), bool) or
                    call.get('counterOwner') != ('dependency' if case['case'] == 'inherited-library' else 'project') or
                    call.get('denied') is not (not call['expectedAllowed']) or
                    call.get('hostBodyAfter') != call.get('hostBodyBefore', -1) + int(call['expectedAllowed'])):
                return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', action='append', required=True, help='Explicit serial; repeat for paired controls')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--suite', choices=['service', 'security-ui', 'startup-recovery', 'scan-config', 'provider', 'worker', 'multiprocess', 'remote-worker'], default='service')
    args = parser.parse_args()
    if len(set(args.device)) != len(args.device):
        parser.error('Duplicate serial')
    suite_class, expected_tests = {'service': ('ServiceCallbackQualificationTest', 3),
                                   'security-ui': ('SecurityUiQualificationTest', 5),
                                   'startup-recovery': ('StartupRecoveryQualificationTest', 4),
                                   'scan-config': ('ScanConfigurationQualificationTest', 3),
                                   'provider': ('ProviderOperationQualificationTest', 5),
                                   'worker': ('WorkerEntryQualificationTest', 6),
                                   'multiprocess': ('MultiprocessEnforcementQualificationTest', 1),
                                   'remote-worker': ('RemoteWorkerQualificationTest', 4)}[args.suite]
    root = Path(__file__).resolve().parents[1]
    output = (args.output or Path(tempfile.mkdtemp(prefix='apparmorx-service-qualification-'))).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error('Output must be empty')
    print('Evidence directory:', output, flush=True)
    summary = {'schema': 1, 'suite': args.suite, 'status': 'incomplete', 'tests': []}
    debug_artifacts = []

    def adb(serial, *args, timeout=180):
        return subprocess.check_output(['adb', '-s', serial, *args], text=True, stderr=subprocess.STDOUT, timeout=timeout)

    def install(serial, artifacts):
        for artifact in artifacts:
            result = adb(serial, 'install', '-r', '-t', str(artifact))
            if 'Success' not in result:
                raise RuntimeError('Installation failed; no automatic uninstall: ' + serial)

    try:
        for mode in ('debug', 'release'):
            directory = output / mode
            directory.mkdir()
            tasks = ['assemble' + mode.title(), 'assemble' + mode.title() + 'AndroidTest']
            command = [str(root / 'gradlew'), '-p', str(root / 'sample'), *tasks,
                       '-Psample.testBuildType=' + mode, '-Psample.restrictedAction=BLOCK_SCREEN',
                       '--configuration-cache', '--configuration-cache-problems=fail', '--stacktrace']
            if args.suite in ('multiprocess', 'remote-worker'):
                command.append('-Psample.processQualification=true')
            with (directory / 'build.log').open('w') as log:
                subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
            originals = [root / f'sample/build/outputs/apk/{mode}/apparmorx-sample-{mode}.apk',
                         root / f'sample/build/outputs/apk/androidTest/{mode}/apparmorx-sample-{mode}-androidTest.apk']
            artifacts = []
            for source in originals:
                target = directory / source.name
                shutil.copyfile(source, target)
                artifacts.append(target)
            if mode == 'debug':
                debug_artifacts = artifacts
            hashes = {artifact.name: hashlib.sha256(artifact.read_bytes()).hexdigest() for artifact in artifacts}
            for index, serial in enumerate(args.device):
                install(serial, artifacts)
                raw = adb(serial, 'shell', 'am', 'instrument', '-w', '-r', '-e', 'class',
                          'com.apparmorx.sample.' + suite_class,
                          'com.apparmorx.sample.test/androidx.test.runner.AndroidJUnitRunner', timeout=180)
                (directory / f'device-{index}.log').write_text(raw)
                prefix = {'provider': 'AAX_PROVIDER_EVIDENCE ', 'worker': 'AAX_WORKER_EVIDENCE ', 'multiprocess': 'AAX_MULTIPROCESS_EVIDENCE ', 'remote-worker': 'AAX_REMOTE_WORKER_EVIDENCE '}.get(args.suite, 'AAX_SERVICE_EVIDENCE ')
                cases = [json.loads(line.partition(prefix)[2]) for line in raw.splitlines() if prefix in line]
                passed = bool(re.search(r'OK \(' + str(expected_tests) + r' tests?\)', raw)) and not any(
                    marker in raw for marker in ['FAILURES!!!', 'INSTRUMENTATION_FAILED', 'Process crashed'])
                expected = mode == 'debug'
                if args.suite == 'remote-worker':
                    passed = passed and len(cases) == 4 and {c.get('case') for c in cases} == {'clear', 'denied', 'cleanup', 'async-cleanup'}
                    for case in cases:
                        calls = case.get('calls', [])
                        passed = passed and case.get('debuggable') is expected and case.get('syntheticEvidence') is True
                        passed = passed and len(calls) == {'clear': 2, 'denied': 6, 'cleanup': 1, 'async-cleanup': 1}.get(case.get('case'), -1)
                        for index, call in enumerate(calls):
                            passed = passed and call.get('uid', 0) >= 10000 and call.get('mainPid') != call.get('remotePid')
                            if case['case'] in ('cleanup', 'async-cleanup'):
                                passed = passed and call.get('workState') == 'CANCELLED' and call.get('entered') == 1 and call.get('cleaned') == 1 and call.get('remoteRestrictionSet') is True
                                if case['case'] == 'async-cleanup':
                                    passed = passed and call.get('kind') == 'Async' and call.get('stopped') is True and call.get('stopCallbacks') == 1 and call.get('cancelRequests', 0) >= 1 and call.get('interruptRequests') == 0 and call.get('futureCancelled') is True
                            else:
                                allowed = case['case'] == 'clear' or expected
                                state = 'READY' if case['case'] == 'clear' else ['RESTRICTED', 'INDETERMINATE', 'CHECKING'][index // 2]
                                cleaned = int(allowed and call.get('kind') == 'Coroutine')
                                passed = passed and call.get('allowed') is allowed and call.get('observedState') == state and call.get('constructed', 0) >= 1 and call.get('entered') == int(allowed) and call.get('cleaned') == cleaned and call.get('workState') == ('SUCCEEDED' if allowed else 'FAILED')
                if args.suite == 'multiprocess':
                    passed = passed and len(cases) == 1 and cases[0].get('debuggable') is expected and cases[0].get('syntheticEvidence') is True
                    calls = cases[0].get('calls', []) if cases else []
                    passed = passed and len(calls) == 5 and [c.get('observedState') for c in calls] == ['READY', 'RESTRICTED', 'INDETERMINATE', 'CHECKING', 'READY']
                    for index, call in enumerate(calls):
                        allowed = expected or index in (0, 4)
                        passed = passed and call.get('allowed') is allowed and call.get('binding') == ('bound' if allowed else 'null') and call.get('after') == call.get('before', -1) + int(allowed) and call.get('mainPid') != call.get('secondaryPid') and call.get('uid', 0) >= 10000 and call.get('mainState') == ('RESTRICTED' if index == 4 else 'READY')
                if args.suite == 'service':
                    passed = passed and {case.get('case') for case in cases} == {'manual-callbacks', 'framework-binding', 'framework-start'} and len(cases) == 3 and all(case.get('allowed') is expected for case in cases)
                if args.suite == 'provider':
                    passed = passed and provider_cases_valid(cases, expected)
                if args.suite == 'worker':
                    counts = {'clear': 3, 'restricted': 3, 'coroutine-cleanup': 1,
                              'unknown-pending': 4, 'retry': 1, 'foreground': 2}
                    passed = passed and len(cases) == 6 and {c.get('case') for c in cases} == set(counts) and all(
                        c.get('debuggable') is expected and c.get('uid', 0) >= 10000 and
                        c.get('syntheticEvidence') is True and c.get('assertionsPassed') is True and
                        c.get('ownedRequests') == counts[c['case']] for c in cases)
                summary['tests'].append({'mode': mode, 'serial': serial, 'passed': passed,
                                         'artifactSha256': hashes, 'cases': cases})
                (output / 'summary.json').write_text(json.dumps(summary, indent=2))
                if not passed:
                    raise RuntimeError(args.suite + ' qualification failed: ' + mode + ' / ' + serial + '; inspect retained logs')
                print('PASS:', args.suite, mode, serial, expected_tests, 'tests', flush=True)
    finally:
        # Restore only this tool's own debug fixture, retaining app data and test evidence.
        if args.suite in ('multiprocess', 'remote-worker') and debug_artifacts:
            # The qualification controller must not be left installed after this explicit suite.
            debug_artifacts = []
            try:
                restored = output / 'default-restoration'
                restored.mkdir()
                command = [str(root / 'gradlew'), '-p', str(root / 'sample'), 'assembleDebug',
                           'assembleDebugAndroidTest', '-Psample.testBuildType=debug',
                           '--configuration-cache', '--configuration-cache-problems=fail', '--stacktrace']
                with (restored / 'build.log').open('w') as log:
                    subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
                sources = [root / 'sample/build/outputs/apk/debug/apparmorx-sample-debug.apk',
                           root / 'sample/build/outputs/apk/androidTest/debug/apparmorx-sample-debug-androidTest.apk']
                with zipfile.ZipFile(sources[0]) as apk:
                    manifest = apk.read('AndroidManifest.xml')
                    dex = b''.join(apk.read(n) for n in apk.namelist() if n.endswith('.dex'))
                for name in ['ProcessControlProvider', 'MultiprocessGuardService', 'RemoteAsyncProbeWorker', 'RemoteCoroutineProbeWorker', 'PendingRemoteFuture']:
                    if name.encode() in dex or any(name.encode(encoding) in manifest for encoding in ['utf-8', 'utf-16le']):
                        raise RuntimeError('Qualification component remains in default APK: ' + name)
                for source in sources:
                    target = restored / source.name
                    shutil.copyfile(source, target)
                    debug_artifacts.append(target)
                summary['defaultDebugArtifactsChecked'] = True
                summary['defaultDebugArtifactSha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in debug_artifacts}
            except Exception as error:
                debug_artifacts = []
                print('Default debug restoration build failed:', type(error).__name__, flush=True)
                summary.setdefault('restoreFailures', []).append('default-debug-build')
        if debug_artifacts:
            for serial in args.device:
                try:
                    install(serial, debug_artifacts)
                except Exception as error:
                    print('Debug fixture restoration failed:', serial, type(error).__name__, flush=True)
                    summary.setdefault('restoreFailures', []).append(serial)
            (output / 'summary.json').write_text(json.dumps(summary, indent=2))
        if args.suite in ('multiprocess', 'remote-worker'):
            summary['defaultDebugRestored'] = bool(debug_artifacts) and not summary.get('restoreFailures')
            (output / 'summary.json').write_text(json.dumps(summary, indent=2))
    if summary.get('restoreFailures'):
        raise SystemExit('Debug fixture restoration incomplete')
    summary['status'] = 'passed'
    (output / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(args.suite + ' qualification passed; debug fixture restored. Test-only keep rules were used for release probe APIs.')


if __name__ == '__main__':
    main()

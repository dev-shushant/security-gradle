#!/usr/bin/env python3
"""Run AppArmorX sample qualification on explicitly selected clean and root-enabled AVDs.
Installs only the repository's debug sample/test APKs; never roots a device or changes policy.
Raw instrumentation output and app-sandbox probe observations are retained locally.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clean', help='Explicit production/user-image control serial')
    parser.add_argument('--rooted', help='Explicit isolated root-enabled AVD serial')
    parser.add_argument('--role', choices=['clean', 'rooted'], help='Single-control mode for sequential, lower-memory runs')
    parser.add_argument('--device', help='Explicit serial for --role')
    parser.add_argument('--report-only', action='store_true', help='Run evidence-report test only, not the full suite')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.role or args.device:
        if not args.role or not args.device or args.clean or args.rooted:
            parser.error('Use --role and --device together, without --clean/--rooted')
        devices = [(args.role, args.device)]
    else:
        if not args.clean or not args.rooted or args.clean == args.rooted:
            parser.error('Provide distinct --clean and --rooted serials, or use --role/--device')
        devices = [('clean', args.clean), ('rooted', args.rooted)]
    root = Path(__file__).resolve().parents[1]
    apk = root / 'sample/build/outputs/apk/debug/apparmorx-sample-debug.apk'
    tests = root / 'sample/build/outputs/apk/androidTest/debug/apparmorx-sample-debug-androidTest.apk'
    if not apk.is_file() or not tests.is_file():
        parser.error('Build sample assembleDebug assembleDebugAndroidTest first')
    output = (args.output or Path(tempfile.mkdtemp(prefix='apparmorx-device-matrix-'))).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error('Output directory must be empty')
    print('Evidence directory:', output, flush=True)

    def adb(serial, *commands, timeout=180):
        return subprocess.check_output(['adb', '-s', serial, *commands], text=True, stderr=subprocess.STDOUT, timeout=timeout)

    summary = {'schema': 1, 'apkSha256': hashlib.sha256(apk.read_bytes()).hexdigest(),
               'testApkSha256': hashlib.sha256(tests.read_bytes()).hexdigest(), 'devices': {}}
    for role, serial in devices:
        metadata = {key: adb(serial, 'shell', 'getprop', key).strip() for key in
                    ['ro.build.type', 'ro.debuggable', 'ro.build.version.sdk', 'ro.product.cpu.abi']}
        metadata['shellIdentity'] = adb(serial, 'shell', 'id').strip()
        metadata['avdName'] = adb(serial, 'emu', 'avd', 'name').splitlines()[0].strip()
        if role == 'clean' and (metadata['ro.build.type'] != 'user' or metadata['ro.debuggable'] != '0'
                                or 'uid=0(' in metadata['shellIdentity']):
            raise SystemExit('Clean control does not match the declared non-root production-image baseline')
        if role == 'rooted' and 'uid=0(' not in metadata['shellIdentity']:
            raise SystemExit('Root-enabled control has no verified root shell; configure only the isolated AVD explicitly')
        destination = output / role
        destination.mkdir()
        (destination / 'metadata.json').write_text(json.dumps(metadata, indent=2))
        for path in (apk, tests):
            result = adb(serial, 'install', '-r', str(path))
            if 'Success' not in result:
                raise SystemExit('Fixture installation failed; no automatic uninstall is performed')
        command = ['shell', 'am', 'instrument', '-w', '-r']
        if args.report_only:
            command += ['-e', 'class', 'com.apparmorx.sample.DeviceEvidenceReportTest']
        command += ['com.apparmorx.sample.test/androidx.test.runner.AndroidJUnitRunner']
        raw = adb(serial, *command, timeout=600)
        (destination / 'instrumentation.log').write_text(raw)
        # Preserve evidence even when assertions fail. Never parse adb's exit code as test success.
        try:
            report = adb(serial, 'shell', 'run-as', 'com.apparmorx.sample', 'cat', 'files/apparmorx-device-evidence.json')
            (destination / 'probe-evidence.json').write_text(report)
            report = json.loads(report)
        except (subprocess.SubprocessError, ValueError):
            report = None
        result = re.search(r'OK \((\d+) tests?\)', raw)
        passed = bool(result) and not any(x in raw for x in ['FAILURES!!!', 'INSTRUMENTATION_FAILED', 'Process crashed'])
        root_checks = {k: v for k, v in (report or {}).get('checks', {}).items()
                       if k in ('root-path', 'native-root-path', 'native-root-mount')}
        root_detected = 'DETECTED' in root_checks.values()
        if role == 'clean' and root_detected:
            passed = False  # unexpected root detections on the clean control require investigation
        summary['devices'][role] = {'serial': serial, 'passed': passed,
                                    'rootDetectionEstablished': root_detected,
                                    'tests': int(result.group(1)) if result else None,
                                    'rootChecks': {k: v for k, v in (report or {}).get('checks', {}).items()
                                                   if k in ('root-path', 'native-root-path', 'native-root-mount')},
                                    'note': 'Root-shell capability is not proof that all app-sandbox root probes can observe it.'}
        (output / 'summary.json').write_text(json.dumps(summary, indent=2))
        if not passed or report is None:
            raise SystemExit('Device qualification failed or evidence missing: ' + role + '; inspect retained logs')
        print('PASS:', role, serial, result.group(1), 'tests; probe evidence retained', flush=True)
    print(('Both environments' if len(devices) == 2 else 'Selected environment') +
          ' completed. This is not physical-OEM or Magisk-cloaking qualification.')


if __name__ == '__main__':
    main()

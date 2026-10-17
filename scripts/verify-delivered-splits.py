#!/usr/bin/env python3
"""Install the independent consumer's device-specific AAB splits and exercise delivered JNI.
Explicit local fixture only. No source substitution or additional target R8 keep rules.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', required=True)
    parser.add_argument('--consumer', type=Path, required=True)
    parser.add_argument('--bundletool', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error('Output must be empty')
    consumer = args.consumer.resolve()
    application_id = re.search(r'applicationId = "([A-Za-z0-9_.]+)"', (consumer / 'build.gradle.kts').read_text()).group(1)
    if not re.fullmatch(r'com\.apparmorx\.consumer(?:\.[A-Za-z][A-Za-z0-9_]*)*', application_id):
        parser.error('Only the owned AppArmorX consumer fixture may be targeted')
    probe_id = application_id + '.splitprobe'
    bundles = list((consumer / 'build/outputs/bundle/release').glob('*.aab'))
    if len(bundles) != 1 or not (consumer / 'fixture.jks').is_file():
        parser.error('Expected an independent signed consumer fixture')
    sdk = Path(next(line.partition('=')[2] for line in (consumer / 'local.properties').read_text().splitlines()
                    if line.startswith('sdk.dir=')))
    build_tools = sorted((sdk / 'build-tools').iterdir(), key=lambda p: tuple(int(n) for n in p.name.split('.') if n.isdigit()))[-1]
    android = sdk / 'platforms/android-34/android.jar'
    summary = {'status': 'incomplete', 'device': args.device,
               'scope': 'Device-specific signed splits, target-process JNI execution. Not a detection/prevention or physical-device claim.'}

    def save():
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')

    def run(command, log, timeout=180):
        result = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=timeout)
        (output / log).write_text(result.stdout + result.stderr)
        result.check_returncode()
        return result.stdout

    def adb(*command):
        return ['adb', '-s', args.device, *command]

    def tool(*command):
        return ['java', '-jar', args.bundletool.resolve(), *command]

    save()
    assert run(adb('get-state'), 'device-state.log').strip() == 'device'
    assert run(adb('shell', 'getprop', 'sys.boot_completed'), 'boot.log').strip() == '1'
    summary['avd'] = run(adb('emu', 'avd', 'name'), 'avd.log').splitlines()[0]
    summary['bundleSha256'] = hashlib.sha256(bundles[0].read_bytes()).hexdigest()
    summary['bundletoolSha256'] = hashlib.sha256(args.bundletool.read_bytes()).hexdigest()
    run(tool('get-device-spec', '--device-id=' + args.device, '--output=' + str(output / 'device.json')), 'device-spec.log')
    run(tool('build-apks', '--bundle=' + str(bundles[0]), '--output=' + str(output / 'delivered.apks'),
             '--device-spec=' + str(output / 'device.json'), '--ks=' + str(consumer / 'fixture.jks'),
             '--ks-key-alias=fixture', '--ks-pass=pass:fixture-only', '--key-pass=pass:fixture-only'), 'build-apks.log')
    with zipfile.ZipFile(output / 'delivered.apks') as archive:
        summary['generatedApks'] = {n: hashlib.sha256(archive.read(n)).hexdigest()
                                    for n in archive.namelist() if n.endswith('.apk')}
        selected = output / 'selected'
        selected.mkdir()
        for name in summary['generatedApks']:
            (selected / Path(name).name).write_bytes(archive.read(name))
    assert len(summary['generatedApks']) >= 2, 'Expected base plus configuration split'
    original_apks = list((consumer / 'build/outputs/apk/release').glob('*.apk'))
    assert len(original_apks) == 1
    original_signature = run([build_tools / 'apksigner', 'verify', '--print-certs', original_apks[0]], 'original-signer.log')
    expected_signers = set(re.findall(r'certificate SHA-256 digest: ([0-9a-fA-F]{64})', original_signature))
    assert len(expected_signers) == 1, 'Expected one fixture signer'
    expected_signer = next(iter(expected_signers))
    delivered_payloads = {}
    for path in sorted(selected.glob('*.apk')):
        signature = run([build_tools / 'apksigner', 'verify', '--print-certs', path], path.name + '-signature.log')
        assert set(re.findall(r'certificate SHA-256 digest: ([0-9a-fA-F]{64})', signature)) == expected_signers
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name.endswith('.dex') or name.endswith('/libapparmorx.so'):
                    delivered_payloads[name] = hashlib.sha256(archive.read(name)).hexdigest()
    assert any(n.endswith('/libapparmorx.so') for n in delivered_payloads)
    assert 'classes.dex' in delivered_payloads
    with zipfile.ZipFile(bundles[0]) as archive:
        for name, digest in delivered_payloads.items():
            original = 'base/dex/' + name if name.endswith('.dex') else 'base/' + name
            assert hashlib.sha256(archive.read(original)).hexdigest() == digest, 'Delivered bytes changed: ' + name
    summary['signerSha256'] = expected_signer
    summary['deliveredDexNativeSha256'] = delivered_payloads
    run(tool('install-apks', '--apks=' + str(output / 'delivered.apks'), '--device-id=' + args.device), 'install-splits.log')
    paths = run(adb('shell', 'pm', 'path', application_id), 'installed-paths.log').splitlines()
    assert len(paths) >= 2, 'Device did not install a split set'
    summary['installedPaths'] = paths

    # A separate signed test APK calls the target's retained JNI contract, without changing its APK.
    src = output / 'src/com/apparmorx/splitprobe/Runner.java'
    src.parent.mkdir(parents=True)
    src.write_text('''package com.apparmorx.splitprobe;
public final class Runner extends android.app.Instrumentation {
 public void onCreate(android.os.Bundle args) { super.onCreate(args); start(); }
 public void onStart() {
  try {
   Class<?> engine = Class.forName("com.apparmorx.runtime.NativeEngine", true, getTargetContext().getClassLoader());
   java.lang.reflect.Method scan = engine.getDeclaredMethod("scanNative"); scan.setAccessible(true);
   int[] values = (int[]) scan.invoke(null);
   if (values == null || values.length != 14) throw new AssertionError("Invalid native contract");
   for (int value : values) if (value < 0 || value > 2) throw new AssertionError("Invalid native status");
   String[] splits = getTargetContext().getApplicationInfo().splitSourceDirs;
   if (splits == null || splits.length == 0) throw new AssertionError("No delivered splits");
   org.json.JSONObject result = new org.json.JSONObject().put("status", "passed")
    .put("uid", android.os.Process.myUid()).put("nativeStatuses", new org.json.JSONArray(values))
    .put("splitCount", splits.length).put("debuggable", (getTargetContext().getApplicationInfo().flags & 2) != 0);
   android.os.Bundle out = new android.os.Bundle(); out.putString("stream", "AAX_SPLIT_JNI " + result + "\\n");
   finish(-1, out);
  } catch (Throwable failure) {
   android.os.Bundle out = new android.os.Bundle(); out.putString("stream", "AAX_SPLIT_FAILURE " + failure + "\\n");
   finish(0, out);
  }
 }
}
''')
    classes = output / 'classes'
    run(['javac', '--release', '17', '-classpath', android, '-d', classes, src], 'javac.log')
    run([build_tools / 'd8', '--min-api', '29', '--lib', android, '--output', output,
         *classes.rglob('*.class')], 'd8.log')
    manifest = output / 'AndroidManifest.xml'
    manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{probe_id}"><uses-sdk android:minSdkVersion="29" android:targetSdkVersion="34"/><application android:hasCode="true"/><instrumentation android:name="com.apparmorx.splitprobe.Runner" android:targetPackage="{application_id}"/></manifest>''')
    unsigned = output / 'probe-unsigned.apk'
    run([build_tools / 'aapt2', 'link', '-I', android, '--manifest', manifest, '-o', unsigned], 'aapt.log')
    with zipfile.ZipFile(unsigned, 'a') as archive:
        archive.write(output / 'classes.dex', 'classes.dex')
    probe = output / 'probe.apk'
    run([build_tools / 'apksigner', 'sign', '--ks', consumer / 'fixture.jks', '--ks-key-alias', 'fixture',
         '--ks-pass', 'pass:fixture-only', '--key-pass', 'pass:fixture-only', '--out', probe, unsigned], 'sign-probe.log')
    assert 'Success' in run(adb('install', '-r', '-t', str(probe)), 'install-probe.log')
    raw = run(adb('shell', 'am', 'instrument', '-w', '-r',
                  probe_id + '/com.apparmorx.splitprobe.Runner'), 'native-execution.log')
    rows = [json.loads(line.partition('AAX_SPLIT_JNI ')[2]) for line in raw.splitlines() if 'AAX_SPLIT_JNI ' in line]
    assert len(rows) == 1 and rows[0]['status'] == 'passed' and rows[0]['debuggable'] is False
    assert rows[0]['uid'] >= 10000
    summary['nativeExecution'] = rows[0]
    summary['status'] = 'passed'
    save()
    print('PASS: delivered split set and 14 JNI probe results in the signed minified target process.')


if __name__ == '__main__':
    main()

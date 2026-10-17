#!/usr/bin/env python3
"""Build a signed, minified consumer of the public plugin without source substitution.
Uses an isolated Gradle home by default. Work directory and logs remain for inspection.
No credentials or publication tasks are used. Requires Android SDK and JDK 17+.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--version', default='0.1.1')
parser.add_argument('--repository', type=Path, help='Explicit isolated candidate Maven repository; no Maven Local')
parser.add_argument('--verify-dependency', action='store_true', help='Require compiled external-JAR clipboard call to pass through the firewall')
parser.add_argument('--work-dir', type=Path)
parser.add_argument('--gradle-user-home', type=Path, help='Optional cache reuse; omit for isolated resolution')
args = parser.parse_args()
if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.version):
    parser.error('Invalid version')
root = Path(__file__).resolve().parents[1]
work = (args.work_dir or Path(tempfile.mkdtemp(prefix='apparmorx-public-consumer-'))).resolve()
work.mkdir(parents=True, exist_ok=True)
if any(work.iterdir()):
    parser.error('work-dir must be empty')
sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
if not sdk:
    for line in (root / 'local.properties').read_text().splitlines() if (root / 'local.properties').exists() else []:
        if line.startswith('sdk.dir='):
            sdk = line.partition('=')[2]
if not sdk or not Path(sdk).is_dir():
    parser.error('Set ANDROID_HOME to an installed Android SDK')
shutil.copy(root / 'gradlew', work / 'gradlew')
shutil.copytree(root / 'gradle/wrapper', work / 'gradle/wrapper')
(work / 'gradle.properties').write_text('org.gradle.jvmargs=-Xmx2g -XX:MaxMetaspaceSize=768m\norg.gradle.workers.max=2\n')
(work / 'local.properties').write_text('sdk.dir=' + sdk.replace('\\', '/') + '\n')
if args.repository and not args.repository.is_dir():
    parser.error('candidate repository must exist')
candidate = ('exclusiveContent { forRepository { maven { url = uri(' + json.dumps(args.repository.resolve().as_uri()) + ') } }; filter { includeGroupByRegex("com[.]apparmorx.*") } }; ') if args.repository else ''
(work / 'settings.gradle.kts').write_text('''pluginManagement { repositories { %sgoogle(); gradlePluginPortal(); mavenCentral() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "apparmorx-public-consumer"
''' % candidate)
(work / 'build.gradle.kts').write_text('''plugins {
    id("com.android.application") version "9.4.1"
    id("com.apparmorx.security") version "%s"
}
android {
    namespace = "com.apparmorx.consumer"
    compileSdk = 34
    defaultConfig { applicationId = "com.apparmorx.consumer"; minSdk = 29; targetSdk = 34; versionCode = 1; versionName = "1" }
    signingConfigs { create("fixture") {
        storeFile = file("fixture.jks"); storePassword = "fixture-only"; keyAlias = "fixture"; keyPassword = "fixture-only"
    } }
    buildTypes { release {
        isMinifyEnabled = true
        signingConfig = signingConfigs.getByName("fixture")
        proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "fixture-rules.pro")
    } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
''' % args.version)
(work / 'fixture-rules.pro').write_text('-keep class com.apparmorx.fixture.vendor.ClipboardReader { *; }\n')
(work / 'build.gradle.kts').open('a').write('\ndependencies { implementation(files("vendor.jar")) }\n')
vendor = work / 'vendor-src/com/apparmorx/fixture/vendor'
vendor.mkdir(parents=True)
(vendor / 'ClipboardReader.java').write_text('''package com.apparmorx.fixture.vendor;
public final class ClipboardReader {
    public static android.content.ClipData read(android.content.ClipboardManager clipboard) {
        return clipboard.getPrimaryClip();
    }
}
''')
vendorClasses = work / 'vendor-classes'
subprocess.run(['javac', '--release', '17', '-classpath', str(Path(sdk) / 'platforms/android-34/android.jar'), '-d', str(vendorClasses), str(vendor / 'ClipboardReader.java')], check=True)
subprocess.run(['jar', 'cf', str(work / 'vendor.jar'), '-C', str(vendorClasses), '.'], check=True)
src = work / 'src/main/java/com/apparmorx/consumer'
src.mkdir(parents=True)
(src / 'MainActivity.java').write_text('''package com.apparmorx.consumer;
public class MainActivity extends android.app.Activity {
    @Override public void onCreate(android.os.Bundle state) { super.onCreate(state); }
}
''')
(work / 'src/main/AndroidManifest.xml').write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="false" android:usesCleartextTraffic="false"><activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity></application></manifest>''')
subprocess.run(['keytool', '-genkeypair', '-keystore', str(work / 'fixture.jks'), '-storepass', 'fixture-only', '-keypass', 'fixture-only', '-alias', 'fixture', '-dname', 'CN=AppArmorX Test Fixture', '-keyalg', 'RSA', '-validity', '30', '-noprompt'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
env = os.environ.copy()
env['GRADLE_USER_HOME'] = str((args.gradle_user_home or work / 'gradle-home').resolve())
env['ANDROID_HOME'] = sdk
print('Evidence directory:', work, flush=True)
command = [str(work / 'gradlew'), '--no-daemon', 'assembleRelease', '--configuration-cache', '--configuration-cache-problems=fail', '--stacktrace']
for run in (1, 2):
    with (work / f'build-{run}.log').open('w') as log:
        result = subprocess.run(command, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=1200)
    if result.returncode:
        print((work / f'build-{run}.log').read_text()[-16000:])
        raise SystemExit(result.returncode)
if 'Reusing configuration cache.' not in (work / 'build-2.log').read_text():
    raise SystemExit('Second run did not reuse configuration cache')
reports = work / 'build/reports/apparmorx'
for name in ('protection-report-release.json', 'protection-report-release.html', 'security-audit-release.sarif'):
    if not (reports / name).is_file() or not (reports / name).stat().st_size:
        raise SystemExit('Missing report: ' + name)
json.loads((reports / 'protection-report-release.json').read_text())
json.loads((reports / 'security-audit-release.sarif').read_text())
if not list((work / 'build/outputs/apk/release').glob('*.apk')):
    raise SystemExit('Missing signed release APK')
apk = next((work / 'build/outputs/apk/release').glob('*.apk'))
signers = sorted((Path(sdk) / 'build-tools').glob('*/apksigner'))
if not signers:
    raise SystemExit('apksigner is required to verify release signing')
with (work / 'signature-verification.log').open('w') as log:
    subprocess.run([str(signers[-1]), 'verify', '--verbose', str(apk)], check=True, stdout=log, stderr=subprocess.STDOUT)
with zipfile.ZipFile(apk) as archive:
    names = set(archive.namelist())
    for abi in ('arm64-v8a', 'x86_64'):
        if f'lib/{abi}/libapparmorx.so' not in names:
            raise SystemExit('Missing packaged native ABI: ' + abi)
if args.verify_dependency:
    dexdumps = sorted((Path(sdk) / 'build-tools').glob('*/dexdump'))
    if not dexdumps:
        raise SystemExit('dexdump is required for dependency regression verification')
    dumps = []
    apk = next((work / 'build/outputs/apk/release').glob('*.apk'))
    with zipfile.ZipFile(apk) as archive:
        for entry in archive.namelist():
            if re.fullmatch(r'classes[0-9]*\.dex', entry):
                dex = work / Path(entry).name
                dex.write_bytes(archive.read(entry))
                dumps.append(subprocess.check_output([str(dexdumps[-1]), '-d', str(dex)], text=True))
    disassembly = '\n'.join(dumps)
    (work / 'disassembly.txt').write_text(disassembly)
    block = next((b for b in disassembly.split('Class #') if "Class descriptor  : 'Lcom/apparmorx/fixture/vendor/ClipboardReader;'" in b), '')
    if not block or not re.search(r'invoke-static[^\n]*DependencyFirewall;?\.getPrimaryClip', block):
        raise SystemExit('REGRESSION: external JAR clipboard call was not redirected through DependencyFirewall (see disassembly.txt)')
    if re.search(r'invoke-virtual[^\n]*ClipboardManager;?\.getPrimaryClip', block):
        raise SystemExit('REGRESSION: external JAR retains direct clipboard access')
    print('PASS: external JAR clipboard call routes through DependencyFirewall in final R8 DEX.')
print('PASS:', 'candidate' if args.repository else 'public plugin', 'signed R8 release, coverage reports, configuration-cache reuse. Build proof only; no device prevention claim.')

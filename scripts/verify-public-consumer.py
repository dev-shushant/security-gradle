#!/usr/bin/env python3
"""Build a signed, minified consumer of the public plugin without source substitution.
Uses an isolated Gradle home by default. Work directory and logs remain for inspection.
No credentials or publication tasks are used. Requires Android SDK and JDK 17+.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from remote_worker_dex import verify_remote_worker_dex, verify_mutation_controls

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--version', default='0.1.1')
parser.add_argument('--application-id', default='com.apparmorx.consumer', help='Owned fixture ID; use a fresh suffix to preserve earlier installed fixtures')
parser.add_argument('--repository', type=Path, help='Explicit isolated candidate Maven repository; no Maven Local')
parser.add_argument('--verify-dependency', action='store_true', help='Require compiled external-JAR clipboard call to pass through the firewall')
parser.add_argument('--verify-service-callbacks', action='store_true', help='Require guard calls before retained Service start/bind fixture bodies in final DEX')
parser.add_argument('--verify-report-boundaries', action='store_true', help='Require component inventory and quoted-warning JSON in actual APK/AAB reports')
parser.add_argument('--verify-provider-operations', action='store_true', help='Require declared provider operation gates in final DEX; requires --verify-report-boundaries')
parser.add_argument('--verify-inherited-provider', action='store_true', help='Require inherited final external-JAR provider gates without provider keep rules')
parser.add_argument('--verify-worker-entries', action='store_true', help='Verify an inherited final external-JAR Worker body after ordinary R8')
parser.add_argument('--verify-coroutine-worker', action='store_true', help='Verify CoroutineWorker entry guard and unguarded suspend cleanup after ordinary R8')
parser.add_argument('--verify-remote-worker', action='store_true', help='Verify remote coroutine entry, returned-Future tracking and stop bridge after ordinary R8')
parser.add_argument('--remote-device-controls', action='store_true', help='Build an OBSERVE-only remote lifecycle UI fixture for device exploration, with no SDK calls or test keep rules')
parser.add_argument('--worker-runtime-aar', type=Path, help='Resolved WorkManager 2.11.1 AAR for compiling the SDK-free vendor fixture')
parser.add_argument('--worker-compile-jar', type=Path, action='append', default=[], help='Compile-only vendor API dependency; repeat for ListenableFuture/annotations')
parser.add_argument('--bundle', action='store_true', help='Also build and inspect the signed minified Android App Bundle; does not prove delivered split behavior')
parser.add_argument('--require-bundle-audit', action='store_true', help='Require candidate plugin bundle gate/report and validate reported digests against final AAB')
parser.add_argument('--work-dir', type=Path)
parser.add_argument('--gradle-user-home', type=Path, help='Optional cache reuse; omit for isolated resolution')
args = parser.parse_args()
if args.remote_device_controls and not args.verify_remote_worker:
    parser.error('--remote-device-controls requires --verify-remote-worker')
if args.verify_remote_worker and not args.verify_coroutine_worker:
    parser.error('--verify-remote-worker requires --verify-coroutine-worker')
if args.verify_coroutine_worker and not args.verify_worker_entries:
    parser.error('--verify-coroutine-worker requires --verify-worker-entries')
if args.verify_worker_entries and (not args.worker_runtime_aar or not args.worker_runtime_aar.is_file()):
    parser.error('--verify-worker-entries requires --worker-runtime-aar')
if args.verify_provider_operations and not args.verify_report_boundaries:
    parser.error('--verify-provider-operations requires --verify-report-boundaries')
if args.verify_inherited_provider and not args.verify_provider_operations:
    parser.error('--verify-inherited-provider requires --verify-provider-operations')
if not re.fullmatch(r'com\.apparmorx\.consumer(?:\.[A-Za-z][A-Za-z0-9_]*)*', args.application_id):
    parser.error('Application ID must remain under com.apparmorx.consumer')
if args.require_bundle_audit and not args.bundle:
    parser.error('--require-bundle-audit requires --bundle')
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
    defaultConfig { applicationId = "%s"; minSdk = 29; targetSdk = 34; versionCode = 1; versionName = "1" }
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
''' % (args.version, args.application_id))
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
vendor_classpath = str(Path(sdk) / 'platforms/android-34/android.jar')
if args.verify_worker_entries:
    with zipfile.ZipFile(args.worker_runtime_aar) as aar:
        worker_api = work / 'worker-compile-api.jar'
        worker_api.write_bytes(aar.read('classes.jar'))
    vendor_classpath += os.pathsep + os.pathsep.join(map(str, [worker_api, *args.worker_compile_jar]))
    (vendor / 'LibraryWorker.java').write_text('''package com.apparmorx.fixture.vendor;
public class LibraryWorker extends androidx.work.Worker {
    public static volatile int entries;
    public LibraryWorker(android.content.Context c, androidx.work.WorkerParameters p) { super(c, p); }
    @Override public final Result doWork() {
        return Result.success(new androidx.work.Data.Builder().putInt("entries", ++entries).build());
    }
}
''')
    with (work / 'build.gradle.kts').open('a') as build:
        build.write('\nandroid { compileSdk = 36 }\ndependencies { implementation("androidx.work:work-runtime:2.11.1") }\n')
if args.verify_inherited_provider:
    shutil.copyfile(root / 'sample/provider-fixture/src/main/java/com/apparmorx/fixture/vendor/LibraryProvider.java', vendor / 'LibraryProvider.java')
subprocess.run(['javac', '--release', '17', '-classpath', vendor_classpath, '-d', str(vendorClasses), *map(str, sorted(vendor.glob('*.java')))], check=True)
subprocess.run(['jar', 'cf', str(work / 'vendor.jar'), '-C', str(vendorClasses), '.'], check=True)
src = work / 'src/main/java/com/apparmorx/consumer'
src.mkdir(parents=True)
(src / 'MainActivity.java').write_text('''package com.apparmorx.consumer;
public class MainActivity extends android.app.Activity {
    @Override public void onCreate(android.os.Bundle state) { super.onCreate(state); }
}
''')
if args.verify_worker_entries:
    (src / 'InheritedWorker.java').write_text('''package com.apparmorx.consumer;
public final class InheritedWorker extends com.apparmorx.fixture.vendor.LibraryWorker {
    public InheritedWorker(android.content.Context c, androidx.work.WorkerParameters p) { super(c, p); }
}
''')
    activity = src / 'MainActivity.java'
    activity.write_text(activity.read_text().replace('super.onCreate(state);',
        'super.onCreate(state); androidx.work.WorkManager.getInstance(this).enqueue('
        'new androidx.work.OneTimeWorkRequest.Builder(InheritedWorker.class).build());'))
if args.verify_coroutine_worker:
    kotlin = work / 'src/main/kotlin/com/apparmorx/consumer'
    kotlin.mkdir(parents=True)
    (kotlin / 'ConsumerCoroutineWorker.kt').write_text('''package com.apparmorx.consumer
import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.delay
class ConsumerCoroutineWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        try {
            delay(25)
            return Result.success()
        } finally {
            Log.i("AppArmorX", "AppArmorX coroutine cleanup")
        }
    }
}
''')
    activity = src / 'MainActivity.java'
    activity.write_text(activity.read_text().replace('super.onCreate(state);',
        'super.onCreate(state); androidx.work.WorkManager.getInstance(this).enqueue('
        'new androidx.work.OneTimeWorkRequest.Builder(ConsumerCoroutineWorker.class).build());'))
if args.verify_remote_worker:
    with (work / 'build.gradle.kts').open('a') as build:
        build.write('\ndependencies { implementation("androidx.work:work-multiprocess:2.11.1") }\n')
    (kotlin / 'ConsumerRemoteWorker.kt').write_text('''package com.apparmorx.consumer
import android.content.Context
import android.util.Log
import androidx.work.WorkerParameters
import androidx.work.multiprocess.RemoteCoroutineWorker
import kotlinx.coroutines.delay
class ConsumerRemoteWorker(context: Context, params: WorkerParameters) : RemoteCoroutineWorker(context, params) {
    override suspend fun doRemoteWork(): Result {
        try {
            delay(25)
            return Result.success()
        } finally {
            Log.i("AppArmorX", "AppArmorX ordinary R8 remote cleanup")
        }
    }
}
''')
    activity = src / 'MainActivity.java'
    activity.write_text(activity.read_text().replace('super.onCreate(state);',
        'super.onCreate(state); androidx.work.WorkManager.getInstance(this).enqueue('
        'new androidx.work.OneTimeWorkRequest.Builder(androidx.work.multiprocess.RemoteListenableDelegatingWorker.class)'
        '.setInputData(new androidx.work.Data.Builder()'
        '.putString(androidx.work.multiprocess.RemoteListenableWorker.ARGUMENT_PACKAGE_NAME, getPackageName())'
        '.putString(androidx.work.multiprocess.RemoteListenableWorker.ARGUMENT_CLASS_NAME, androidx.work.multiprocess.RemoteWorkerService.class.getName())'
        '.putString(androidx.work.multiprocess.RemoteListenableDelegatingWorker.ARGUMENT_REMOTE_LISTENABLE_WORKER_NAME, ConsumerRemoteWorker.class.getName())'
        '.build()).build());'))
(work / 'src/main/AndroidManifest.xml').write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="false" android:usesCleartextTraffic="false"><activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity></application></manifest>''')
if args.verify_remote_worker:
    manifest = work / 'src/main/AndroidManifest.xml'
    manifest.write_text(manifest.read_text().replace('</application>', '<service android:name="androidx.work.multiprocess.RemoteWorkerService" android:exported="false" android:process=":worker"/></application>'))
if args.remote_device_controls:
    # Explicit lifecycle-only fixture posture; never weaken the plugin's production defaults.
    with (work / 'build.gradle.kts').open('a') as build:
        build.write('\nsecurity { restrictedAction.set("OBSERVE"); failClosedOnStartup.set(false); enforceIndeterminate.set(false); secureScreen.set(false) }\n')
    (kotlin / 'ConsumerRemoteWorker.kt').write_text('''package com.apparmorx.consumer
import android.content.Context
import android.os.Process
import android.util.Log
import androidx.work.Data
import androidx.work.WorkerParameters
import androidx.work.multiprocess.RemoteCoroutineWorker
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
class ConsumerRemoteWorker(context: Context, params: WorkerParameters) : RemoteCoroutineWorker(context, params) {
    override suspend fun doRemoteWork(): Result {
        val waiting = inputData.getBoolean("wait", false)
        Log.i("AAXRemoteConsumer", "entered id=$id pid=${Process.myPid()} uid=${Process.myUid()} wait=$waiting")
        try {
            if (waiting) {
                delay(1000)
                Log.i("AAXRemoteConsumer", "awaiting id=$id pid=${Process.myPid()}")
                awaitCancellation()
            }
            delay(25)
            return Result.success(Data.Builder().putInt("remotePid", Process.myPid())
                .putInt("remoteUid", Process.myUid()).putString("marker", "AppArmorX remote output").build())
        } finally {
            Log.i("AAXRemoteConsumer", "cleanup id=$id pid=${Process.myPid()}")
            Log.i("AppArmorX", "AppArmorX ordinary R8 remote cleanup")
        }
    }
}
''')
    (src / 'MainActivity.java').write_text('''package com.apparmorx.consumer;
public class MainActivity extends android.app.Activity {
    private java.util.UUID current;
    private android.widget.TextView status;
    private final android.os.Handler handler = new android.os.Handler(android.os.Looper.getMainLooper());
    private boolean visible;
    @Override public void onCreate(android.os.Bundle saved) {
        super.onCreate(saved);
        android.widget.LinearLayout layout = new android.widget.LinearLayout(this);
        layout.setOrientation(android.widget.LinearLayout.VERTICAL); layout.setPadding(24,48,24,24);
        status = new android.widget.TextView(this); status.setText("READY - OBSERVE lifecycle fixture"); layout.addView(status);
        addButton(layout,"Run remote worker", () -> startRemote(false));
        addButton(layout,"Start pending worker", () -> startRemote(true));
        addButton(layout,"Cancel pending worker", () -> {
            if(current != null) {
                androidx.work.WorkManager.getInstance(this).cancelWorkById(current);
                android.util.Log.i("AAXRemoteConsumer","cancel-request id="+current);
            }
        });
        setContentView(layout);
        androidx.work.WorkManager.getInstance(this).enqueue(new androidx.work.OneTimeWorkRequest.Builder(InheritedWorker.class).build());
        androidx.work.WorkManager.getInstance(this).enqueue(new androidx.work.OneTimeWorkRequest.Builder(ConsumerCoroutineWorker.class).build());
    }
    private void addButton(android.widget.LinearLayout layout,String label,Runnable action) {
        android.widget.Button button = new android.widget.Button(this);button.setText(label);
        button.setContentDescription(label);button.setOnClickListener(view -> action.run());layout.addView(button);
    }
    private void startRemote(boolean wait) {
        if(current != null && status.getText().toString().startsWith("RUNNING")) return;
        androidx.work.Data data = new androidx.work.Data.Builder()
            .putString(androidx.work.multiprocess.RemoteListenableWorker.ARGUMENT_PACKAGE_NAME,getPackageName())
            .putString(androidx.work.multiprocess.RemoteListenableWorker.ARGUMENT_CLASS_NAME,androidx.work.multiprocess.RemoteWorkerService.class.getName())
            .putString(androidx.work.multiprocess.RemoteListenableDelegatingWorker.ARGUMENT_REMOTE_LISTENABLE_WORKER_NAME,ConsumerRemoteWorker.class.getName())
            .putBoolean("wait",wait).build();
        androidx.work.OneTimeWorkRequest request = new androidx.work.OneTimeWorkRequest.Builder(androidx.work.multiprocess.RemoteListenableDelegatingWorker.class).setInputData(data).build();
        current=request.getId();status.setText("ENQUEUED id="+current);
        android.util.Log.i("AAXRemoteConsumer","enqueued id="+current+" mainPid="+android.os.Process.myPid()+" wait="+wait);
        androidx.work.WorkManager.getInstance(this).enqueue(request);
    }
    private final Runnable refresh = new Runnable() {
        @Override public void run() {
            if(!visible) return;
            if(current != null) {
                final java.util.UUID id=current;
                com.google.common.util.concurrent.ListenableFuture<androidx.work.WorkInfo> future = androidx.work.WorkManager.getInstance(MainActivity.this).getWorkInfoById(id);
                future.addListener(() -> {
                    try {
                        androidx.work.WorkInfo info=future.get();
                        if(visible && id.equals(current) && info != null) {
                            status.setText(info.getState()+" id="+id+" remotePid="+info.getOutputData().getInt("remotePid",-1)+" remoteUid="+info.getOutputData().getInt("remoteUid",-1)+" marker="+info.getOutputData().getString("marker"));
                        }
                    } catch(Exception failure) { status.setText("ERROR "+failure.getClass().getSimpleName()); }
                },getMainExecutor());
            }
            handler.postDelayed(this,200);
        }
    };
    @Override protected void onStart() { super.onStart();visible=true;handler.post(refresh); }
    @Override protected void onStop() { visible=false;handler.removeCallbacks(refresh);super.onStop(); }
}
''')
if args.verify_service_callbacks:
    (src / 'GuardedService.java').write_text("""package com.apparmorx.consumer;
public final class GuardedService extends android.app.Service {
    public static volatile boolean startBody;
    public static volatile boolean bindBody;
    @Override public int onStartCommand(android.content.Intent intent, int flags, int startId) {
        startBody = true; return START_STICKY;
    }
    @Override public android.os.IBinder onBind(android.content.Intent intent) {
        bindBody = true; return new android.os.Binder();
    }
}
""")
    with (work / 'fixture-rules.pro').open('a') as rules:
        rules.write('-keep class com.apparmorx.consumer.GuardedService { *; }\n')
    manifest = work / 'src/main/AndroidManifest.xml'
    manifest.write_text(manifest.read_text().replace('</application>', '<service android:name=".GuardedService" android:exported="false"/></application>'))
if args.verify_report_boundaries:
    (src / 'FixtureApplication.java').write_text('''package com.apparmorx.consumer;
public final class FixtureApplication extends android.app.Application {
    @Override public void onCreate() { super.onCreate(); }
}
''')
    (src / 'DiagnosticProvider.java').write_text('''package com.apparmorx.consumer;
public final class DiagnosticProvider extends android.content.ContentProvider {
    public boolean onCreate() { return true; }
    public android.database.Cursor query(android.net.Uri u, String[] p, String s, String[] a, String o) { return null; }
    public String getType(android.net.Uri u) { return null; }
    public android.net.Uri insert(android.net.Uri u, android.content.ContentValues v) { return null; }
    public int delete(android.net.Uri u, String s, String[] a) { return 0; }
    public int update(android.net.Uri u, android.content.ContentValues v, String s, String[] a) { return 0; }
}
''')
    manifest = work / 'src/main/AndroidManifest.xml'
    # Intentional audit warning exercises quotes in JSON; this fixture never sends HTTP traffic.
    xml = manifest.read_text().replace('android:usesCleartextTraffic="false"',
        'android:usesCleartextTraffic="true" android:name="com.apparmorx.consumer.FixtureApplication"')
    xml = xml.replace('</application>', '<activity-alias android:name=".Alias" android:targetActivity="com.apparmorx.consumer.MainActivity" android:exported="false"/>' +
        '<provider android:name="com.apparmorx.consumer.DiagnosticProvider" android:authorities="' + args.application_id +
        '.fixture.data" android:process=":data" android:exported="false"/></application>')
    manifest.write_text(xml)
if args.verify_inherited_provider:
    (src / 'InheritedProvider.java').write_text('''package com.apparmorx.consumer;
public final class InheritedProvider extends com.apparmorx.fixture.vendor.LibraryProvider {}
''')
    manifest = work / 'src/main/AndroidManifest.xml'
    manifest.write_text(manifest.read_text().replace('</application>',
        '<provider android:name="com.apparmorx.consumer.InheritedProvider" android:authorities="' + args.application_id +
        '.inherited" android:exported="false"/></application>'))
subprocess.run(['keytool', '-genkeypair', '-keystore', str(work / 'fixture.jks'), '-storepass', 'fixture-only', '-keypass', 'fixture-only', '-alias', 'fixture', '-dname', 'CN=AppArmorX Test Fixture', '-keyalg', 'RSA', '-validity', '30', '-noprompt'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
env = os.environ.copy()
env['GRADLE_USER_HOME'] = str((args.gradle_user_home or work / 'gradle-home').resolve())
env['ANDROID_HOME'] = sdk
print('Evidence directory:', work, flush=True)
command = [str(work / 'gradlew'), '--no-daemon', 'assembleRelease', '--configuration-cache', '--configuration-cache-problems=fail', '--stacktrace']
if args.bundle:
    command.insert(3, 'bundleRelease')
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
apk_report = json.loads((reports / 'protection-report-release.json').read_text())
if args.verify_report_boundaries:
    inventory = apk_report['componentInventory']
    assert inventory['bytecodeVerified'] is False and inventory['issues'] == []
    declared = {c['name']: c for c in inventory['components']}
    provider = declared['com.apparmorx.consumer.DiagnosticProvider']
    assert provider['process'] == ':data' and provider['coverage'] == 'ALL_SCOPE_PROVIDER_OPERATIONS_UNVERIFIED'
    assert any(c['kind'] == 'activity-alias' and c['target'] == 'com.apparmorx.consumer.MainActivity' for c in declared.values())
    assert declared['com.apparmorx.consumer.FixtureApplication']['coverage'] == 'PROJECT_SCOPE_GUARDS_UNVERIFIED'
    assert any('android:usesCleartextTraffic="true"' in finding for finding in apk_report['manifestFindings'])
    html = (reports / 'protection-report-release.html').read_text()
    assert 'PACKAGED CHECKS PASSED' in html and 'PROTECTION VERIFIED' not in html
    assert 'ALL_SCOPE_PROVIDER_OPERATIONS_UNVERIFIED' in html and 'Workers are not enumerated' in html
    print('PASS: actual APK report preserves quoted findings and truthful component boundaries.')
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
if args.bundle:
    bundles = list((work / 'build/outputs/bundle/release').glob('*.aab'))
    if len(bundles) != 1:
        raise SystemExit('Expected exactly one release AAB')
    bundle = bundles[0]
    with zipfile.ZipFile(bundle) as archive:
        names = set(archive.namelist())
        required = {'BundleConfig.pb', 'base/manifest/AndroidManifest.xml',
                    'base/assets/apparmorx/policy.properties',
                    'base/lib/arm64-v8a/libapparmorx.so', 'base/lib/x86_64/libapparmorx.so'}
        missing = required - names
        if missing or not any(re.fullmatch(r'base/dex/classes[0-9]*[.]dex', n) for n in names):
            raise SystemExit('Incomplete protected AAB: ' + ', '.join(sorted(missing)) + ' (base DEX also required)')
        for name in required:
            if not archive.getinfo(name).file_size:
                raise SystemExit('Empty required bundle entry: ' + name)
    # jarsigner verifies bundle JAR signatures; APK signing schemes do not apply to an AAB.
    # The fixture owns this keystore. Check the expected alias as well as verification output:
    # jarsigner alone can exit zero for unsigned archives.
    with (work / 'bundle-signature-verification.log').open('w') as log:
        signature = subprocess.run(['jarsigner', '-verify', '-verbose', '-certs',
            '-keystore', str(work / 'fixture.jks'), '-storepass', 'fixture-only',
            str(bundle), 'fixture'], env={**env, 'JAVA_TOOL_OPTIONS': '-Duser.language=en -Duser.country=US'},
            stdout=log, stderr=subprocess.STDOUT, check=True)
    signature_text = (work / 'bundle-signature-verification.log').read_text()
    if 'jar verified.' not in signature_text or 'jar is unsigned' in signature_text:
        raise SystemExit('Bundle signature was not verified')
    payloads = required | {n for n in names if re.fullmatch(r'base/dex/classes[0-9]*[.]dex', n)}
    for name in payloads:
        if not re.search(r'^smk\s+\d+\s+[^\n]* ' + re.escape(name) + r'$', signature_text, re.MULTILINE):
            raise SystemExit('Required AAB payload lacks verified expected fixture signer: ' + name)
    if args.require_bundle_audit:
        report_path = reports / 'protection-report-release-bundle.json'
        if not report_path.is_file():
            raise SystemExit('Missing automatic bundle audit report')
        bundle_report = json.loads(report_path.read_text())
        if args.verify_report_boundaries:
            assert bundle_report['componentInventory'] == apk_report['componentInventory']
            print('PASS: APK/AAB component inventories match without claiming bytecode verification.')
        if bundle_report.get('isProtected') is not True or bundle_report.get('failures') != []:
            raise SystemExit('Automatic bundle audit did not pass')
        entry_digests = bundle_report.get('entryDigests', {})
        if not payloads.issubset(entry_digests):
            raise SystemExit('Automatic bundle report omitted required payload entries')
        with zipfile.ZipFile(bundle) as archive:
            for name, expected in entry_digests.items():
                if hashlib.sha256(archive.read(name)).hexdigest() != expected:
                    raise SystemExit('Bundle report does not match final artifact: ' + name)
        print('PASS: automatic bundle gate/report matches final signed AAB payload.')
    print('PASS: signed R8 AAB base payload, policy and both native ABIs; delivered splits not verified.')
remote_r8_results = []
if args.verify_dependency or args.verify_service_callbacks or args.verify_provider_operations or args.verify_worker_entries:
    dexdumps = sorted((Path(sdk) / 'build-tools').glob('*/dexdump'))
    if not dexdumps:
        raise SystemExit('dexdump is required for dependency regression verification')
    for artifact in ([apk, bundle] if args.bundle else [apk]):
        dumps = []
        with zipfile.ZipFile(artifact) as archive:
            for entry in archive.namelist():
                if re.fullmatch(r'(?:base/dex/)?classes[0-9]*\.dex', entry):
                    dex = work / Path(entry).name
                    dex.write_bytes(archive.read(entry))
                    dumps.append(subprocess.check_output([str(dexdumps[-1]), '-d', str(dex)], text=True))
        disassembly = '\n'.join(dumps)
        (work / ('disassembly-' + artifact.suffix[1:] + '.txt')).write_text(disassembly)
        if args.verify_worker_entries:
            mapping = (work / 'build/outputs/mapping/release/mapping.txt').read_text()
            blocks = []
            for original in ['com.apparmorx.fixture.vendor.LibraryWorker', 'com.apparmorx.consumer.InheritedWorker']:
                mapped = re.search(r'^' + re.escape(original) + r' -> ([^:]+):$', mapping, re.MULTILINE)
                if mapped:
                    descriptor = 'L' + mapped.group(1).replace('.', '/') + ';'
                    blocks.extend(b for b in disassembly.split('Class #') if "Class descriptor  : '" + descriptor + "'" in b)
            names = {'doWork', *re.findall(r'\bdoWork\(\).* -> (\S+)', mapping)}
            methods = [m for b in blocks for m in re.split(r'(?m)^\s*#\d+\s+:\s+\(in ', b)
                       if any(re.search(r"name\s+: '" + re.escape(name) + "'", m) for name in names)]
            def guarded_before_body(method):
                gate = re.search(r'invoke-static[^\n]*SecurityGuard;?\.allowWorker', method)
                body = re.search(r'\bsput(?:-\w+)?\b', method)
                return bool(gate and body and gate.start() < body.start() and 'SecurityException' in method)
            if not any(guarded_before_body(m) for m in methods):
                raise SystemExit('REGRESSION: inherited external-JAR Worker lacks final-DEX denial gate in ' + artifact.name)
            print('PASS: inherited final external-JAR Worker gate survives ordinary R8 ' + artifact.suffix[1:].upper() + ' without worker keep rules.')
        if args.verify_coroutine_worker:
            def mapped_blocks(original):
                match = re.search(r'^' + re.escape(original) + r' -> ([^:]+):$', mapping, re.MULTILINE)
                if not match:
                    return []
                descriptor = 'L' + match.group(1).replace('.', '/') + ';'
                return [b for b in disassembly.split('Class #') if "Class descriptor  : '" + descriptor + "'" in b]
            framework = mapped_blocks('androidx.work.CoroutineWorker')
            section = re.search(r'^androidx\.work\.CoroutineWorker -> [^:]+:\n((?:(?:[ \t]|#)[^\n]*\n)*)', mapping, re.MULTILINE)
            starts = {'startWork', *re.findall(r'\bstartWork\(\).* -> (\S+)', section.group(1) if section else '')}
            entries = [m for b in framework for m in re.split(r'(?m)^\s*#\d+\s+:\s+\(in ', b)
                       if any(re.search(r"name\s+: '" + re.escape(n) + "'", m) for n in starts)]
            if not any(re.search(r'invoke-static[^\n]*SecurityGuard;?\.allowWorker', m) and 'SecurityException' in m for m in entries):
                raise SystemExit('REGRESSION: CoroutineWorker non-suspending entry gate missing in ' + artifact.name)
            suspend = mapped_blocks('com.apparmorx.consumer.ConsumerCoroutineWorker')
            suspend += mapped_blocks('com.apparmorx.consumer.ConsumerCoroutineWorker$doWork$1')
            if not suspend or not any('AppArmorX coroutine cleanup' in b for b in suspend):
                raise SystemExit('REGRESSION: coroutine cleanup body not retained in ' + artifact.name)
            if any(re.search(r'invoke-static[^\n]*SecurityGuard;?\.allowWorker', b) for b in suspend):
                raise SystemExit('REGRESSION: guard injected into suspend body/continuation in ' + artifact.name)
            print('PASS: CoroutineWorker startup gate and unguarded suspend cleanup survive ordinary R8 ' + artifact.suffix[1:].upper() + '. Static proof; cancellation is qualified separately.')
        if args.verify_remote_worker:
            try:
                counts = verify_remote_worker_dex(disassembly, mapping)
                rejected = verify_mutation_controls(disassembly, mapping)
            except ValueError as failure:
                raise SystemExit('REGRESSION: ' + str(failure) + ' in ' + artifact.name)
            remote_r8_results.append({'artifact': artifact.name, 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
                **counts, 'rejectedMutations': rejected, 'ordinaryR8': True, 'remoteDeviceExecutionQualified': False})
            print('PASS: remote coroutine entry/tracking, unguarded cleanup and stop compatibility survive ordinary R8 ' + artifact.suffix[1:].upper() + '. Static proof only; mutation controls rejected.')
        if args.verify_dependency:
            block = next((b for b in disassembly.split('Class #') if "Class descriptor  : 'Lcom/apparmorx/fixture/vendor/ClipboardReader;'" in b), '')
            if not block or not re.search(r'invoke-static[^\n]*DependencyFirewall;?\.getPrimaryClip', block):
                raise SystemExit('REGRESSION: external JAR clipboard call was not redirected in ' + artifact.name)
            if re.search(r'invoke-virtual[^\n]*ClipboardManager;?\.getPrimaryClip', block):
                raise SystemExit('REGRESSION: external JAR retains direct clipboard access in ' + artifact.name)
            print('PASS: external JAR clipboard call routes through DependencyFirewall in final R8 ' + artifact.suffix[1:].upper() + ' DEX.')
        if args.verify_service_callbacks:
            service = next((b for b in disassembly.split('Class #') if "Class descriptor  : 'Lcom/apparmorx/consumer/GuardedService;'" in b), '')
            methods = re.split(r'(?m)^\s*#\d+\s+:\s+\(in ', service)
            for name, field in [('onStartCommand', 'startBody'), ('onBind', 'bindBody')]:
                method = next((b for b in methods if re.search(r"name\s+: '" + name + "'", b)), '')
                guard = re.search(r'invoke-static[^\n]*SecurityGuard;?\.allowService', method)
                body = re.search(r'sput-boolean[^\n]*GuardedService;?\.' + field, method)
                if not guard or not body or guard.start() >= body.start():
                    raise SystemExit('REGRESSION: missing guard before Service ' + name + ' body in ' + artifact.name)
            print('PASS: Service start/bind guards precede fixture bodies in final R8 ' + artifact.suffix[1:].upper() + ' DEX. Runtime denial is qualified separately.')
        if args.verify_provider_operations:
            provider = next((b for b in disassembly.split('Class #') if "Class descriptor  : 'Lcom/apparmorx/consumer/DiagnosticProvider;'" in b), '')
            methods = re.split(r'(?m)^\s*#\d+\s+:\s+\(in ', provider)
            for name in ['query', 'getType', 'insert', 'delete', 'update']:
                method = next((b for b in methods if re.search(r"name\s+: '" + name + "'", b)), '')
                guard = re.search(r'invoke-static[^\n]*SecurityGuard;?\.allowProvider', method)
                returned = re.search(r'\breturn(?:-object)?\b', method)
                if not guard or not returned or guard.start() >= returned.start() or 'SecurityException' not in method:
                    raise SystemExit('REGRESSION: provider ' + name + ' lacks guard/denial before return in ' + artifact.name)
            print('PASS: provider CRUD/type operation gates and denial survive final R8 ' + artifact.suffix[1:].upper() + ' DEX.')
        if args.verify_inherited_provider:
            mapping = (work / 'build/outputs/mapping/release/mapping.txt').read_text()
            blocks = []
            for original in ['com.apparmorx.fixture.vendor.LibraryProvider', 'com.apparmorx.consumer.InheritedProvider']:
                mapped = re.search(r'^' + re.escape(original) + r' -> ([^:]+):$', mapping, re.MULTILINE)
                if mapped:
                    descriptor = 'L' + mapped.group(1).replace('.', '/') + ';'
                    blocks.extend(b for b in disassembly.split('Class #') if "Class descriptor  : '" + descriptor + "'" in b)
            for name in ['getType', 'call']:
                candidates = [method for block in blocks for method in re.split(r'(?m)^\s*#\d+\s+:\s+\(in ', block)
                              if re.search(r"name\s+: '" + name + "'", method)]
                if not any(re.search(r'invoke-static[^\n]*SecurityGuard;?\.allowProvider', method) and 'SecurityException' in method for method in candidates):
                    raise SystemExit('REGRESSION: inherited external-JAR provider ' + name + ' has no final-DEX gate in ' + artifact.name)
            print('PASS: inherited final external-JAR provider gates survive ordinary R8 ' + artifact.suffix[1:].upper() + ' DEX without provider keep rules.')
print('PASS:', 'candidate' if args.repository else 'public plugin', 'signed R8 release, coverage reports, configuration-cache reuse. Build proof only; no device prevention claim.')

if args.verify_remote_worker:
    (work / 'remote-r8-summary.json').write_text(json.dumps({'status': 'static-checks-passed', 'results': remote_r8_results, 'fixtureRules': (work / 'fixture-rules.pro').read_text()}, indent=2) + '\n')

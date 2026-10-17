# Only used when -Psample.testBuildType=release; Android test APK needs these probe APIs.
# Normal minified consumer qualification remains separate and uses normal consumer rules.
-keep class com.apparmorx.sample.SampleBackgroundService { *; }
-keep class com.apparmorx.runtime.SecurityRuntime { *; }
-keep class com.apparmorx.runtime.SecuritySnapshot { *; }
-keep class com.apparmorx.runtime.EnforcementPolicy { *; }
-keep class com.apparmorx.runtime.Evidence { *; }
-keep enum com.apparmorx.runtime.Status { *; }
-keep enum com.apparmorx.runtime.EnforcementAction { *; }
-keep class com.apparmorx.sample.SampleBackgroundService$Companion { *; }
# The test APK shares the target's Kotlin runtime. Preserve APIs the runner itself needs.
-keep class kotlin.** { *; }
# UI routing inspected only by the release instrumentation fixture.
-keep class com.apparmorx.runtime.SecurityUiDestination { *; }
-keep class com.apparmorx.sample.StartupProbeActivity { *; }
-keep class com.apparmorx.sample.StartupProbeActivity$Companion { *; }
-keep class com.apparmorx.runtime.StartupLaunches { *; }
-keep class com.apparmorx.runtime.ExpiringTickets { *; }
-keep class com.apparmorx.runtime.RuntimeScanner { *; }
-keep enum com.apparmorx.runtime.ProtectionState { *; }
-keep class com.apparmorx.runtime.ApplicationInitialization { *; }
-keep class com.apparmorx.runtime.ApplicationInitializationKt { *; }
-keep class com.apparmorx.sample.ColdStartApplication { *; }
-keep class com.apparmorx.sample.SampleContentProvider { *; }
-keep class com.apparmorx.sample.InheritedContentProvider { *; }
-keep class com.apparmorx.fixture.vendor.LibraryProvider { *; }
-keep class com.apparmorx.sample.work.** { *; }
# Qualification-only state accessor used by the separately compiled release test APK.
-keepclassmembers class com.apparmorx.runtime.SecurityGuard {
    public com.apparmorx.runtime.ProtectionState lastObservedState();
}
-keep class androidx.tracing.Trace { *; }
# Instrumentation references WorkManager APIs from a separate APK. This fixture
# retains those APIs; ordinary consumer shrinking must be qualified separately.
-keep class androidx.work.** { *; }
# Explicit process-qualification fixture only; these classes are absent by default.
-keep class com.apparmorx.sample.MultiprocessGuardService { *; }
-keep class com.apparmorx.runtime.fixture.ProcessControlProvider { *; }
-keep class com.apparmorx.sample.remote.** { *; }

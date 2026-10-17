# JNI registration requires this exact class and native method contract.
-keep,allowoptimization class com.apparmorx.runtime.NativeEngine {
    native <methods>;
}
-keep,allowoptimization class com.apparmorx.runtime.DependencyFirewall {
    public static <methods>;
}
-keep,allowoptimization class com.apparmorx.runtime.SecurityGuard {
    public static <methods>;
}
# Host UX class is selected by its manifest metadata string. Preserve that class name/constructor.
-keep,allowoptimization class * extends com.apparmorx.runtime.SecurityBlockActivity {
    public <init>();
}

# ALL-scope WorkManager compatibility uses only Java Future, with no mandatory library linkage.
-keep,allowoptimization class com.apparmorx.runtime.RemoteWorkerCancellation {
    public static <methods>;
}

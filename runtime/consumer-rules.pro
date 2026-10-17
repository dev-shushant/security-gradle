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

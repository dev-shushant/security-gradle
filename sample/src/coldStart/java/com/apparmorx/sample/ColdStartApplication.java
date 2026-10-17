package com.apparmorx.sample;

import android.app.Application;
import java.util.concurrent.atomic.AtomicInteger;

/** Dedicated qualification source set, absent from the ordinary sample APK. */
public final class ColdStartApplication extends Application {
    public static final AtomicInteger initialized = new AtomicInteger();

    @Override public void onCreate() {
        super.onCreate();
        // The plugin must place its guard before this host initialization body.
        initialized.incrementAndGet();
    }
}

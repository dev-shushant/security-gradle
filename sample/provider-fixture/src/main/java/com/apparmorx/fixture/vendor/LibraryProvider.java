package com.apparmorx.fixture.vendor;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import java.util.concurrent.atomic.AtomicInteger;

/** Independent library fixture: no SDK dependency or AppArmorX calls in this module. */
public class LibraryProvider extends ContentProvider {
    public static final AtomicInteger initializations = new AtomicInteger();
    public static final AtomicInteger operations = new AtomicInteger();
    @Override public boolean onCreate() { initializations.incrementAndGet(); return true; }
    @Override public final String getType(Uri uri) { operations.incrementAndGet(); return "vnd.android.cursor.item/apparmorx-library"; }
    @Override public final Bundle call(String method, String arg, Bundle extras) {
        operations.incrementAndGet(); Bundle result = new Bundle(); result.putString("marker", "AppArmorX library body"); return result;
    }
    @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) { operations.incrementAndGet(); return null; }
    @Override public Uri insert(Uri u, ContentValues v) { operations.incrementAndGet(); return u; }
    @Override public int delete(Uri u, String s, String[] a) { operations.incrementAndGet(); return 37; }
    @Override public int update(Uri u, ContentValues v, String s, String[] a) { operations.incrementAndGet(); return 37; }
}

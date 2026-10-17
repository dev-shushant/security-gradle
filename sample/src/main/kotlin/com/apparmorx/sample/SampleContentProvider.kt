package com.apparmorx.sample

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import java.util.concurrent.atomic.AtomicInteger

/** Framework-routed operation fixture, containing no manual AppArmorX calls. */
class SampleContentProvider : ContentProvider() {
    override fun onCreate(): Boolean { initializations.incrementAndGet(); return true }
    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        operations.incrementAndGet()
        return Bundle().apply { putString("marker", "AppArmorX provider body") }
    }
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        operations.incrementAndGet()
        return MatrixCursor(arrayOf("marker")).apply { addRow(arrayOf("AppArmorX")) }
    }
    override fun getType(uri: Uri): String { operations.incrementAndGet(); return "vnd.android.cursor.item/apparmorx" }
    override fun insert(uri: Uri, values: ContentValues?): Uri { operations.incrementAndGet(); return uri }
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int { operations.incrementAndGet(); return 37 }
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int { operations.incrementAndGet(); return 37 }
    companion object {
        @JvmField val initializations = AtomicInteger()
        @JvmField val operations = AtomicInteger()
    }
}

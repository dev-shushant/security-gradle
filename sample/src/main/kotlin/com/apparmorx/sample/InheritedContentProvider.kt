package com.apparmorx.sample

/** No operation overrides: final callback bodies live in an uninstrumented-at-library-build dependency. */
class InheritedContentProvider : com.apparmorx.fixture.vendor.LibraryProvider()

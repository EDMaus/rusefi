package com.rusefi;

import com.rusefi.core.preferences.storage.PersistentConfiguration;

public class AutoupdateProperty {
    public static final String AUTO_UPDATE_BUNDLE_PROPERTY = "AUTO_UPDATE_BUNDLE";

    public static boolean get() {
        // Custom board bundles are distributed as GitHub Action artifacts, not from
        // rusefi.com/build_server. Silent autoupdate can replace this bundle with a
        // cached or official bundle, so keep custom artifacts self-contained.
        return false;
    }
}

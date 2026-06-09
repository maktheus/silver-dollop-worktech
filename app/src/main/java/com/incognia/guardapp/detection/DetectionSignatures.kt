package com.incognia.guardapp.detection

/**
 * Centralised threat-signature catalogue shared across all analyzers.
 *
 * Keeping every lookup table here means the team only needs to touch
 * this one file when a new clone framework, root tool, or hook library
 * ships — no need to hunt across multiple analyzer files.
 *
 * All identifiers are [internal] so they remain invisible outside the
 * :app module boundary while still being accessible to every analyzer.
 */
internal object DetectionSignatures {

    // ── Clone / dual-space frameworks ─────────────────────────────────────────

    /**
     * Known package names for clone / multi-account / virtual-space apps.
     *
     * Limitation: an attacker can rename the package in the APK manifest
     * (apktool + re-sign) and bypass this list in ~15 minutes.
     * That is why CloneAnalyzer also uses UID offsets, dataDir paths, and
     * /proc/self/maps patterns — techniques that survive package renaming.
     */
    val KNOWN_CLONE_PACKAGES = listOf(
        "com.lbe.parallel.intl",
        "com.excelliance.dualaid",
        "com.parallel.space.lite",
        "com.parallel.space.pro",
        "cn.parallel.space.lite",
        "com.mobiwia.dualspace",
        "com.slspace.dualspace",
        "com.buk.android.cloneapp",
        "com.phonemaster.speed",
        "com.dualspace.multiaccount",
        "com.multi.clone.space",
        "com.twofaces.multiaccounts",
        "com.fancyclone.app",
        "com.dual.sim.space",
        "me.weishu.exp",
        "io.va.exposed",
        "com.qihoo.appstore.virtualapp.stub",
        "com.virtual.box",
        "com.ludashi.superboost",
        "com.dual.account.multispace",
        "com.polestar.domultiple",
        "com.flyingaway.vphone",
        "com.lody.virtual",
        "com.glow.android.secure.space",
    )

    /**
     * On-disk directories left behind by clone frameworks even after they
     * are uninstalled — useful as a secondary signal.
     */
    val CLONE_ARTIFACT_PATHS = listOf(
        "/data/data/com.lbe.parallel.intl",
        "/data/data/io.va.exposed",
        "/data/data/me.weishu.exp",
        "/data/data/com.lody.virtual",
    )

    /**
     * Substrings found in /proc/self/maps that indicate a clone framework's
     * native library has been loaded into this process.
     *
     * Note: package renaming changes the APK manifest but NOT the compiled
     * .so paths already baked into the native library — so these patterns
     * remain valid even against repackaged clone apps.
     */
    val CLONE_MAP_PATTERNS = mapOf(
        "com.lbe.parallel" to "Parallel Space native library",
        "io.va"            to "VirtualApp (io.va) native library",
        "com.lody.virtual" to "VirtualApp (lody) native library",
        "me.weishu"        to "VirtualXposed native library",
        "dual.space"       to "Dual Space native library",
    )

    // ── Root management ───────────────────────────────────────────────────────

    /** Known root management / superuser app package names. */
    val ROOT_PACKAGES = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
    )

    /** Common paths where su binaries are placed on rooted devices. */
    val SU_PATHS = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/xbin/su",
        "/data/local/tmp/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
    )

    /**
     * System property / bad-value pairs that indicate a rooted or
     * developer build.
     */
    val ROOT_PROP_CHECKS = mapOf(
        "ro.debuggable" to listOf("1"),
        "ro.secure"     to listOf("0"),
        "ro.build.type" to listOf("eng", "userdebug"),
    )

    /** System paths that should never be writable on a stock device. */
    val WRITABLE_SYSTEM_PATHS = listOf(
        "/system",
        "/system/bin",
        "/system/xbin",
        "/vendor/bin",
        "/sbin",
    )

    // ── Hook / instrumentation frameworks ────────────────────────────────────

    /** File paths associated with Xposed, Frida, Cydia Substrate, and Magisk. */
    val HOOK_PATHS = listOf(
        "/system/framework/XposedBridge.jar",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/data/data/de.robv.android.xposed.installer",
        "/data/data/io.github.lsposed.manager",   // LSPosed
        "/data/adb/lspd",                          // LSPosed daemon
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/data/local/frida-server",
        "/system/lib/libsubstrate.so",             // Cydia Substrate
        "/system/lib64/libsubstrate.so",
        "/system/lib/libsubstratevm.so",
        "/sbin/.magisk",                           // Magisk
        "/sbin/.core/mirror",
    )

    /**
     * Substrings in /proc/self/maps that indicate a hooking framework's
     * native library was mapped into this process.
     */
    val HOOK_MAP_PATTERNS = mapOf(
        "frida"      to "Frida instrumentation framework",
        "xposed"     to "Xposed framework",
        "substrate"  to "Cydia Substrate",
        "va.hook"    to "VirtualApp hook layer",
        "virtualapp" to "VirtualApp framework",
    )

    /** Xposed class names injected into every classloader by the framework. */
    val XPOSED_CLASS_NAMES = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
    )

    // ── Installer provenance ──────────────────────────────────────────────────

    /** Package names of stores we consider legitimate install sources. */
    val LEGITIMATE_INSTALLERS = setOf(
        "com.android.vending",                  // Google Play
        "com.amazon.venezia",                   // Amazon Appstore
        "com.sec.android.app.samsungapps",      // Samsung Galaxy Store
        "com.huawei.appmarket",                 // Huawei AppGallery
        "com.xiaomi.market",                    // Xiaomi GetApps
    )
}

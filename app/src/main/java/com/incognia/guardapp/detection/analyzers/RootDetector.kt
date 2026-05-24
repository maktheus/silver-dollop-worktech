package com.incognia.guardapp.detection.analyzers

import android.content.Context
import com.incognia.guardapp.detection.DetectionSignal
import com.incognia.guardapp.detection.EnvironmentAnalyzer
import com.incognia.guardapp.detection.Severity
import com.incognia.guardapp.detection.SignalCategory
import java.io.File

/**
 * Detects rooted devices via four complementary strategies:
 *  1. su binary presence in well-known paths
 *  2. Root management apps installed (Magisk, SuperSU, KingRoot, etc.)
 *  3. Dangerous system properties (ro.debuggable=1, ro.secure=0)
 *  4. Writable system partitions (impossible on stock, non-root devices)
 *
 * Constructor parameters are injectable for unit testing without a device.
 */
class RootDetector(
    private val fileProbe: (String) -> Boolean = { File(it).exists() },
    private val writableProbe: (String) -> Boolean = { File(it).run { exists() && canWrite() } },
    private val packageChecker: (Context, String) -> Boolean = { ctx, pkg ->
        runCatching { ctx.packageManager.getPackageInfo(pkg, 0); true }.getOrDefault(false)
    },
) : EnvironmentAnalyzer {

    override fun analyze(context: Context): List<DetectionSignal> =
        checkSuBinaries() +
            checkRootManagementApps(context) +
            checkDangerousProps() +
            checkWritableSystemPaths()

    // ── 1. su binaries ────────────────────────────────────────────────────────

    internal fun checkSuBinaries(): List<DetectionSignal> =
        SU_PATHS.filter { fileProbe(it) }.map { path ->
            DetectionSignal(SignalCategory.ROOT, "Root binary found: $path", Severity.HIGH)
        }

    // ── 2. Root management apps ───────────────────────────────────────────────

    private fun checkRootManagementApps(context: Context): List<DetectionSignal> =
        ROOT_PACKAGES.mapNotNull { pkg ->
            if (packageChecker(context, pkg)) {
                DetectionSignal(SignalCategory.ROOT, "Root management app installed: $pkg", Severity.HIGH)
            } else null
        }

    // ── 3. Dangerous system properties ───────────────────────────────────────

    internal fun checkDangerousProps(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        try {
            val clazz = Class.forName("android.os.SystemProperties")
            val get = clazz.getMethod("get", String::class.java, String::class.java)
            ROOT_PROP_CHECKS.forEach { (prop, badValues) ->
                val value = (get.invoke(null, prop, "") as? String)?.lowercase().orEmpty()
                if (value.isNotEmpty() && badValues.any { value.contains(it) }) {
                    signals += DetectionSignal(
                        SignalCategory.SYSTEM_PROPERTY,
                        "Root-indicative system property [$prop=$value]",
                        Severity.HIGH,
                    )
                }
            }
        } catch (_: Exception) {}
        return signals
    }

    // ── 4. Writable system partitions ─────────────────────────────────────────

    internal fun checkWritableSystemPaths(): List<DetectionSignal> =
        SYSTEM_PATHS.filter { writableProbe(it) }.map { path ->
            DetectionSignal(
                SignalCategory.ROOT,
                "System path is writable — indicates root mount: $path",
                Severity.HIGH,
            )
        }

    private companion object {
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

        val ROOT_PROP_CHECKS = mapOf(
            "ro.debuggable"  to listOf("1"),
            "ro.secure"      to listOf("0"),
            "ro.build.type"  to listOf("eng", "userdebug"),
        )

        val SYSTEM_PATHS = listOf(
            "/system",
            "/system/bin",
            "/system/xbin",
            "/vendor/bin",
            "/sbin",
        )
    }
}

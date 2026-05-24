package com.incognia.guardapp.detection.analyzers

import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import com.incognia.guardapp.detection.DetectionSignal
import com.incognia.guardapp.detection.EnvironmentAnalyzer
import com.incognia.guardapp.detection.Severity
import com.incognia.guardapp.detection.SignalCategory
import java.io.File

/**
 * Detects app-cloning / dual-space environments such as:
 * App Cloner, Dual Space, Multi Account, 2Face, VirtualApp, Game Cloner.
 *
 * Constructor parameters are injectable so unit tests can replace real
 * system calls with fakes without needing Robolectric or a device.
 *
 * Strategies:
 *  1. Package presence — known clone-framework packages installed on device.
 *  2. File artifacts — directories/libraries left by clone frameworks.
 *  3. Multi-user UID — cloned apps run under secondary Android user IDs (uid ≥ 100000).
 *  4. Data directory path — clone frameworks redirect the data dir outside /data/data/<pkg>.
 *  5. /proc/self/maps — clone framework native libraries loaded into this process.
 */
class CloneAnalyzer(
    private val uidProvider: () -> Int = { Process.myUid() },
    private val fileProbe: (String) -> Boolean = { File(it).exists() },
    private val packageChecker: (Context, String) -> Boolean = { ctx, pkg ->
        runCatching { ctx.packageManager.getPackageInfo(pkg, 0); true }.getOrDefault(false)
    },
    private val dataDirProvider: (Context) -> String? = { it.applicationInfo?.dataDir },
) : EnvironmentAnalyzer {

    override fun analyze(context: Context): List<DetectionSignal> =
        checkInstalledClonePackages(context) +
            checkCloneArtifactFiles() +
            checkSecondaryUserEnvironment(context) +
            checkProcMapsForCloneLibraries()

    // ── 1. Installed clone packages ───────────────────────────────────────────

    private fun checkInstalledClonePackages(context: Context): List<DetectionSignal> =
        KNOWN_CLONE_PACKAGES.mapNotNull { pkg ->
            if (packageChecker(context, pkg)) {
                DetectionSignal(
                    SignalCategory.CLONE_APP,
                    "Clone/virtual-space app installed: $pkg",
                    Severity.HIGH,
                )
            } else null
        }

    // ── 2. File artifacts ─────────────────────────────────────────────────────

    private fun checkCloneArtifactFiles(): List<DetectionSignal> =
        CLONE_ARTIFACT_PATHS.filter { fileProbe(it) }.map { path ->
            DetectionSignal(SignalCategory.SUSPICIOUS_PATH, "Clone framework artifact: $path", Severity.HIGH)
        }

    // ── 3 & 4. Secondary-user / redirected data dir ───────────────────────────

    internal fun checkSecondaryUserEnvironment(context: Context): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()

        // UID-based check: Android assigns UIDs in blocks of 100 000 per user.
        val userId = uidProvider() / 100_000
        if (userId != 0) {
            signals += DetectionSignal(
                SignalCategory.CLONE_APP,
                "App is running under Android user ID $userId (non-primary user space)",
                Severity.HIGH,
            )
        }

        // Data-dir check: clone frameworks redirect dataDir outside the primary path.
        val dataDir = dataDirProvider(context) ?: return signals
        val expectedPaths = listOf(
            "/data/data/${context.packageName}",
            "/data/user/0/${context.packageName}",
        )
        if (expectedPaths.none { dataDir.startsWith(it) }) {
            signals += DetectionSignal(
                SignalCategory.CLONE_APP,
                "App data directory is outside the expected primary-user path: $dataDir",
                Severity.HIGH,
            )
        }

        return signals
    }

    // ── 5. /proc/self/maps ────────────────────────────────────────────────────

    private fun checkProcMapsForCloneLibraries(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        val reported = mutableSetOf<String>()
        try {
            File("/proc/self/maps").forEachLine { line ->
                CLONE_MAP_PATTERNS.forEach { (pattern, label) ->
                    if (pattern !in reported && line.contains(pattern, ignoreCase = true)) {
                        reported += pattern
                        signals += DetectionSignal(
                            SignalCategory.CLONE_APP,
                            "$label detected in /proc/self/maps",
                            Severity.HIGH,
                        )
                    }
                }
            }
        } catch (_: Exception) {}
        return signals
    }

    private companion object {
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

        val CLONE_ARTIFACT_PATHS = listOf(
            "/data/data/com.lbe.parallel.intl",
            "/data/data/io.va.exposed",
            "/data/data/me.weishu.exp",
            "/data/data/com.lody.virtual",
        )

        val CLONE_MAP_PATTERNS = mapOf(
            "com.lbe.parallel" to "Parallel Space native library",
            "io.va"            to "VirtualApp (io.va) native library",
            "com.lody.virtual" to "VirtualApp (lody) native library",
            "me.weishu"        to "VirtualXposed native library",
            "dual.space"       to "Dual Space native library",
        )
    }
}

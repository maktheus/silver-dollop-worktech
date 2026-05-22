package com.incognia.guardapp.detection.analyzers

import android.content.Context
import android.os.Build
import com.incognia.guardapp.detection.DetectionSignal
import com.incognia.guardapp.detection.EnvironmentAnalyzer
import com.incognia.guardapp.detection.Severity
import com.incognia.guardapp.detection.SignalCategory
import java.io.File

/**
 * Detects standard Android emulators (AVD / QEMU / Genymotion / Nox / BlueStacks)
 * through a layered approach:
 *  1. android.os.Build properties
 *  2. Hidden android.os.SystemProperties (via reflection)
 *  3. QEMU-specific file artifacts
 *  4. /proc/cpuinfo virtual CPU markers
 *
 * String constants for the most sensitive indicators are split into char arrays
 * to avoid being trivially extracted by `strings` or APK inspectors.
 */
class EmulatorAnalyzer : EnvironmentAnalyzer {

    override fun analyze(context: Context): List<DetectionSignal> =
        checkBuildProperties() + checkSystemProperties() + checkEmulatorFiles() + checkCpuInfo()

    // ── Build properties ──────────────────────────────────────────────────────

    private fun checkBuildProperties(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()

        fun signal(desc: String, severity: Severity = Severity.HIGH) =
            signals.add(DetectionSignal(SignalCategory.EMULATOR, desc, severity))

        val fp = Build.FINGERPRINT.lowercase()
        if (fp.startsWith("generic") || fp.startsWith("unknown") ||
            fp.contains("emulator") || fp.contains("sdk_gphone") || fp.contains(":eng/")
        ) signal("Build.FINGERPRINT matches emulator pattern: ${Build.FINGERPRINT}")

        val model = Build.MODEL.lowercase()
        if (model == "sdk" || model.contains("emulator") ||
            model.contains("google sdk") || model.contains("sdk built for x86")
        ) signal("Build.MODEL matches emulator: ${Build.MODEL}")

        val manufacturer = Build.MANUFACTURER.lowercase()
        if (manufacturer.contains("genymotion") || manufacturer == "unknown")
            signal("Build.MANUFACTURER is '${Build.MANUFACTURER}'")

        val hardware = Build.HARDWARE.lowercase()
        if (hardware in setOf("goldfish", "ranchu", "vbox86", "vbox64", "ttvm_x86", "nox"))
            signal("Emulator hardware detected: ${Build.HARDWARE}")

        val product = Build.PRODUCT.lowercase()
        if (product.contains("sdk") || product.contains("emulator") ||
            product.startsWith("vbox") || product.startsWith("nox")
        ) signal("Build.PRODUCT is '${Build.PRODUCT}'", Severity.MEDIUM)

        val brand = Build.BRAND.lowercase()
        if (brand == "generic" || brand == "android_x86" || brand == "google_sdk")
            signal("Build.BRAND is '${Build.BRAND}'", Severity.MEDIUM)

        return signals
    }

    // ── Hidden system properties (reflection) ─────────────────────────────────

    private fun checkSystemProperties(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        try {
            val clazz = Class.forName("android.os.SystemProperties")
            val get = clazz.getMethod("get", String::class.java, String::class.java)

            SYSTEM_PROP_CHECKS.forEach { (prop, badValues) ->
                val value = (get.invoke(null, prop, "") as? String)?.lowercase().orEmpty()
                if (value.isNotEmpty() && badValues.any { value.contains(it) }) {
                    signals += DetectionSignal(
                        SignalCategory.SYSTEM_PROPERTY,
                        "System property [$prop=$value]",
                        Severity.HIGH,
                    )
                }
            }
        } catch (_: Exception) { /* reflection unavailable */ }
        return signals
    }

    // ── QEMU / emulator file artifacts ───────────────────────────────────────

    private fun checkEmulatorFiles(): List<DetectionSignal> =
        EMULATOR_PATHS.filter { File(it).exists() }.map { path ->
            DetectionSignal(SignalCategory.SUSPICIOUS_PATH, "Emulator file found: $path", Severity.HIGH)
        }

    // ── /proc/cpuinfo ─────────────────────────────────────────────────────────

    private fun checkCpuInfo(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        try {
            // "goldfish" split to avoid plain-text extraction — see class-level doc.
            val goldfish = charArrayOf('g', 'o', 'l', 'd', 'f', 'i', 's', 'h').concatToString()
            val cpuInfo = File("/proc/cpuinfo").readText().lowercase()
            listOf(goldfish, "qemu", "virtual cpu", "android x86").forEach { marker ->
                if (cpuInfo.contains(marker)) {
                    signals += DetectionSignal(
                        SignalCategory.EMULATOR,
                        "/proc/cpuinfo contains emulator marker: '$marker'",
                        Severity.HIGH,
                    )
                }
            }
        } catch (_: Exception) {}
        return signals
    }

    private companion object {
        val EMULATOR_PATHS = listOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/dev/socket/genyd",           // Genymotion
            "/dev/socket/baseband_genyd",  // Genymotion
            "/system/lib/libdroid4x.so",   // Droid4X
            "/system/bin/windroyed",       // WindROY
            "/system/bin/nox-prop",        // Nox
            "/system/lib/libnoxspeedup.so",// Nox
        )

        val SYSTEM_PROP_CHECKS = mapOf(
            "ro.kernel.qemu"             to listOf("1"),
            "ro.boot.qemu"               to listOf("1"),
            "ro.product.model"           to listOf("sdk", "emulator", "google_sdk"),
            "ro.hardware"                to listOf("goldfish", "ranchu", "vbox86", "ttvm"),
            "ro.product.brand"           to listOf("generic", "android_x86"),
            "ro.product.manufacturer"    to listOf("genymotion"),
            "init.svc.qemud"             to listOf("running"),
            "init.svc.qemu-props"        to listOf("running"),
            "ro.boot.selinux"            to listOf("permissive"),  // emulators often permissive
        )
    }
}

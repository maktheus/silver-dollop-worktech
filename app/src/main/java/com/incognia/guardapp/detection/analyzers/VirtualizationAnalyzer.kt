package com.incognia.guardapp.detection.analyzers

import android.content.Context
import com.incognia.guardapp.detection.DetectionSignal
import com.incognia.guardapp.detection.EnvironmentAnalyzer
import com.incognia.guardapp.detection.Severity
import com.incognia.guardapp.detection.SignalCategory
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Detects dynamic instrumentation and hooking frameworks:
 *  - Xposed / LSPosed (file artifacts + ClassLoader probe)
 *  - Frida (port probe on 27042 + /proc/net/tcp + /proc/self/maps)
 *  - Cydia Substrate / Magisk (file artifacts)
 *  - VirtualApp hook layer (/proc/self/maps)
 *
 * The ClassLoader probe for XposedBridge relies on the fact that
 * Xposed injects its JAR into every app's classloader at startup.
 * On a clean device the class will not be found.
 *
 * Frida's default server port (27042) is probed with a short timeout
 * so the check is fast even on clean devices.
 */
class VirtualizationAnalyzer : EnvironmentAnalyzer {

    override fun analyze(context: Context): List<DetectionSignal> =
        checkHookFiles() +
            checkProcMaps() +
            checkXposedClassLoader() +
            checkFrida()

    // ── File artifacts ────────────────────────────────────────────────────────

    private fun checkHookFiles(): List<DetectionSignal> =
        HOOK_PATHS.filter { File(it).exists() }.map { path ->
            DetectionSignal(
                SignalCategory.VIRTUALIZATION,
                "Hook/virtualization file found: $path",
                Severity.HIGH,
            )
        }

    // ── /proc/self/maps ───────────────────────────────────────────────────────

    private fun checkProcMaps(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        val reported = mutableSetOf<String>()
        try {
            File("/proc/self/maps").forEachLine { line ->
                MAP_PATTERNS.forEach { (pattern, label) ->
                    if (pattern !in reported && line.contains(pattern, ignoreCase = true)) {
                        reported += pattern
                        signals += DetectionSignal(
                            SignalCategory.VIRTUALIZATION,
                            "$label detected in /proc/self/maps",
                            Severity.HIGH,
                        )
                    }
                }
            }
        } catch (_: Exception) {}
        return signals
    }

    // ── XposedBridge ClassLoader probe ────────────────────────────────────────

    private fun checkXposedClassLoader(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        XPOSED_CLASS_NAMES.forEach { className ->
            try {
                Class.forName(className)
                signals += DetectionSignal(
                    SignalCategory.VIRTUALIZATION,
                    "Xposed class accessible in classloader: $className",
                    Severity.HIGH,
                )
            } catch (_: ClassNotFoundException) { /* expected on clean device */ }
        }
        return signals
    }

    // ── Frida detection ───────────────────────────────────────────────────────

    private fun checkFrida(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()

        // Port probe — Frida server listens on 27042 by default.
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", FRIDA_PORT), SOCKET_TIMEOUT_MS)
                signals += DetectionSignal(
                    SignalCategory.VIRTUALIZATION,
                    "Frida server responding on localhost:$FRIDA_PORT",
                    Severity.HIGH,
                )
            }
        } catch (_: Exception) { /* not listening */ }

        // /proc/net/tcp fallback — port 27042 = 0x699A in little-endian hex.
        // Avoids the network overhead when Frida is not present.
        try {
            val fridaPortHex = "%04X".format(FRIDA_PORT)
            if (File("/proc/net/tcp").readText().contains(fridaPortHex, ignoreCase = true)) {
                if (signals.none { it.description.contains("Frida server") }) {
                    signals += DetectionSignal(
                        SignalCategory.VIRTUALIZATION,
                        "Frida-default port ($FRIDA_PORT / 0x$fridaPortHex) open per /proc/net/tcp",
                        Severity.MEDIUM,
                    )
                }
            }
        } catch (_: Exception) {}

        return signals
    }

    private companion object {
        const val FRIDA_PORT = 27042
        const val SOCKET_TIMEOUT_MS = 150

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

        val MAP_PATTERNS = mapOf(
            "frida"       to "Frida instrumentation framework",
            "xposed"      to "Xposed framework",
            "substrate"   to "Cydia Substrate",
            "va.hook"     to "VirtualApp hook layer",
            "virtualapp"  to "VirtualApp framework",
        )

        val XPOSED_CLASS_NAMES = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers",
        )
    }
}

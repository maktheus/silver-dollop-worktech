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

        // /proc/net/tcp fallback — parse column-by-column to avoid false positives.
        // Format: sl  local_address(IP:PORT)  rem_address  st  ...
        // local_address is "XXXXXXXX:PPPP" where IP is little-endian hex and PORT is big-endian hex.
        // State 0A = TCP_LISTEN. We require a LISTEN socket on the local side to confirm Frida.
        if (signals.none { it.description.contains("Frida server") }) {
            signals += checkFridaTcpTable("/proc/net/tcp")
            signals += checkFridaTcpTable("/proc/net/tcp6")
        }

        return signals
    }

    /**
     * Parses /proc/net/tcp (or tcp6) properly to avoid false positives.
     *
     * Each data row has the form:
     *   sl  local_address  rem_address  st  tx_queue:rx_queue  ...
     * where local_address = "XXXXXXXX:PPPP" (little-endian IP hex, big-endian port hex)
     * and st = "0A" means TCP_LISTEN.
     *
     * We only flag when the local port matches Frida's default AND the socket is in
     * LISTEN state, preventing false positives from remote-endpoint fields.
     */
    private fun checkFridaTcpTable(path: String): List<DetectionSignal> =
        runCatching { parseTcpTable(File(path).readLines(), path) }.getOrDefault(emptyList())

    /**
     * Pure parser exposed as [internal] so unit tests can feed synthetic rows
     * without touching the real filesystem.
     *
     * /proc/net/tcp row layout (whitespace-delimited):
     *   sl  local_address  rem_address  st  tx_queue  ...
     * local_address = "XXXXXXXX:PPPP" (IP little-endian hex, port big-endian hex)
     * st = "0A" means TCP_LISTEN.
     *
     * We match only when the LOCAL port equals [FRIDA_PORT] AND the socket
     * is in LISTEN state, so remote-endpoint fields with the same hex value
     * do not produce false positives.
     */
    internal fun parseTcpTable(lines: List<String>, sourcePath: String = ""): List<DetectionSignal> {
        // Hardcode the expected port hex to avoid any private-companion-object
        // constant-inlining edge cases when called from an `internal` function.
        // 27042 = 0x699A
        val fridaPortHex = "699A"
        val signals = mutableListOf<DetectionSignal>()
        for (line in lines) {
            val parts = line.trim().split(" ").filter { it.isNotEmpty() }
            if (parts.size >= 4) {
                val localPort = parts[1].substringAfter(":", missingDelimiterValue = "")
                val state = parts[3]
                if (localPort.equals(fridaPortHex, ignoreCase = true) && state.equals("0A", ignoreCase = true)) {
                    signals += DetectionSignal(
                        SignalCategory.VIRTUALIZATION,
                        "Frida-default port ($FRIDA_PORT) in LISTEN state" +
                            if (sourcePath.isNotEmpty()) " per $sourcePath" else "",
                        Severity.MEDIUM,
                    )
                }
            }
        }
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

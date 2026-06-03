package com.incognia.guardapp.detection.analyzers

import android.content.Context
import com.incognia.guardapp.detection.DetectionSignal
import com.incognia.guardapp.detection.DetectionSignatures
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
        DetectionSignatures.HOOK_PATHS.filter { File(it).exists() }.map { path ->
            DetectionSignal(
                SignalCategory.VIRTUALIZATION,
                "Hook/virtualization file found: $path",
                Severity.HIGH,
                "Arquivo de um framework de instrumentação/hooking encontrado. Indica que a ferramenta " +
                    "foi instalada ou está preparada para execução neste dispositivo.",
            )
        }

    // ── /proc/self/maps ───────────────────────────────────────────────────────

    private fun checkProcMaps(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        val reported = mutableSetOf<String>()
        try {
            File("/proc/self/maps").forEachLine { line ->
                DetectionSignatures.HOOK_MAP_PATTERNS.forEach { (pattern, label) ->
                    if (pattern !in reported && line.contains(pattern, ignoreCase = true)) {
                        reported += pattern
                        signals += DetectionSignal(
                            SignalCategory.VIRTUALIZATION,
                            "$label detected in /proc/self/maps",
                            Severity.HIGH,
                            "Biblioteca nativa de '$label' mapeada no espaço de memória deste processo. " +
                                "Isso indica que o framework está ativo e pode estar interceptando " +
                                "chamadas de método em tempo de execução.",
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
        DetectionSignatures.XPOSED_CLASS_NAMES.forEach { className ->
            try {
                Class.forName(className)
                signals += DetectionSignal(
                    SignalCategory.VIRTUALIZATION,
                    "Xposed class accessible in classloader: $className",
                    Severity.HIGH,
                    "O Xposed/LSPosed injeta automaticamente XposedBridge.jar no classloader de todo " +
                        "processo ao iniciar. Se a classe é resolvível, o framework está ativo e pode " +
                        "interceptar e modificar qualquer método Java/Kotlin em tempo de execução.",
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
                    "O Frida é um framework de instrumentação dinâmica que permite interceptar e " +
                        "modificar qualquer código em execução em tempo real, incluindo chamadas de " +
                        "criptografia, autenticação e lógica de segurança. Porta padrão $FRIDA_PORT respondendo.",
                )
            }
        } catch (_: Exception) { /* not listening */ }

        // /proc/net/tcp fallback — parse column-by-column to avoid false positives.
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
     */
    internal fun parseTcpTable(lines: List<String>, sourcePath: String = ""): List<DetectionSignal> {
        // 27042 = 0x69A2 (hardcoded to avoid constant-inlining edge cases in internal fun)
        val fridaPortHex = "69A2"
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
                        "Entrada no /proc/net/tcp mostra a porta $FRIDA_PORT em estado LISTEN (0A). " +
                            "O servidor Frida está aguardando conexão de scripts de instrumentação, " +
                            "mesmo que a conexão TCP direta tenha falhado.",
                    )
                }
            }
        }
        return signals
    }

    private companion object {
        // Behavioral constants — timeouts and port numbers belong here,
        // not in DetectionSignatures (which holds threat-intelligence data).
        const val FRIDA_PORT = 27042
        const val SOCKET_TIMEOUT_MS = 150
    }
}

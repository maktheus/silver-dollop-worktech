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

        fun signal(desc: String, severity: Severity = Severity.HIGH, explanation: String = "") =
            signals.add(DetectionSignal(SignalCategory.EMULATOR, desc, severity, explanation))

        val fp = Build.FINGERPRINT.lowercase()
        if (fp.startsWith("generic") || fp.startsWith("unknown") ||
            fp.contains("emulator") || fp.contains("sdk_gphone") || fp.contains(":eng/")
        ) signal(
            "Build.FINGERPRINT matches emulator pattern: ${Build.FINGERPRINT}",
            explanation = "O fingerprint do build contém padrões de emulador (generic, sdk_gphone). " +
                "Dispositivos reais têm fingerprints únicos do fabricante com modelo e versão de build específicos.",
        )

        val model = Build.MODEL.lowercase()
        if (model == "sdk" || model.contains("emulator") ||
            model.contains("google sdk") || model.contains("sdk built for x86")
        ) signal(
            "Build.MODEL matches emulator: ${Build.MODEL}",
            explanation = "O modelo reportado ('SDK', 'emulator') é um identificador padrão do Android Virtual Device. " +
                "Dispositivos reais têm nomes comerciais como 'Pixel 9 Pro' ou 'Galaxy S25'.",
        )

        val manufacturer = Build.MANUFACTURER.lowercase()
        if (manufacturer.contains("genymotion") || manufacturer == "unknown")
            signal(
                "Build.MANUFACTURER is '${Build.MANUFACTURER}'",
                explanation = "'Genymotion' é um emulador comercial. 'unknown' indica que o fabricante não foi definido — " +
                    "impossível em dispositivos comerciais.",
            )

        val hardware = Build.HARDWARE.lowercase()
        if (hardware in setOf("goldfish", "ranchu", "vbox86", "vbox64", "ttvm_x86", "nox"))
            signal(
                "Emulator hardware detected: ${Build.HARDWARE}",
                explanation = "'goldfish' e 'ranchu' são os nomes do hardware virtual do emulador QEMU padrão do Android. " +
                    "Esse valor reflete diretamente o tipo de CPU simulada — inexistente em qualquer hardware físico.",
            )

        val product = Build.PRODUCT.lowercase()
        if (product.contains("sdk") || product.contains("emulator") ||
            product.startsWith("vbox") || product.startsWith("nox")
        ) signal(
            "Build.PRODUCT is '${Build.PRODUCT}'",
            Severity.MEDIUM,
            explanation = "O nome do produto contém 'sdk' ou 'emulator', identificadores do AVD padrão. " +
                "Dispositivos reais têm nomes de produto como 'shiba' (Pixel 9 Pro) ou 'dm3q' (Galaxy S23).",
        )

        val brand = Build.BRAND.lowercase()
        if (brand == "generic" || brand == "android_x86" || brand == "google_sdk")
            signal(
                "Build.BRAND is '${Build.BRAND}'",
                Severity.MEDIUM,
                explanation = "A marca 'generic' ou 'android_x86' é gerada por builds de emulador. " +
                    "Produtos comerciais sempre têm uma marca registrada (Google, Samsung, Xiaomi…).",
            )

        return signals
    }

    // ── Hidden system properties (reflection) ─────────────────────────────────

    private fun checkSystemProperties(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        try {
            val clazz = Class.forName("android.os.SystemProperties")
            val get = clazz.getMethod("get", String::class.java, String::class.java)

            SYSTEM_PROP_CHECKS.forEach { (prop, badValues, explanation) ->
                val value = (get.invoke(null, prop, "") as? String)?.lowercase().orEmpty()
                if (value.isNotEmpty() && badValues.any { value.contains(it) }) {
                    signals += DetectionSignal(
                        SignalCategory.SYSTEM_PROPERTY,
                        "System property [$prop=$value]",
                        Severity.HIGH,
                        explanation,
                    )
                }
            }
        } catch (_: Exception) { /* reflection unavailable */ }
        return signals
    }

    // ── QEMU / emulator file artifacts ───────────────────────────────────────

    private fun checkEmulatorFiles(): List<DetectionSignal> =
        EMULATOR_PATHS.filter { File(it).exists() }.map { path ->
            DetectionSignal(
                SignalCategory.SUSPICIOUS_PATH,
                "Emulator file found: $path",
                Severity.HIGH,
                "Arquivo/socket específico do QEMU encontrado. Esses arquivos são criados " +
                    "exclusivamente pelo emulador Android — nunca presentes em hardware físico real.",
            )
        }

    // ── /proc/cpuinfo ─────────────────────────────────────────────────────────

    private fun checkCpuInfo(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        try {
            val goldfish = charArrayOf('g', 'o', 'l', 'd', 'f', 'i', 's', 'h').concatToString()
            val cpuInfo = File("/proc/cpuinfo").readText().lowercase()
            listOf(goldfish to "goldfish", "qemu" to "qemu", "virtual cpu" to "virtual cpu", "android x86" to "android x86")
                .forEach { (marker, label) ->
                    if (cpuInfo.contains(marker)) {
                        signals += DetectionSignal(
                            SignalCategory.EMULATOR,
                            "/proc/cpuinfo contains emulator marker: '$label'",
                            Severity.HIGH,
                            "O arquivo /proc/cpuinfo expõe o tipo de CPU do hardware. '$label' identifica " +
                                "a CPU virtual do emulador Android — um processador físico nunca reporta esse valor.",
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

        data class PropCheck(val prop: String, val badValues: List<String>, val explanation: String)

        val SYSTEM_PROP_CHECKS = listOf(
            PropCheck("ro.kernel.qemu", listOf("1"),
                "Propriedade ativada pelo kernel QEMU para autoidentificação como máquina virtual. Ausente em kernels de dispositivos reais."),
            PropCheck("ro.boot.qemu", listOf("1"),
                "Flag de boot do QEMU indicando inicialização em ambiente virtualizado."),
            PropCheck("ro.product.model", listOf("sdk", "emulator", "google_sdk"),
                "Modelo do produto com identificadores de emulador — atribuído pelo build system do AVD, não por um OEM real."),
            PropCheck("ro.hardware", listOf("goldfish", "ranchu", "vbox86", "ttvm"),
                "Hardware virtual do emulador QEMU. 'goldfish' e 'ranchu' são os dois perfis de hardware do AVD padrão."),
            PropCheck("ro.product.brand", listOf("generic", "android_x86"),
                "Marca genérica típica de builds de emulador ou projetos de desenvolvimento sem OEM definido."),
            PropCheck("ro.product.manufacturer", listOf("genymotion"),
                "Fabricante 'genymotion' identifica o emulador comercial Genymotion, popular entre desenvolvedores."),
            PropCheck("init.svc.qemud", listOf("running"),
                "Serviço qemud em execução — daemon específico do QEMU para comunicação entre guest e host."),
            PropCheck("init.svc.qemu-props", listOf("running"),
                "Serviço qemu-props em execução — inicia e expõe propriedades do ambiente QEMU ao sistema Android."),
            PropCheck("ro.boot.selinux", listOf("permissive"),
                "SELinux em modo permissivo: emuladores frequentemente desativam o enforcement do SELinux para facilitar o desenvolvimento."),
        )
    }
}

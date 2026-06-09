package com.incognia.guardapp.detection.analyzers

import android.content.Context
import com.incognia.guardapp.detection.DetectionSignal
import com.incognia.guardapp.detection.DetectionSignatures
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
        DetectionSignatures.SU_PATHS.filter { fileProbe(it) }.map { path ->
            DetectionSignal(
                SignalCategory.ROOT,
                "Root binary found: $path",
                Severity.HIGH,
                "Binário 'su' (switch user) encontrado. Esse executável concede privilégios de " +
                    "superusuário a qualquer processo que o invoque, permitindo bypass de todas " +
                    "as proteções implementadas em userspace.",
            )
        }

    // ── 2. Root management apps ───────────────────────────────────────────────

    private fun checkRootManagementApps(context: Context): List<DetectionSignal> =
        DetectionSignatures.ROOT_PACKAGES.mapNotNull { pkg ->
            if (packageChecker(context, pkg)) {
                DetectionSignal(
                    SignalCategory.ROOT,
                    "Root management app installed: $pkg",
                    Severity.HIGH,
                    "Aplicativo de gerenciamento root encontrado. Com root ativo, o atacante tem " +
                        "controle total do sistema — pode modificar memória, interceptar chamadas de " +
                        "sistema e bypassar qualquer verificação de segurança em nível de aplicativo.",
                )
            } else null
        }

    // ── 3. Dangerous system properties ───────────────────────────────────────

    internal fun checkDangerousProps(): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        try {
            val clazz = Class.forName("android.os.SystemProperties")
            val get = clazz.getMethod("get", String::class.java, String::class.java)
            DetectionSignatures.ROOT_PROP_CHECKS.forEach { (prop, badValues) ->
                val value = (get.invoke(null, prop, "") as? String)?.lowercase().orEmpty()
                if (value.isNotEmpty() && badValues.any { value.contains(it) }) {
                    val explanation = when (prop) {
                        "ro.debuggable" ->
                            "ro.debuggable=1 habilita depuração de qualquer processo do sistema via JDWP, " +
                                "incluindo apps com android:debuggable=false. Exclusivo de builds de engenharia ou root."
                        "ro.secure" ->
                            "ro.secure=0 desabilita a verificação de segurança do shell adb, " +
                                "concedendo shell root sem autenticação. Impossível em builds de produção."
                        "ro.build.type" ->
                            "Build type '$value' indica imagem de desenvolvimento (eng) ou com depuração ativada " +
                                "(userdebug). Builds de produção sempre usam 'user'."
                        else -> "Propriedade de sistema com valor indicativo de ambiente não-produção ou root."
                    }
                    signals += DetectionSignal(
                        SignalCategory.SYSTEM_PROPERTY,
                        "Root-indicative system property [$prop=$value]",
                        Severity.HIGH,
                        explanation,
                    )
                }
            }
        } catch (_: Exception) {}
        return signals
    }

    // ── 4. Writable system partitions ─────────────────────────────────────────

    internal fun checkWritableSystemPaths(): List<DetectionSignal> =
        DetectionSignatures.WRITABLE_SYSTEM_PATHS.filter { writableProbe(it) }.map { path ->
            DetectionSignal(
                SignalCategory.ROOT,
                "System path is writable — indicates root mount: $path",
                Severity.HIGH,
                "A partição $path está montada com permissão de escrita. Em dispositivos stock, " +
                    "essas partições são sempre somente leitura. Escrita habilitada indica remount " +
                    "manual via root — o atacante pode modificar binários do sistema.",
            )
        }
}

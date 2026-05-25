package com.incognia.guardapp.detection.analyzers

import android.content.Context
import android.os.Process
import com.incognia.guardapp.detection.DetectionSignal
import com.incognia.guardapp.detection.DetectionSignatures
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
        DetectionSignatures.KNOWN_CLONE_PACKAGES.mapNotNull { pkg ->
            if (packageChecker(context, pkg)) {
                DetectionSignal(
                    SignalCategory.CLONE_APP,
                    "Clone/virtual-space app installed: $pkg",
                    Severity.HIGH,
                    "App de espaço virtual instalado. Esses frameworks criam um sandbox que pode " +
                        "isolar verificações de segurança — o app protegido roda 'dentro' do clone " +
                        "sem acesso direto ao ambiente real.",
                )
            } else null
        }

    // ── 2. File artifacts ─────────────────────────────────────────────────────

    private fun checkCloneArtifactFiles(): List<DetectionSignal> =
        DetectionSignatures.CLONE_ARTIFACT_PATHS.filter { fileProbe(it) }.map { path ->
            DetectionSignal(
                SignalCategory.SUSPICIOUS_PATH,
                "Clone framework artifact: $path",
                Severity.HIGH,
                "Diretório de dados de um clone framework encontrado em disco. Persiste mesmo após " +
                    "desinstalação do app clone, indicando uso anterior ou ativo do framework neste dispositivo.",
            )
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
                "O Android atribui UIDs em blocos de 100.000 por usuário. UID ÷ 100.000 = $userId " +
                    "indica que o app roda em um perfil secundário — técnica usada por clones para " +
                    "isolar instâncias do mesmo app.",
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
                "Frameworks de clonagem redirecionam o dataDir do app para fora do caminho primário " +
                    "(/data/data/ ou /data/user/0/), colocando-o dentro do próprio container virtual. " +
                    "Difícil de falsificar sem root.",
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
                DetectionSignatures.CLONE_MAP_PATTERNS.forEach { (pattern, label) ->
                    if (pattern !in reported && line.contains(pattern, ignoreCase = true)) {
                        reported += pattern
                        signals += DetectionSignal(
                            SignalCategory.CLONE_APP,
                            "$label detected in /proc/self/maps",
                            Severity.HIGH,
                            "Biblioteca nativa do clone framework carregada no espaço de memória deste processo. " +
                                "Diferente do nome do pacote (fácil de renomear), o path da .so compilada " +
                                "geralmente preserva o namespace original do framework.",
                        )
                    }
                }
            }
        } catch (_: Exception) {}
        return signals
    }
}

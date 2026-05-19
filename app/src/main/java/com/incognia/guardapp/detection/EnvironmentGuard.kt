package com.incognia.guardapp.detection

import android.content.Context
import com.incognia.guardapp.detection.analyzers.CloneAnalyzer
import com.incognia.guardapp.detection.analyzers.EmulatorAnalyzer
import com.incognia.guardapp.detection.analyzers.SignatureAnalyzer
import com.incognia.guardapp.detection.analyzers.VirtualizationAnalyzer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

/**
 * Facade for runtime environment analysis.
 *
 * Each [EnvironmentAnalyzer] runs in parallel on [Dispatchers.Default] so that
 * file-system and network probes do not block each other. Any individual probe
 * failure is silently swallowed so that a single crash cannot suppress the
 * entire report.
 *
 * Adding new detection domains only requires implementing [EnvironmentAnalyzer]
 * and adding an instance to [analyzers].
 */
class EnvironmentGuard private constructor(private val context: Context) {

    private val analyzers: List<EnvironmentAnalyzer> = listOf(
        EmulatorAnalyzer(),
        CloneAnalyzer(),
        VirtualizationAnalyzer(),
        SignatureAnalyzer(),
    )

    suspend fun generateReport(): SecurityReport = coroutineScope {
        val deferred = analyzers.map { analyzer ->
            async(Dispatchers.Default) {
                runCatching { analyzer.analyze(context) }.getOrDefault(emptyList())
            }
        }
        SecurityReport(deferred.awaitAll().flatten())
    }

    companion object {
        fun create(context: Context): EnvironmentGuard =
            EnvironmentGuard(context.applicationContext)
    }
}

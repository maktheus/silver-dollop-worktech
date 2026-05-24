package com.incognia.guardapp.detection

import android.content.Context
import com.incognia.guardapp.detection.analyzers.CloneAnalyzer
import com.incognia.guardapp.detection.analyzers.EmulatorAnalyzer
import com.incognia.guardapp.detection.analyzers.RootDetector
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
 * Use [create] for production. Use [create] with a custom [analyzers] list
 * to inject fakes/mocks in tests.
 */
class EnvironmentGuard private constructor(
    private val context: Context,
    private val analyzers: List<EnvironmentAnalyzer>,
) {

    suspend fun generateReport(): SecurityReport = coroutineScope {
        val deferred = analyzers.map { analyzer ->
            async(Dispatchers.Default) {
                runCatching { analyzer.analyze(context) }.getOrDefault(emptyList())
            }
        }
        SecurityReport(deferred.awaitAll().flatten())
    }

    companion object {
        /** Production entry point — uses all built-in analyzers. */
        fun create(context: Context): EnvironmentGuard = create(
            context,
            listOf(
                EmulatorAnalyzer(),
                CloneAnalyzer(),
                VirtualizationAnalyzer(),
                SignatureAnalyzer(),
                RootDetector(),
            ),
        )

        /** Test / custom entry point — inject any list of analyzers. */
        fun create(
            context: Context,
            analyzers: List<EnvironmentAnalyzer>,
        ): EnvironmentGuard = EnvironmentGuard(context.applicationContext, analyzers)
    }
}

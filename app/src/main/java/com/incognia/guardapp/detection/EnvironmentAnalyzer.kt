package com.incognia.guardapp.detection

import android.content.Context

/**
 * Each concrete analyzer handles one detection domain.
 *
 * Declared as a [fun interface] (SAM) so tests can pass a lambda directly:
 *   val fake = EnvironmentAnalyzer { listOf(signal) }
 */
fun interface EnvironmentAnalyzer {
    fun analyze(context: Context): List<DetectionSignal>
}

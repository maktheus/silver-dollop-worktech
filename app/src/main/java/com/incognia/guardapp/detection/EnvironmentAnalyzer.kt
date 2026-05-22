package com.incognia.guardapp.detection

import android.content.Context

/** Each concrete analyzer handles one detection domain. */
interface EnvironmentAnalyzer {
    fun analyze(context: Context): List<DetectionSignal>
}

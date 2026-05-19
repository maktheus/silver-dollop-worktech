package com.incognia.guardapp.detection

data class SecurityReport(val signals: List<DetectionSignal>) {

    /** An environment is considered tampered when at least one MEDIUM or HIGH signal is found. */
    val isTampered: Boolean
        get() = signals.any { it.severity != Severity.LOW }

    val highSignals: List<DetectionSignal>
        get() = signals.filter { it.severity == Severity.HIGH }

    val mediumSignals: List<DetectionSignal>
        get() = signals.filter { it.severity == Severity.MEDIUM }

    val infoSignals: List<DetectionSignal>
        get() = signals.filter { it.severity == Severity.LOW }

    val riskScore: Int
        get() = signals.sumOf {
            when (it.severity) {
                Severity.HIGH -> 3
                Severity.MEDIUM -> 1
                Severity.LOW -> 0
            }
        }
}

package com.incognia.guardapp.detection

enum class SignalCategory(val displayName: String) {
    EMULATOR("Emulator"),
    CLONE_APP("Clone / Dual-Space App"),
    VIRTUALIZATION("Virtualization / Hooking"),
    ROOT("Root / Superuser"),
    SIGNATURE("Signature / Integrity"),
    SUSPICIOUS_PATH("Suspicious Path"),
    SYSTEM_PROPERTY("Suspicious System Property"),
}

/**
 * LOW  = informational, not evidence of tampering on its own
 * MEDIUM = suspicious, raises risk score
 * HIGH   = strong indicator of a tampered environment
 */
enum class Severity { LOW, MEDIUM, HIGH }

data class DetectionSignal(
    val category: SignalCategory,
    val description: String,
    val severity: Severity,
    /** Human-readable explanation of why this signal matters and what it means. */
    val explanation: String = "",
)

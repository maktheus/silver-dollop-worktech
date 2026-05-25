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
        get() = signals.sumOf { signal ->
            when (signal.severity) {
                Severity.HIGH -> 3
                Severity.MEDIUM -> 1
                Severity.LOW -> 0
            }.toInt()
        }

    /**
     * Probability (0.0–1.0) that this device is an emulator, based on independent
     * emulator-specific evidence sources.
     *
     * Uses cumulative independent evidence: P = 1 − ∏(1 − pᵢ)
     * Each HIGH emulator signal contributes 80% per independent source.
     * Each MEDIUM emulator signal contributes 50%.
     */
    val emulatorProbability: Float
        get() {
            val emulatorSignals = signals.filter {
                it.category == SignalCategory.EMULATOR ||
                    (it.category == SignalCategory.SYSTEM_PROPERTY &&
                        it.description.contains("qemu", ignoreCase = true)) ||
                    (it.category == SignalCategory.SUSPICIOUS_PATH &&
                        it.description.contains("emulator file", ignoreCase = true))
            }
            if (emulatorSignals.isEmpty()) return 0f
            var p = 0.0
            emulatorSignals.forEach { signal ->
                p += (1.0 - p) * when (signal.severity) {
                    Severity.HIGH   -> 0.80
                    Severity.MEDIUM -> 0.50
                    Severity.LOW    -> 0.10
                }
            }
            return p.toFloat().coerceIn(0f, 1f)
        }

    /**
     * Human-readable analysis of the overall security state, suitable for display
     * directly in the app UI.
     */
    val summary: String
        get() {
            val tamperedCategories = signals
                .filter { it.severity != Severity.LOW }
                .map { it.category }
                .toSet()

            if (tamperedCategories.isEmpty()) return buildString {
                append("Nenhum indicador de adulteração detectado. ")
                append("O ambiente parece ser um dispositivo Android legítimo e não modificado.")
            }

            return buildString {
                if (emulatorProbability > 0f) {
                    val pct = (emulatorProbability * 100).toInt()
                    val confidence = when {
                        pct >= 85 -> "alta confiança"
                        pct >= 55 -> "confiança moderada"
                        else      -> "baixa confiança"
                    }
                    append("Emulador detectado ($pct%, $confidence). ")
                    append("Múltiplas técnicas de fingerprinting independentes confirmam execução em ambiente virtual. ")
                }
                if (SignalCategory.ROOT in tamperedCategories) {
                    append("Dispositivo rooteado: root concede acesso irrestrito ao sistema, ")
                    append("contornando qualquer proteção implementada em userspace. ")
                }
                if (SignalCategory.CLONE_APP in tamperedCategories) {
                    append("App clone ativo: frameworks de virtualização podem interceptar ")
                    append("chamadas de sistema e isolar o app de verificações de segurança reais. ")
                }
                if (SignalCategory.VIRTUALIZATION in tamperedCategories) {
                    append("Ferramenta de hook detectada (Frida/Xposed): o código do app pode ")
                    append("estar sendo interceptado e modificado em tempo de execução. ")
                }
                if (SignalCategory.SIGNATURE in tamperedCategories) {
                    if (signals.any { it.severity == Severity.HIGH && it.category == SignalCategory.SIGNATURE }) {
                        append("Integridade da assinatura comprometida: o APK pode ter sido ")
                        append("reempacotado ou adulterado por terceiros.")
                    } else {
                        append("App instalado via chave de debug ou fonte desconhecida. ")
                        append("Em produção, distribua via Play Store com chave de release própria.")
                    }
                }
            }.trimEnd()
        }
}

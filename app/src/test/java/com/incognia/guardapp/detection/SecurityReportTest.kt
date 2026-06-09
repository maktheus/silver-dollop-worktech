package com.incognia.guardapp.detection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityReportTest {

    private fun signal(severity: Severity, category: SignalCategory = SignalCategory.EMULATOR) =
        DetectionSignal(category, "test signal [$severity]", severity)

    // ── isTampered ────────────────────────────────────────────────────────────

    @Test
    fun `empty report is not tampered`() {
        assertFalse(SecurityReport(emptyList()).isTampered)
    }

    @Test
    fun `report with only LOW signals is not tampered`() {
        val report = SecurityReport(listOf(signal(Severity.LOW), signal(Severity.LOW)))
        assertFalse(report.isTampered)
    }

    @Test
    fun `report with MEDIUM signal is tampered`() {
        val report = SecurityReport(listOf(signal(Severity.LOW), signal(Severity.MEDIUM)))
        assertTrue(report.isTampered)
    }

    @Test
    fun `report with HIGH signal is tampered`() {
        assertTrue(SecurityReport(listOf(signal(Severity.HIGH))).isTampered)
    }

    // ── riskScore ─────────────────────────────────────────────────────────────

    @Test
    fun `empty report has zero risk score`() {
        assertEquals(0, SecurityReport(emptyList()).riskScore)
    }

    @Test
    fun `risk score sums HIGH=3 MEDIUM=1 LOW=0`() {
        val report = SecurityReport(
            listOf(
                signal(Severity.HIGH),    // +3
                signal(Severity.HIGH),    // +3
                signal(Severity.MEDIUM),  // +1
                signal(Severity.LOW),     // +0
            )
        )
        assertEquals(7, report.riskScore)
    }

    @Test
    fun `LOW signals do not contribute to risk score`() {
        val report = SecurityReport(List(10) { signal(Severity.LOW) })
        assertEquals(0, report.riskScore)
    }

    // ── grouped accessors ─────────────────────────────────────────────────────

    @Test
    fun `highSignals returns only HIGH severity signals`() {
        val report = SecurityReport(
            listOf(signal(Severity.HIGH), signal(Severity.MEDIUM), signal(Severity.LOW))
        )
        assertEquals(1, report.highSignals.size)
        assertTrue(report.highSignals.all { it.severity == Severity.HIGH })
    }

    @Test
    fun `mediumSignals returns only MEDIUM severity signals`() {
        val report = SecurityReport(
            listOf(signal(Severity.HIGH), signal(Severity.MEDIUM), signal(Severity.LOW))
        )
        assertEquals(1, report.mediumSignals.size)
        assertTrue(report.mediumSignals.all { it.severity == Severity.MEDIUM })
    }

    @Test
    fun `infoSignals returns only LOW severity signals`() {
        val report = SecurityReport(
            listOf(signal(Severity.HIGH), signal(Severity.MEDIUM), signal(Severity.LOW))
        )
        assertEquals(1, report.infoSignals.size)
        assertTrue(report.infoSignals.all { it.severity == Severity.LOW })
    }

    @Test
    fun `signals are preserved in insertion order`() {
        val signals = listOf(
            signal(Severity.HIGH, SignalCategory.EMULATOR),
            signal(Severity.MEDIUM, SignalCategory.CLONE_APP),
            signal(Severity.LOW, SignalCategory.SIGNATURE),
        )
        val report = SecurityReport(signals)
        assertEquals(signals, report.signals)
    }
}

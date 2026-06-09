package com.incognia.guardapp.detection

import android.content.Context
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnvironmentGuardTest {

    private val ctx: Context = mockk(relaxed = true)

    private fun fakeSignal(label: String, severity: Severity = Severity.HIGH) =
        DetectionSignal(SignalCategory.EMULATOR, label, severity)

    private fun fakeAnalyzer(vararg signals: DetectionSignal): EnvironmentAnalyzer =
        EnvironmentAnalyzer { signals.toList() }

    // ── signal aggregation ────────────────────────────────────────────────────

    @Test
    fun `report contains signals from every analyzer`() = runTest {
        val s1 = fakeSignal("emulator-signal")
        val s2 = fakeSignal("clone-signal")
        val guard = EnvironmentGuard.create(ctx, listOf(fakeAnalyzer(s1), fakeAnalyzer(s2)))

        val report = guard.generateReport()

        assertEquals(2, report.signals.size)
        assertTrue(report.signals.contains(s1))
        assertTrue(report.signals.contains(s2))
    }

    @Test
    fun `empty analyzer list produces clean report`() = runTest {
        val report = EnvironmentGuard.create(ctx, emptyList()).generateReport()

        assertFalse(report.isTampered)
        assertEquals(0, report.signals.size)
    }

    // ── resilience ────────────────────────────────────────────────────────────

    @Test
    fun `crashing analyzer does not suppress other analyzers`() = runTest {
        val goodSignal = fakeSignal("good")
        val crashingAnalyzer = EnvironmentAnalyzer { throw RuntimeException("simulated crash") }
        val goodAnalyzer = fakeAnalyzer(goodSignal)

        val report = EnvironmentGuard.create(ctx, listOf(crashingAnalyzer, goodAnalyzer)).generateReport()

        assertEquals(1, report.signals.size)
        assertTrue(report.signals.contains(goodSignal))
    }

    @Test
    fun `all analyzers crashing produces empty report without exception`() = runTest {
        val allCrash = List(3) { EnvironmentAnalyzer { throw RuntimeException("crash $it") } }
        val report = EnvironmentGuard.create(ctx, allCrash).generateReport()

        assertFalse(report.isTampered)
        assertTrue(report.signals.isEmpty())
    }

    // ── isTampered reflects real signals ──────────────────────────────────────

    @Test
    fun `report is tampered when any analyzer returns HIGH signal`() = runTest {
        val analyzer = fakeAnalyzer(fakeSignal("high", Severity.HIGH))
        val report = EnvironmentGuard.create(ctx, listOf(analyzer)).generateReport()
        assertTrue(report.isTampered)
    }

    @Test
    fun `report is not tampered when all signals are LOW`() = runTest {
        val analyzer = fakeAnalyzer(fakeSignal("info", Severity.LOW))
        val report = EnvironmentGuard.create(ctx, listOf(analyzer)).generateReport()
        assertFalse(report.isTampered)
    }

    // ── risk score ────────────────────────────────────────────────────────────

    @Test
    fun `risk score accumulates across multiple analyzers`() = runTest {
        val a1 = fakeAnalyzer(fakeSignal("h1", Severity.HIGH), fakeSignal("h2", Severity.HIGH))
        val a2 = fakeAnalyzer(fakeSignal("m1", Severity.MEDIUM))
        val report = EnvironmentGuard.create(ctx, listOf(a1, a2)).generateReport()

        assertEquals(7, report.riskScore) // 3 + 3 + 1
    }
}

package com.incognia.guardapp.detection.analyzers

import android.content.Context
import io.mockk.mockk
import com.incognia.guardapp.detection.Severity
import com.incognia.guardapp.detection.SignalCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RootDetectorTest {

    private val ctx: Context = mockk(relaxed = true)

    // ── su binary detection ───────────────────────────────────────────────────

    @Test
    fun `su binary at known path triggers HIGH ROOT signal`() {
        val detector = RootDetector(fileProbe = { it == "/system/xbin/su" })
        val signals = detector.checkSuBinaries()
        assertEquals(1, signals.size)
        assertEquals(Severity.HIGH, signals[0].severity)
        assertEquals(SignalCategory.ROOT, signals[0].category)
        assertTrue(signals[0].description.contains("/system/xbin/su"))
    }

    @Test
    fun `multiple su binaries each produce a signal`() {
        val presentPaths = setOf("/system/bin/su", "/sbin/su", "/data/local/su")
        val detector = RootDetector(fileProbe = { it in presentPaths })
        assertEquals(3, detector.checkSuBinaries().size)
    }

    @Test
    fun `no su binaries produces no signals`() {
        val detector = RootDetector(fileProbe = { false })
        assertTrue(detector.checkSuBinaries().isEmpty())
    }

    // ── writable system paths ─────────────────────────────────────────────────

    @Test
    fun `writable system partition triggers HIGH ROOT signal`() {
        val detector = RootDetector(
            fileProbe = { false },
            writableProbe = { it == "/system" },
        )
        val signals = detector.checkWritableSystemPaths()
        assertEquals(1, signals.size)
        assertEquals(Severity.HIGH, signals[0].severity)
        assertTrue(signals[0].description.contains("/system"))
    }

    @Test
    fun `non-writable system paths produce no signals`() {
        val detector = RootDetector(fileProbe = { false }, writableProbe = { false })
        assertTrue(detector.checkWritableSystemPaths().isEmpty())
    }

    // ── full analyze call ────────────────────────────────────────────────────

    @Test
    fun `clean device produces no root signals`() {
        val detector = RootDetector(
            fileProbe = { false },
            writableProbe = { false },
            packageChecker = { _, _ -> false },
        )
        assertTrue(detector.analyze(ctx).none { it.category == SignalCategory.ROOT })
    }

    @Test
    fun `rooted device triggers signals across multiple categories`() {
        val detector = RootDetector(
            fileProbe = { it == "/system/bin/su" },
            writableProbe = { it == "/system" },
            packageChecker = { _, pkg -> pkg == "com.topjohnwu.magisk" },
        )
        val signals = detector.analyze(ctx)
        assertTrue(signals.any { it.description.contains("/system/bin/su") })
        assertTrue(signals.any { it.description.contains("/system") && it.description.contains("writable") })
        assertTrue(signals.any { it.description.contains("com.topjohnwu.magisk") })
    }
}

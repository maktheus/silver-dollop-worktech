package com.incognia.guardapp.detection.analyzers

import android.content.Context
import io.mockk.mockk
import com.incognia.guardapp.detection.Severity
import com.incognia.guardapp.detection.SignalCategory
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [CloneAnalyzer].
 *
 * All Android system dependencies (UID, dataDir, PackageManager) are injected
 * via constructor lambdas so these tests run on the JVM without Robolectric.
 * The [Context] mock is relaxed — only the lambdas produce actual values.
 */
class CloneAnalyzerTest {

    private val ctx: Context = mockk(relaxed = true)

    private fun analyzer(
        uid: Int = 10_065,
        dataDir: String = "/data/data/com.incognia.guardapp",
        pkgInstalled: (String) -> Boolean = { false },
        fileExists: (String) -> Boolean = { false },
    ) = CloneAnalyzer(
        uidProvider = { uid },
        fileProbe = fileExists,
        packageChecker = { _, pkg -> pkgInstalled(pkg) },
        dataDirProvider = { dataDir },
    )

    // ── UID / secondary-user detection ────────────────────────────────────────

    @Test
    fun `primary user UID (0-99999) does not trigger user-ID signal`() {
        val signals = analyzer(uid = 10_065).checkSecondaryUserEnvironment(ctx)
        assertTrue(signals.none { it.description.contains("user ID") })
    }

    @Test
    fun `UID in secondary user range (100000+) triggers HIGH clone signal`() {
        val signals = analyzer(uid = 110_065).checkSecondaryUserEnvironment(ctx)
        assertTrue(signals.any { it.severity == Severity.HIGH && it.category == SignalCategory.CLONE_APP })
    }

    @Test
    fun `boundary UID 100000 is treated as secondary user`() {
        val signals = analyzer(uid = 100_000).checkSecondaryUserEnvironment(ctx)
        assertTrue(signals.any { it.description.contains("user ID 1") })
    }

    // ── Data directory detection ───────────────────────────────────────────────

    @Test
    fun `primary data dir under data-data does not trigger data-dir signal`() {
        val signals = analyzer(dataDir = "/data/data/com.incognia.guardapp")
            .checkSecondaryUserEnvironment(ctx)
        assertTrue(signals.none { it.description.contains("data directory") })
    }

    @Test
    fun `primary data dir under data-user-0 does not trigger data-dir signal`() {
        val signals = analyzer(dataDir = "/data/user/0/com.incognia.guardapp")
            .checkSecondaryUserEnvironment(ctx)
        assertTrue(signals.none { it.description.contains("data directory") })
    }

    @Test
    fun `redirected data dir under data-user-10 triggers HIGH signal`() {
        val signals = analyzer(dataDir = "/data/user/10/com.incognia.guardapp")
            .checkSecondaryUserEnvironment(ctx)
        assertTrue(signals.any { it.severity == Severity.HIGH && it.description.contains("data directory") })
    }

    // ── Package presence ──────────────────────────────────────────────────────

    @Test
    fun `known clone package triggers HIGH clone signal`() {
        val signals = analyzer(pkgInstalled = { it == "com.lbe.parallel.intl" }).analyze(ctx)
        assertTrue(signals.any {
            it.severity == Severity.HIGH &&
                it.category == SignalCategory.CLONE_APP &&
                it.description.contains("com.lbe.parallel.intl")
        })
    }

    @Test
    fun `no clone packages installed produces no CLONE_APP package signal`() {
        val signals = analyzer().analyze(ctx)
        assertTrue(signals.none {
            it.category == SignalCategory.CLONE_APP && it.description.contains("installed")
        })
    }

    // ── File artifacts ─────────────────────────────────────────────────────────

    @Test
    fun `clone artifact file triggers SUSPICIOUS_PATH signal`() {
        val target = "/data/data/io.va.exposed"
        val signals = analyzer(fileExists = { it == target }).analyze(ctx)
        assertTrue(signals.any {
            it.category == SignalCategory.SUSPICIOUS_PATH && it.description.contains(target)
        })
    }

    @Test
    fun `no clone files on disk produces no SUSPICIOUS_PATH signal`() {
        val signals = analyzer().analyze(ctx)
        assertTrue(signals.none { it.category == SignalCategory.SUSPICIOUS_PATH })
    }
}

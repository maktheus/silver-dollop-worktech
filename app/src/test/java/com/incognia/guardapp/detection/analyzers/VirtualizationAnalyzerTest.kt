package com.incognia.guardapp.detection.analyzers

import com.incognia.guardapp.detection.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for [VirtualizationAnalyzer.parseTcpTable].
 *
 * /proc/net/tcp row layout (whitespace-separated):
 *   sl  local_address  rem_address  st  ...
 * local_address = "XXXXXXXX:PPPP" (IP little-endian hex, port big-endian hex)
 * st = "0A" means TCP_LISTEN.  Port 27042 = 0x69A2.
 */
class VirtualizationAnalyzerTest {

    private val analyzer = VirtualizationAnalyzer()

    // helper: build a tcp row as the kernel would — single-space delimited after trim
    private fun row(local: String, remote: String = "00000000:0000", state: String = "0A") =
        "0: $local $remote $state 00000000:00000000 00:00000000 00000000 0 0 0 1"

    // ── True positives ────────────────────────────────────────────────────────

    @Test
    fun `detects Frida listening on loopback port 27042`() {
        val signals = analyzer.parseTcpTable(listOf(row("0100007F:69A2")))
        assertEquals(1, signals.size)
        assertEquals(Severity.MEDIUM, signals[0].severity)
        assertTrue(signals[0].description.contains("27042"))
    }

    @Test
    fun `detects Frida bound to wildcard address 0_0_0_0`() {
        val signals = analyzer.parseTcpTable(listOf(row("00000000:69A2")))
        assertEquals(1, signals.size)
    }

    @Test
    fun `port match is case-insensitive (lowercase hex)`() {
        val signals = analyzer.parseTcpTable(listOf(row("0100007F:69a2")))
        assertEquals(1, signals.size)
    }

    @Test
    fun `header line is skipped (local_address has no colon-port)`() {
        val header = "sl  local_address rem_address   st tx_queue rx_queue"
        val data   = row("0100007F:69A2")
        val signals = analyzer.parseTcpTable(listOf(header, data))
        assertEquals(1, signals.size)   // header must not double-count
    }

    @Test
    fun `multiple listening Frida sockets each produce a signal`() {
        val signals = analyzer.parseTcpTable(
            listOf(row("0100007F:69A2"), row("00000000:69A2"))
        )
        assertEquals(2, signals.size)
    }

    // ── False positive guards ─────────────────────────────────────────────────

    @Test
    fun `does not flag when 69A2 appears only in remote address`() {
        val signals = analyzer.parseTcpTable(
            listOf(row(local = "0200007F:C350", remote = "0100007F:69A2", state = "01"))
        )
        assertTrue(signals.isEmpty())
    }

    @Test
    fun `does not flag ESTABLISHED socket on Frida port`() {
        // state 01 = ESTABLISHED, not LISTEN
        val signals = analyzer.parseTcpTable(listOf(row("0100007F:69A2", state = "01")))
        assertTrue(signals.isEmpty())
    }

    @Test
    fun `does not flag a different port in LISTEN state`() {
        // port 80 = 0x0050
        val signals = analyzer.parseTcpTable(listOf(row("00000000:0050")))
        assertTrue(signals.isEmpty())
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    @Test
    fun `empty list returns empty result`() {
        assertTrue(analyzer.parseTcpTable(emptyList()).isEmpty())
    }

    @Test
    fun `malformed lines do not throw`() {
        val lines = listOf("not a valid line", "", "   ", "x")
        assertTrue(analyzer.parseTcpTable(lines).isEmpty())
    }

    @Test
    fun `sourcePath is included in signal description when provided`() {
        val signal = analyzer.parseTcpTable(listOf(row("0100007F:69A2")), "/proc/net/tcp")
        assertTrue(signal[0].description.contains("/proc/net/tcp"))
    }

    @Test
    fun `no sourcePath leaves description without per-path suffix`() {
        val signal = analyzer.parseTcpTable(listOf(row("0100007F:69A2")))
        assertTrue(!signal[0].description.contains(" per "))
    }
}

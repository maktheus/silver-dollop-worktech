package com.incognia.guardapp.ui

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.incognia.guardapp.detection.DetectionSignal
import com.incognia.guardapp.detection.EnvironmentGuard
import com.incognia.guardapp.detection.SecurityReport
import com.incognia.guardapp.detection.Severity
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

class MainActivity : AppCompatActivity() {

    private lateinit var container: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val scroll = ScrollView(this)
        container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(40))
        }
        scroll.addView(container)
        setContentView(scroll)

        addText("Analyzing environment…", size = 18f, bold = true, color = Color.DKGRAY)

        lifecycleScope.launch {
            val report = EnvironmentGuard.create(this@MainActivity).generateReport()
            runOnUiThread { renderReport(report) }
        }
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    private fun renderReport(report: SecurityReport) {
        container.removeAllViews()

        // ── Status header ──────────────────────────────────────────────────────
        val statusLabel = if (report.isTampered) "TAMPERED ENVIRONMENT" else "ENVIRONMENT CLEAN"
        val statusColor = if (report.isTampered) Color.parseColor("#C62828") else Color.parseColor("#2E7D32")
        addText(statusLabel, size = 22f, bold = true, color = statusColor)

        val total = report.highSignals.size + report.mediumSignals.size
        addText(
            "Risk score: ${report.riskScore}  |  Evidence signals: $total tamper + ${report.infoSignals.size} info",
            size = 14f, color = Color.DKGRAY, topPad = dp(6),
        )

        // ── Emulator probability gauge ─────────────────────────────────────────
        val emulatorPct = report.emulatorProbability
        if (emulatorPct > 0f) {
            val pct = (emulatorPct * 100).roundToInt()
            val barFilled = (emulatorPct * 12).roundToInt().coerceIn(0, 12)
            val bar = "█".repeat(barFilled) + "░".repeat(12 - barFilled)
            val label = when {
                pct >= 85 -> "Alta confiança"
                pct >= 55 -> "Confiança moderada"
                pct >= 25 -> "Possível"
                else      -> "Baixa confiança"
            }
            val gaugeColor = when {
                pct >= 85 -> Color.parseColor("#C62828")
                pct >= 55 -> Color.parseColor("#E65100")
                else      -> Color.parseColor("#F9A825")
            }
            addText(
                "Probabilidade de emulador",
                size = 11f, color = Color.GRAY, topPad = dp(12),
            )
            addText(
                "[$bar] $pct% — $label",
                size = 14f, bold = true, color = gaugeColor, topPad = dp(2), bottomPad = dp(4),
            )
        }

        addDivider(topMargin = dp(12), bottomMargin = dp(8))

        // ── Analysis summary ───────────────────────────────────────────────────
        if (report.summary.isNotEmpty()) {
            addText(
                "ANÁLISE",
                size = 11f, bold = true, color = Color.GRAY, topPad = dp(4),
            )
            addText(
                report.summary,
                size = 13f, color = Color.DKGRAY, topPad = dp(4), bottomPad = dp(4),
                italic = true,
            )
            addDivider(topMargin = dp(8), bottomMargin = dp(4))
        }

        // ── Signal groups ──────────────────────────────────────────────────────
        if (!report.isTampered && report.infoSignals.isEmpty()) {
            addText("No suspicious indicators found.", size = 15f, topPad = dp(12))
        }

        renderGroup("HIGH SEVERITY",   report.highSignals,   Color.parseColor("#B71C1C"))
        renderGroup("MEDIUM SEVERITY", report.mediumSignals, Color.parseColor("#E65100"))
        renderGroup("INFORMATIONAL",   report.infoSignals,   Color.parseColor("#1565C0"))
    }

    private fun renderGroup(
        title: String,
        signals: List<DetectionSignal>,
        headerColor: Int,
    ) {
        if (signals.isEmpty()) return

        addText(
            "── $title (${signals.size})",
            size = 13f, bold = true, color = headerColor, topPad = dp(16),
        )

        signals.forEach { signal ->
            // Category + description
            addText(
                "  [${signal.category.displayName}]\n  ${signal.description}",
                size = 13f, color = Color.DKGRAY, topPad = dp(8),
            )
            // Explanation (dimmer, smaller)
            if (signal.explanation.isNotEmpty()) {
                addText(
                    "  ↳ ${signal.explanation}",
                    size = 11f, color = Color.parseColor("#888888"),
                    topPad = dp(3), bottomPad = dp(2), italic = true,
                )
            }
        }
    }

    // ── View helpers ──────────────────────────────────────────────────────────

    private fun addText(
        text: String,
        size: Float = 14f,
        bold: Boolean = false,
        italic: Boolean = false,
        color: Int = Color.BLACK,
        topPad: Int = 0,
        bottomPad: Int = 0,
    ) {
        container.addView(TextView(this).apply {
            this.text = text
            textSize = size
            setTextColor(color)
            val style = when {
                bold && italic -> Typeface.BOLD_ITALIC
                bold           -> Typeface.BOLD
                italic         -> Typeface.ITALIC
                else           -> Typeface.NORMAL
            }
            setTypeface(Typeface.MONOSPACE, style)
            setPadding(0, topPad, 0, bottomPad)
        })
    }

    private fun addDivider(topMargin: Int = dp(4), bottomMargin: Int = dp(4)) {
        container.addView(
            android.view.View(this).apply {
                setBackgroundColor(Color.LTGRAY)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, dp(1)
                ).also { it.topMargin = topMargin; it.bottomMargin = bottomMargin }
            }
        )
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()
}

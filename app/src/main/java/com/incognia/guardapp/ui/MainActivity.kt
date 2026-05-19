package com.incognia.guardapp.ui

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.incognia.guardapp.detection.EnvironmentGuard
import com.incognia.guardapp.detection.SecurityReport
import com.incognia.guardapp.detection.Severity
import kotlinx.coroutines.launch

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

        val statusLabel = if (report.isTampered) "TAMPERED ENVIRONMENT" else "ENVIRONMENT CLEAN"
        val statusColor = if (report.isTampered) Color.parseColor("#C62828") else Color.parseColor("#2E7D32")
        addText(statusLabel, size = 22f, bold = true, color = statusColor)

        val total = report.highSignals.size + report.mediumSignals.size
        addText(
            "Risk score: ${report.riskScore}  |  Evidence signals: $total tamper + ${report.infoSignals.size} info",
            size = 14f,
            color = Color.DKGRAY,
            topPad = dp(6),
            bottomPad = dp(18),
        )

        addDivider()

        if (!report.isTampered && report.infoSignals.isEmpty()) {
            addText("No suspicious indicators found.", size = 15f, topPad = dp(12))
        }

        renderGroup("HIGH SEVERITY", report.highSignals, Color.parseColor("#B71C1C"))
        renderGroup("MEDIUM SEVERITY", report.mediumSignals, Color.parseColor("#E65100"))
        renderGroup("INFORMATIONAL", report.infoSignals, Color.parseColor("#1565C0"))
    }

    private fun renderGroup(
        title: String,
        signals: List<com.incognia.guardapp.detection.DetectionSignal>,
        headerColor: Int,
    ) {
        if (signals.isEmpty()) return

        addText("── $title (${signals.size})", size = 13f, bold = true, color = headerColor, topPad = dp(16))

        signals.forEach { signal ->
            addText(
                "  [${signal.category.displayName}]\n  ${signal.description}",
                size = 13f,
                color = Color.DKGRAY,
                topPad = dp(6),
            )
        }
    }

    // ── View helpers ──────────────────────────────────────────────────────────

    private fun addText(
        text: String,
        size: Float = 14f,
        bold: Boolean = false,
        color: Int = Color.BLACK,
        topPad: Int = 0,
        bottomPad: Int = 0,
    ) {
        container.addView(TextView(this).apply {
            this.text = text
            textSize = size
            setTextColor(color)
            setTypeface(Typeface.MONOSPACE, if (bold) Typeface.BOLD else Typeface.NORMAL)
            setPadding(0, topPad, 0, bottomPad)
        })
    }

    private fun addDivider() {
        container.addView(
            android.view.View(this).apply {
                setBackgroundColor(Color.LTGRAY)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, dp(1)
                ).also { it.topMargin = dp(4); it.bottomMargin = dp(4) }
            }
        )
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()
}

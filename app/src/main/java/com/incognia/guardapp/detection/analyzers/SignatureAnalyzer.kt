package com.incognia.guardapp.detection.analyzers

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import com.incognia.guardapp.detection.DetectionSignal
import com.incognia.guardapp.detection.DetectionSignatures
import com.incognia.guardapp.detection.EnvironmentAnalyzer
import com.incognia.guardapp.detection.Severity
import com.incognia.guardapp.detection.SignalCategory
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Verifies the APK signing certificate and install provenance.
 *
 * Checks:
 *  1. Debug certificate subject ("CN=Android Debug") — repackaged builds often
 *     resign with a debug key.
 *  2. Known-good hash comparison — in production, replace [EXPECTED_CERT_SHA256]
 *     with the SHA-256 of your release certificate.
 *  3. Installer source — unexpected installer packages indicate sideloading or
 *     repackaging distribution channels.
 *  4. Package name consistency — some clone frameworks alter the runtime package
 *     name while leaving the declared name intact in ApplicationInfo.
 */
class SignatureAnalyzer : EnvironmentAnalyzer {

    override fun analyze(context: Context): List<DetectionSignal> =
        checkCertificate(context) + checkInstallerSource(context) + checkPackageNameConsistency(context)

    // ── Certificate checks ────────────────────────────────────────────────────

    private fun checkCertificate(context: Context): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        val signatures = getSignatures(context) ?: return signals

        signatures.firstOrNull()?.let { sig ->
            val sha256 = computeHash(sig, "SHA-256")
            val sha1   = computeHash(sig, "SHA-1")

            // Informational — always emit so the UI can display the hash.
            signals += DetectionSignal(
                SignalCategory.SIGNATURE,
                "APK cert SHA-256: $sha256",
                Severity.LOW,
            )

            // Debug key detection via X.509 subject.
            try {
                val cert = CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(sig.toByteArray())) as X509Certificate
                val subject = cert.subjectDN.name
                if (subject.contains("Android Debug", ignoreCase = true)) {
                    signals += DetectionSignal(
                        SignalCategory.SIGNATURE,
                        "App is signed with the Android debug key (subject: $subject)",
                        Severity.MEDIUM,
                    )
                }
                signals += DetectionSignal(
                    SignalCategory.SIGNATURE,
                    "Certificate subject: $subject",
                    Severity.LOW,
                )
            } catch (_: Exception) {}

            // Integrity check against the expected production certificate.
            // Replace EXPECTED_CERT_SHA256 with your actual release cert hash.
            if (EXPECTED_CERT_SHA256.isNotEmpty() && sha256 != EXPECTED_CERT_SHA256) {
                signals += DetectionSignal(
                    SignalCategory.SIGNATURE,
                    "Certificate SHA-256 mismatch — expected $EXPECTED_CERT_SHA256, got $sha256",
                    Severity.HIGH,
                )
            }
        }

        return signals
    }

    // ── Installer source ──────────────────────────────────────────────────────

    private fun checkInstallerSource(context: Context): List<DetectionSignal> {
        val signals = mutableListOf<DetectionSignal>()
        try {
            val pm = context.packageManager
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(context.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(context.packageName)
            }

            signals += DetectionSignal(
                SignalCategory.SIGNATURE,
                "Install source: ${installer ?: "adb / unknown"}",
                Severity.LOW,
            )

            if (installer != null && installer !in DetectionSignatures.LEGITIMATE_INSTALLERS) {
                signals += DetectionSignal(
                    SignalCategory.SIGNATURE,
                    "Unexpected install source: $installer (not a known app store)",
                    Severity.MEDIUM,
                )
            }
        } catch (_: Exception) {}
        return signals
    }

    // ── Package name consistency ───────────────────────────────────────────────

    private fun checkPackageNameConsistency(context: Context): List<DetectionSignal> {
        val declared = context.applicationInfo.packageName
        val runtime  = context.packageName
        return if (declared != runtime) {
            listOf(
                DetectionSignal(
                    SignalCategory.SIGNATURE,
                    "Package name mismatch: declared=$declared vs runtime=$runtime",
                    Severity.HIGH,
                )
            )
        } else emptyList()
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    @Suppress("DEPRECATION")
    private fun getSignatures(context: Context): Array<Signature>? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager
                .getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                .signingInfo
                ?.apkContentsSigners
        } else {
            context.packageManager
                .getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                .signatures
        }
    }.getOrNull()

    private fun computeHash(signature: Signature, algorithm: String): String =
        MessageDigest.getInstance(algorithm)
            .digest(signature.toByteArray())
            .joinToString("") { "%02X".format(it) }

    private companion object {
        /**
         * SHA-256 of the signing certificate expected for THIS build.
         *
         * Current value: Android debug keystore (androiddebugkey).
         * For production, replace with the SHA-256 of your release certificate:
         *   apksigner verify --print-certs app-release.apk | grep SHA-256
         *
         * To update for a new keystore:
         *   keytool -list -v -keystore <path>.jks -alias <alias> | grep SHA256
         *   → remove colons, keep uppercase
         */
        const val EXPECTED_CERT_SHA256 =
            "DE8964584DE8F5DEB08D65041FE22B85299069C8B44635AC869D00C0DF4BB8C2"
    }
}

package com.naush12.mobile

import android.app.KeyguardManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject


class SmsReceiver : BroadcastReceiver() {

    companion object {

        // IMPORTANT:
        // Must match the backend server's address
        // (check constants/api.js)

        private const val BACKEND_URL_OTP =
            "http://192.168.1.101:8000/analyze-sms"

        private const val BACKEND_URL_PHISHING =
            "http://192.168.1.101:8000/analyze-url"

        private const val PREFS_NAME =
            "sms_monitor"

        private const val LATEST_EVENT =
            "latest_sms_event"
    }


    override fun onReceive(
        context: Context,
        intent: Intent
    ) {

        if (
            intent.action !=
            Telephony.Sms.Intents.SMS_RECEIVED_ACTION
        ) {
            return
        }

        val pendingResult =
            goAsync()

        val messages =
            Telephony.Sms.Intents
                .getMessagesFromIntent(intent)

        CoroutineScope(
            Dispatchers.IO
        ).launch {

            try {

                // ============================================================
                // HANDLE MULTIPART / LONG SMS
                // ============================================================

                if (messages.isEmpty()) {
                    return@launch
                }


                // ============================================================
                // GET SENDER
                // ============================================================

                val sender =
                    messages
                        .firstOrNull {
                            !it.originatingAddress.isNullOrBlank()
                        }
                        ?.originatingAddress
                        ?: return@launch


                // ============================================================
                // COMBINE ALL SMS PARTS
                // ============================================================

                val body =
                    messages
                        .filter {
                            it.originatingAddress == sender
                        }
                        .joinToString(separator = "") {
                            it.messageBody ?: ""
                        }


                // ============================================================
                // SAFETY CHECK
                // ============================================================

                if (body.isBlank()) {
                    return@launch
                }


                android.util.Log.d(
                    "SmsReceiver",
                    "Complete SMS received: $body"
                )


                // ============================================================
                // EXTRACT OTP LOCALLY
                // ============================================================

                val localOtp =
                    extractOtpLocally(
                        body
                    )


                // ============================================================
                // SANITIZE SMS FOR OTP AGENT
                // ============================================================

                val sanitizedBody =
                    sanitizeForOtpAgent(
                        body,
                        localOtp
                    )


                // ============================================================
                // ANDROID CONTEXT
                // ============================================================

                val foregroundApp =
                    getRecentForegroundApp(
                        context
                    )


                val screenUnlocked =
                    isScreenUnlocked(
                        context
                    )


                val expectedOtp =
                    isLikelyOtpRelatedApp(
                        foregroundApp
                    )


                // ============================================================
                // ANALYZE SMS
                // ============================================================

                val result =
                    analyzeWithBackend(
                        sender = sender,
                        sanitizedBody = sanitizedBody,
                        originalBody = body,
                        foregroundApp = foregroundApp,
                        expectedOtp = expectedOtp,
                        screenUnlocked = screenUnlocked
                    )


                // ============================================================
                // SAVE RESULT
                // ============================================================

                saveLatestEvent(
                    context,
                    sender,
                    body,
                    foregroundApp,
                    expectedOtp,
                    screenUnlocked,
                    result
                )

            } catch (e: Exception) {

                e.printStackTrace()

            } finally {

                pendingResult.finish()
            }
        }
    }


    // ========================================================
    // BACKEND REQUEST
    // ========================================================

    private fun analyzeWithBackend(
        sender: String,
        sanitizedBody: String,
        originalBody: String,
        foregroundApp: String,
        expectedOtp: Boolean,
        screenUnlocked: Boolean
    ): JSONObject {

        val result =
            JSONObject()


        // ====================================================
        // OTP AGENT
        // ====================================================

        try {

            val otpAnalysis =
                makeBackendRequest(
                    url = BACKEND_URL_OTP,
                    sender = sender,
                    body = sanitizedBody,
                    foregroundApp = foregroundApp,
                    expectedOtp = expectedOtp,
                    screenUnlocked = screenUnlocked
                )


            result.put(
                "analysis",
                otpAnalysis
            )

        } catch (e: Exception) {

            android.util.Log.e(
                "SmsReceiver",
                "OTP analysis failed: ${e.message}"
            )

            result.put(
                "analysis",
                JSONObject().apply {

                    put(
                        "error",
                        e.message
                    )

                    put(
                        "level",
                        "ERROR"
                    )
                }
            )
        }


        // ====================================================
        // URL / PHISHING AGENT
        // ====================================================

        try {

            val urlAnalysis =
                makeBackendRequest(
                    url = BACKEND_URL_PHISHING,
                    sender = sender,
                    body = originalBody,
                    foregroundApp = foregroundApp,
                    expectedOtp = expectedOtp,
                    screenUnlocked = screenUnlocked
                )


            result.put(
                "url_analysis",
                urlAnalysis
            )

        } catch (e: Exception) {

            android.util.Log.e(
                "SmsReceiver",
                "URL analysis failed: ${e.message}"
            )

            result.put(
                "url_analysis",
                JSONObject().apply {

                    put(
                        "error",
                        e.message
                    )

                    put(
                        "category",
                        "unknown"
                    )
                }
            )
        }


        return result
    }


    // ========================================================
    // BACKEND HTTP REQUEST
    // ========================================================

    private fun makeBackendRequest(
        url: String,
        sender: String,
        body: String,
        foregroundApp: String,
        expectedOtp: Boolean,
        screenUnlocked: Boolean
    ): JSONObject {

        val connection =
            URL(url)
                .openConnection()
                    as HttpURLConnection


        connection.requestMethod =
            "POST"


        connection.connectTimeout =
            8000


        connection.readTimeout =
            15000


        connection.doOutput =
            true


        connection.setRequestProperty(
            "Content-Type",
            "application/json"
        )


        val json =
            JSONObject()


        json.put(
            "sender",
            sender
        )


        json.put(
            "body",
            body
        )


        json.put(
            "timestamp",
            System.currentTimeMillis()
        )


        json.put(
            "source",
            "android_sms_receiver"
        )


        json.put(
            "expected_otp",
            expectedOtp
        )


        json.put(
            "foreground_app",
            foregroundApp
        )


        json.put(
            "screen_unlocked",
            screenUnlocked
        )


        OutputStreamWriter(
            connection.outputStream
        ).use { writer ->

            writer.write(
                json.toString()
            )

            writer.flush()
        }


        val responseCode =
            connection.responseCode


        val response =
            connection.inputStream
                .bufferedReader()
                .use {
                    it.readText()
                }


        connection.disconnect()


        if (
            responseCode !in 200..299
        ) {

            throw Exception(
                "Backend HTTP error: " +
                    "$responseCode - $response"
            )
        }


        return JSONObject(
            response
        )
    }


    // ========================================================
    // LOCAL OTP EXTRACTION
    // ========================================================

    private fun extractOtpLocally(
        body: String
    ): String? {

        // ====================================================
        // 1. STRONG OTP CONTEXT
        // ====================================================

        val contextualPattern =
            Regex(
                "(?i)(otp|one[- ]time password|verification code|" +
                    "verification number|security code|authentication code|" +
                    "auth code|login code|verification pin)" +
                    "[^0-9]{0,30}" +
                    "(\\d{4,8})"
            )


        val contextualMatch =
            contextualPattern.find(body)


        if (contextualMatch != null) {

            return contextualMatch
                .groupValues[2]
        }


        // ====================================================
        // 2. CHECK WHETHER MESSAGE HAS OTP CONTEXT
        // ====================================================

        val otpContextPattern =
            Regex(
                "(?i)\\b(" +
                    "otp|" +
                    "one[- ]time password|" +
                    "verification|" +
                    "verify|" +
                    "authentication|" +
                    "authenticate|" +
                    "security|" +
                    "login|" +
                    "sign[- ]in|" +
                    "authorize|" +
                    "authorization" +
                    ")\\b"
            )


        val hasOtpContext =
            otpContextPattern.containsMatchIn(body)


        // ====================================================
        // 3. GENERIC NUMBER ONLY IF OTP CONTEXT EXISTS
        // ====================================================

        if (hasOtpContext) {

            val genericPattern =
                Regex("\\b\\d{4,8}\\b")


            for (match in genericPattern.findAll(body)) {

                val candidate =
                    match.value


                // Ignore obvious years such as 2026
                if (
                    candidate.length == 4 &&
                    candidate.toIntOrNull() in 1900..2099
                ) {
                    continue
                }


                return candidate
            }
        }


        // ====================================================
        // 4. NO CONFIDENT OTP
        // ====================================================

        return null
    }


    // ========================================================
    // SANITIZE ONLY FOR OTP AGENT
    // ========================================================

    private fun sanitizeForOtpAgent(
        body: String,
        otp: String?
    ): String {

        var sanitized =
            body


        // ----------------------------------------------------
        // Replace detected OTP
        // ----------------------------------------------------

        if (
            otp != null
        ) {

            sanitized =
                sanitized.replace(
                    otp,
                    "[OTP]"
                )
        }


        // ----------------------------------------------------
        // EXTRA PRIVACY PROTECTION
        // ----------------------------------------------------

        sanitized =
            sanitized.replace(
                Regex(
                    "\\b\\d{4,8}\\b"
                ),
                "[OTP]"
            )


        return sanitized
    }


    // ========================================================
    // RECENT FOREGROUND APP
    // ========================================================

    private fun getRecentForegroundApp(
        context: Context
    ): String {

        if (
            Build.VERSION.SDK_INT <
            Build.VERSION_CODES.LOLLIPOP
        ) {
            return ""
        }


        val usageStatsManager =
            context.getSystemService(
                Context.USAGE_STATS_SERVICE
            ) as? UsageStatsManager
                ?: return ""


        val endTime =
            System.currentTimeMillis()


        // Look back 3 minutes

        val startTime =
            endTime -
                (3 * 60 * 1000L)


        val events =
            usageStatsManager.queryEvents(
                startTime,
                endTime
            )


        val event =
            UsageEvents.Event()


        var latestPackage =
            ""


        var latestTimestamp =
            0L


        while (
            events.hasNextEvent()
        ) {

            events.getNextEvent(
                event
            )


            if (
                event.eventType ==
                UsageEvents.Event.ACTIVITY_RESUMED
            ) {

                if (
                    event.timeStamp >
                    latestTimestamp
                ) {

                    latestTimestamp =
                        event.timeStamp


                    latestPackage =
                        event.packageName ?: ""
                }
            }
        }


        return latestPackage
    }


    // ========================================================
    // SCREEN STATE
    // ========================================================

    private fun isScreenUnlocked(
        context: Context
    ): Boolean {

        val keyguardManager =
            context.getSystemService(
                Context.KEYGUARD_SERVICE
            ) as? KeyguardManager
                ?: return true


        return !keyguardManager.isKeyguardLocked
    }


    // ========================================================
    // OTP-RELATED APP CHECK
    // ========================================================

    private fun isLikelyOtpRelatedApp(
        packageName: String
    ): Boolean {

        if (
            packageName.isBlank()
        ) {
            return false
        }


        val pkg =
            packageName.lowercase()


        val keywords =
            listOf(
                "bank",
                "hdfc",
                "icici",
                "sbi",
                "axis",
                "kotak",
                "paytm",
                "phonepe",
                "googlepay",
                "gpay",
                "amazon",
                "flipkart",
                "cred",
                "paypal",
                "microsoft"
            )


        return keywords.any {
            pkg.contains(it)
        }
    }


    // ========================================================
    // SAVE EVENT
    // ========================================================

    private fun saveLatestEvent(
        context: Context,
        sender: String,
        body: String,
        foregroundApp: String,
        expectedOtp: Boolean,
        screenUnlocked: Boolean,
        result: JSONObject
    ) {

        val event =
            JSONObject()


        event.put(
            "sender",
            sender
        )


        event.put(
            "body",
            body
        )


        event.put(
            "timestamp",
            System.currentTimeMillis()
        )


        event.put(
            "foreground_app",
            foregroundApp
        )


        event.put(
            "expected_otp",
            expectedOtp
        )


        event.put(
            "screen_unlocked",
            screenUnlocked
        )


        // Extract OTP analysis

        if (
            result.has("analysis")
        ) {

            event.put(
                "analysis",
                result.getJSONObject(
                    "analysis"
                )
            )

        } else {

            event.put(
                "analysis",
                JSONObject()
            )
        }


        // Extract URL analysis

        if (
            result.has("url_analysis")
        ) {

            event.put(
                "url_analysis",
                result.getJSONObject(
                    "url_analysis"
                )
            )

        } else {

            event.put(
                "url_analysis",
                JSONObject()
            )
        }


        context
            .getSharedPreferences(
                PREFS_NAME,
                Context.MODE_PRIVATE
            )
            .edit()
            .putString(
                LATEST_EVENT,
                event.toString()
            )
            .apply()
    }
}
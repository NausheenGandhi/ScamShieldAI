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
import java.net.HttpURLConnection
import java.net.URL
import java.io.OutputStreamWriter
import org.json.JSONObject


class SmsReceiver : BroadcastReceiver() {

    companion object {

        // IMPORTANT:
        // Replace this with your PC's current IPv4 address.
        private const val BACKEND_URL =
            "http://192.168.1.101:8000/analyze-sms"

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

        val pendingResult = goAsync()

        val messages =
            Telephony.Sms.Intents
                .getMessagesFromIntent(intent)

        CoroutineScope(
            Dispatchers.IO
        ).launch {

            try {

                for (sms in messages) {

                    val sender =
                        sms.originatingAddress
                            ?: continue

                    val body =
                        sms.messageBody
                            ?: continue

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

                    val result =
                        analyzeWithBackend(
                            sender = sender,
                            body = body,
                            foregroundApp =
                                foregroundApp,
                            expectedOtp =
                                expectedOtp,
                            screenUnlocked =
                                screenUnlocked
                        )

                    saveLatestEvent(
                        context,
                        sender,
                        body,
                        foregroundApp,
                        expectedOtp,
                        screenUnlocked,
                        result
                    )
                }

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
        body: String,
        foregroundApp: String,
        expectedOtp: Boolean,
        screenUnlocked: Boolean
    ): JSONObject {

        val connection =
            URL(BACKEND_URL)
                .openConnection()
                    as HttpURLConnection

        connection.requestMethod = "POST"

        connection.connectTimeout =
            5000

        connection.readTimeout =
            10000

        connection.doOutput = true

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

        if (
            responseCode !in 200..299
        ) {

            throw Exception(
                "Backend HTTP error: $responseCode"
            )
        }

        val response =
            connection.inputStream
                .bufferedReader()
                .use {
                    it.readText()
                }

        connection.disconnect()

        return JSONObject(
            response
        )
    }

    // ========================================================
    // RECENT FOREGROUND APP
    // ========================================================

    private fun getRecentForegroundApp(
        context: Context
    ): String {

        if (Build.VERSION.SDK_INT <
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

        // Look back 3 minutes.
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

        var latestPackage = ""
        var latestTimestamp = 0L

        while (
            events.hasNextEvent()
        ) {

            events.getNextEvent(event)

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

        if (packageName.isBlank()) {
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

        event.put(
            "analysis",
            result
        )

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
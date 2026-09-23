package com.naush12.mobile

import android.app.KeyguardManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.ContactsContract
import android.provider.Telephony
import android.util.Log

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

import org.json.JSONObject

import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL


class SmsReceiver : BroadcastReceiver() {

    companion object {

        private const val TAG = "SmsReceiver"

        // ========================================================
        // BACKEND
        // ========================================================

        /*
         * Because you are using:
         *
         * adb reverse tcp:8000 tcp:8000
         *
         * localhost:8000 on the Android device is forwarded
         * to your computer's FastAPI server.
         */
        private const val BASE_URL =
            "http://localhost:8000"

        /*
         * NEW ARCHITECTURE:
         *
         * One request only.
         *
         * /analyze-sms
         *      ↓
         * LangGraph Coordinator
         *      ↓
         * OTP / URL / Content
         */
        private const val BACKEND_URL =
            "$BASE_URL/analyze-sms"


        // ========================================================
        // SHARED PREFERENCES
        // ========================================================

        private const val PREFS_NAME =
            "sms_monitor"

        private const val LATEST_EVENT =
            "latest_sms_event"
    }


    // ========================================================
    // SMS RECEIVED
    // ========================================================

    override fun onReceive(
        context: Context,
        intent: Intent
    ) {

        /*
         * Only process actual incoming SMS broadcasts.
         */
        if (
            intent.action !=
            Telephony.Sms.Intents.SMS_RECEIVED_ACTION
        ) {
            return
        }


        /*
         * Keep BroadcastReceiver alive while the
         * asynchronous backend request is running.
         */
        val pendingResult =
            goAsync()


        /*
         * Extract all SMS parts.
         */
        val messages =
            Telephony.Sms.Intents
                .getMessagesFromIntent(intent)


        CoroutineScope(
            Dispatchers.IO
        ).launch {

            try {

                // ====================================================
                // HANDLE EMPTY SMS
                // ====================================================

                if (messages.isEmpty()) {

                    Log.w(
                        TAG,
                        "No SMS messages found"
                    )

                    return@launch
                }


                // ====================================================
                // GET SENDER
                // ====================================================

                val sender =
                    messages
                        .firstOrNull {
                            !it.originatingAddress
                                .isNullOrBlank()
                        }
                        ?.originatingAddress
                        ?: run {

                            Log.w(
                                TAG,
                                "Could not determine SMS sender"
                            )

                            return@launch
                        }


                // ====================================================
                // COMBINE MULTIPART SMS
                // ====================================================

                val body =
                    messages
                        .filter {
                            it.originatingAddress ==
                                sender
                        }
                        .joinToString(
                            separator = ""
                        ) {
                            it.messageBody ?: ""
                        }


                // ====================================================
                // SAFETY CHECK
                // ====================================================

                if (body.isBlank()) {

                    Log.w(
                        TAG,
                        "SMS body is empty"
                    )

                    return@launch
                }


                Log.d(
                    TAG,
                    "Incoming SMS from $sender"
                )

                Log.d(
                    TAG,
                    "SMS body received"
                )


                // ====================================================
                // ANDROID DEVICE CONTEXT
                // ====================================================

                val foregroundApp =
                    getRecentForegroundApp(
                        context
                    )


                val screenUnlocked =
                    isScreenUnlocked(
                        context
                    )


                /*
                 * Determine whether the currently foreground
                 * application looks related to OTP usage.
                 */
                val expectedOtp =
                    isLikelyOtpRelatedApp(
                        foregroundApp
                    )


                // ====================================================
                // CONTACT LOOKUP
                // ====================================================

                val isSaved =
                    isSavedContact(
                        context,
                        sender
                    )


                val contactName =
                    if (isSaved) {

                        getContactName(
                            context,
                            sender
                        )

                    } else {

                        null
                    }


                Log.d(
                    TAG,
                    "Contact lookup: saved=$isSaved, name=$contactName"
                )


                // ====================================================
                // LANGGRAPH ANALYSIS
                // ====================================================

                /*
                 * IMPORTANT:
                 *
                 * We now send ONLY ONE request:
                 *
                 * /analyze-sms
                 *
                 * FastAPI → LangGraph Coordinator
                 *
                 * LangGraph decides:
                 *
                 * OTP
                 * URL
                 * Content
                 *
                 * Content always runs.
                 */
                val langGraphResult =
                    analyzeWithLangGraph(
                        sender = sender,
                        body = body,
                        foregroundApp = foregroundApp,
                        expectedOtp = expectedOtp,
                        screenUnlocked = screenUnlocked,
                        isSavedContact = isSaved,
                        contactName = contactName
                    )


                // ====================================================
                // SAVE COMPLETE LANGGRAPH RESULT
                // ====================================================

                saveLatestEvent(
                    context = context,
                    sender = sender,
                    body = body,
                    foregroundApp = foregroundApp,
                    expectedOtp = expectedOtp,
                    screenUnlocked = screenUnlocked,
                    isSavedContact = isSaved,
                    contactName = contactName,
                    langGraphResult = langGraphResult
                )


                Log.d(
                    TAG,
                    "SMS analysis completed and saved"
                )

            } catch (e: Exception) {

                Log.e(
                    TAG,
                    "SMS processing failed: ${e.message}",
                    e
                )

            } finally {

                /*
                 * IMPORTANT:
                 * Always finish the BroadcastReceiver.
                 */
                pendingResult.finish()
            }
        }
    }


    // ========================================================
    // LANGGRAPH BACKEND REQUEST
    // ========================================================

    private fun analyzeWithLangGraph(
        sender: String,
        body: String,
        foregroundApp: String,
        expectedOtp: Boolean,
        screenUnlocked: Boolean,
        isSavedContact: Boolean,
        contactName: String?
    ): JSONObject {

        Log.d(
            TAG,
            "Sending SMS to LangGraph backend"
        )


        val connection =
            URL(BACKEND_URL)
                .openConnection() as HttpURLConnection


        try {

            // ====================================================
            // HTTP CONFIGURATION
            // ====================================================

            connection.requestMethod =
                "POST"

            connection.connectTimeout =
                8000

            connection.readTimeout =
                90000

            connection.doOutput =
                true

            connection.setRequestProperty(
                "Content-Type",
                "application/json"
            )


            // ====================================================
            // REQUEST BODY
            // ====================================================

            val json =
                JSONObject()


            json.put(
                "sender",
                sender
            )


            /*
             * Send the original SMS body to FastAPI.
             *
             * The OTP agent performs its own defensive
             * OTP sanitization before sending text to the LLM.
             */
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


            json.put(
                "is_saved_contact",
                isSavedContact
            )


            if (contactName != null) {

                json.put(
                    "contact_name",
                    contactName
                )

            } else {

                json.put(
                    "contact_name",
                    ""
                )
            }


            Log.d(
                TAG,
                "Sending request to $BACKEND_URL"
            )


            // ====================================================
            // SEND REQUEST
            // ====================================================

            OutputStreamWriter(
                connection.outputStream
            ).use { writer ->

                writer.write(
                    json.toString()
                )

                writer.flush()
            }


            // ====================================================
            // READ RESPONSE
            // ====================================================

            val responseCode =
                connection.responseCode


            val response =
                if (
                    responseCode in 200..299
                ) {

                    connection.inputStream
                        .bufferedReader()
                        .use {
                            it.readText()
                        }

                } else {

                    connection.errorStream
                        ?.bufferedReader()
                        ?.use {
                            it.readText()
                        }
                        ?: ""
                }


            Log.d(
                TAG,
                "Backend response code: $responseCode"
            )


            if (
                responseCode !in 200..299
            ) {

                throw Exception(
                    "Backend HTTP error: " +
                        "$responseCode - $response"
                )
            }


            if (response.isBlank()) {

                throw Exception(
                    "Backend returned empty response"
                )
            }


            // ====================================================
            // PARSE LANGGRAPH RESPONSE
            // ====================================================

            return JSONObject(
                response
            )

        } finally {

            connection.disconnect()
        }
    }


    // ========================================================
    // CONTACT LOOKUP
    // ========================================================

    private fun isSavedContact(
        context: Context,
        phoneNumber: String
    ): Boolean {

        return try {

            val uri =
                Uri.withAppendedPath(
                    ContactsContract
                        .PhoneLookup
                        .CONTENT_FILTER_URI,
                    Uri.encode(phoneNumber)
                )


            context.contentResolver.query(
                uri,
                arrayOf(
                    ContactsContract
                        .PhoneLookup
                        ._ID
                ),
                null,
                null,
                null
            )?.use { cursor ->

                cursor.moveToFirst()

            } ?: false

        } catch (e: SecurityException) {

            Log.w(
                TAG,
                "READ_CONTACTS not granted, skipping contact check"
            )

            false

        } catch (e: Exception) {

            Log.e(
                TAG,
                "Contact lookup failed: ${e.message}"
            )

            false
        }
    }


    // ========================================================
    // CONTACT NAME
    // ========================================================

    private fun getContactName(
        context: Context,
        phoneNumber: String
    ): String? {

        return try {

            val uri =
                Uri.withAppendedPath(
                    ContactsContract
                        .PhoneLookup
                        .CONTENT_FILTER_URI,
                    Uri.encode(phoneNumber)
                )


            context.contentResolver.query(
                uri,
                arrayOf(
                    ContactsContract
                        .PhoneLookup
                        .DISPLAY_NAME
                ),
                null,
                null,
                null
            )?.use { cursor ->

                if (cursor.moveToFirst()) {

                    cursor.getString(0)

                } else {

                    null
                }

            }

        } catch (e: Exception) {

            Log.e(
                TAG,
                "Failed to get contact name: ${e.message}"
            )

            null
        }
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


        /*
         * Look back three minutes.
         */
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
    // SAVE LATEST EVENT
    // ========================================================

    private fun saveLatestEvent(
        context: Context,
        sender: String,
        body: String,
        foregroundApp: String,
        expectedOtp: Boolean,
        screenUnlocked: Boolean,
        isSavedContact: Boolean,
        contactName: String?,
        langGraphResult: JSONObject
    ) {

        try {

            // ====================================================
            // CREATE EVENT OBJECT
            // ====================================================

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
                "is_saved_contact",
                isSavedContact
            )


            event.put(
                "contact_name",
                contactName ?: ""
            )


            // ====================================================
            // COMPLETE LANGGRAPH RESULT
            // ====================================================

            /*
             * This is the most important change.
             *
             * App.js expects:
             *
             * parsedEvent.langgraph_result
             *
             * So we store the complete FastAPI response here.
             */
            event.put(
                "langgraph_result",
                langGraphResult
            )


            // ====================================================
            // SAVE TO SHARED PREFERENCES
            // ====================================================

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


            Log.d(
                TAG,
                "Latest LangGraph event saved"
            )

        } catch (e: Exception) {

            Log.e(
                TAG,
                "Failed to save SMS event: ${e.message}",
                e
            )
        }
    }
}
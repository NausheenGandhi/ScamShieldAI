package com.naush12.mobile

import android.content.Context
import android.util.Log
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

class SmsNativeModule(
    reactContext: ReactApplicationContext
) : ReactContextBaseJavaModule(reactContext) {

    companion object {
        private const val TAG = "SmsNativeModule"

        private const val PREFS_NAME = "sms_monitor"
        private const val LATEST_EVENT = "latest_sms_event"
    }

    override fun getName(): String {
        return "SmsNativeModule"
    }

    @ReactMethod
    fun getLatestSmsEvent(promise: Promise) {

        try {

            Log.d(
                TAG,
                "getLatestSmsEvent() called"
            )

            val prefs =
                reactApplicationContext.getSharedPreferences(
                    PREFS_NAME,
                    Context.MODE_PRIVATE
                )

            val event =
                prefs.getString(
                    LATEST_EVENT,
                    null
                )

            Log.d(
                TAG,
                "Stored event = $event"
            )

            if (event == null) {

                Log.d(
                    TAG,
                    "No SMS event found"
                )

                promise.resolve(null)

            } else {

                Log.d(
                    TAG,
                    "Returning SMS event to React Native"
                )

                promise.resolve(event)
            }

        } catch (e: Exception) {

            Log.e(
                TAG,
                "Failed to read SMS event",
                e
            )

            promise.reject(
                "SMS_EVENT_ERROR",
                e.message,
                e
            )
        }
    }

    @ReactMethod
    fun clearLatestSmsEvent(
        promise: Promise
    ) {

        try {

            reactApplicationContext
                .getSharedPreferences(
                    PREFS_NAME,
                    Context.MODE_PRIVATE
                )
                .edit()
                .remove(
                    LATEST_EVENT
                )
                .apply()

            promise.resolve(true)

        } catch (e: Exception) {

            promise.reject(
                "CLEAR_SMS_ERROR",
                e.message,
                e
            )
        }
    }

    // Required by React Native NativeEventEmitter
    @ReactMethod
    fun addListener(
        eventName: String
    ) {
    }

    @ReactMethod
    fun removeListeners(
        count: Int
    ) {
    }
}
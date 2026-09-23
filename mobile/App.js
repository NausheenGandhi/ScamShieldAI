import React, { useEffect, useRef, useState } from "react";

import { NativeModules, AppState } from "react-native";

import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider } from "react-native-safe-area-context";

import OnboardingScreen, { INTRO_STEPS } from "./components/OnboardingScreen";

import PermissionsScreen from "./components/PermissionsScreen";
import DeviceDataScreen from "./components/DeviceDataScreen";
import SecurityCenter from "./components/SecurityCenter";
import ScanScreen from "./components/ScanScreen";
import OtpMonitoringScreen from "./components/OtpMonitoringScreen";
import UrlAgentScreen from "./components/Urlagentscreen";
import ContactAgentScreen from "./components/ContactAgentScreen";

/* =========================================================
   NATIVE SMS MODULE
   ========================================================= */

const { SmsNativeModule } = NativeModules;

/* =========================================================
   APP STAGES
   ========================================================= */

const STAGES = {
  ONBOARDING: "onboarding",
  PERMISSIONS: "permissions",
  DEVICE_DATA: "device_data",
  SECURITY_CENTER: "security_center",
  OTP_AGENT: "otp_agent",
  URL_AGENT: "url_agent",
  CONTACT_AGENT: "contact_agent",
  SCAN: "scan",
};

/* =========================================================
   APP
   ========================================================= */

export default function App() {
  /* =======================================================
     BASIC APP STATE
     ======================================================= */

  const [step, setStep] = useState(0);

  const [stage, setStage] = useState(STAGES.ONBOARDING);

  /* =======================================================
     LATEST LANGGRAPH RESULT
     ======================================================= */

  const [analysisResult, setAnalysisResult] = useState(null);

  /* =======================================================
     MANUAL SCAN RETURN STAGE
     ======================================================= */

  const [scanReturnStage, setScanReturnStage] = useState(
    STAGES.SECURITY_CENTER,
  );

  /* =======================================================
     SMS MONITORING REFS
     ======================================================= */

  // Stores the timestamp of the last SMS processed.
  // Prevents the same SMS from being displayed repeatedly.
  const lastProcessedTimestamp = useRef(null);

  // Keeps track of the current screen without
  // recreating the SMS monitoring effect.
  const stageRef = useRef(stage);

  /* =======================================================
     KEEP CURRENT STAGE IN REF
     ======================================================= */

  useEffect(() => {
    stageRef.current = stage;
  }, [stage]);

  /* =========================================================
     AUTOMATIC SMS MONITORING
     
     Flow:

     Incoming SMS
          ↓
     SmsReceiver.kt
          ↓
     Backend /analyze-sms
          ↓
     LangGraph
          ↓
     SharedPreferences
          ↓
     SmsNativeModule
          ↓
     App.js
          ↓
     SecurityCenter
     ========================================================= */

  useEffect(() => {
    let intervalId = null;
    let appStateSubscription = null;

    /* =====================================================
       CHECK FOR NEW SMS
       ===================================================== */

    const checkForNewSms = async () => {
      try {
        /* -------------------------------------------------
           CHECK NATIVE MODULE
           ------------------------------------------------- */

        if (!SmsNativeModule) {
          console.warn("SmsNativeModule is not available");

          return;
        }

        /* -------------------------------------------------
           GET LATEST SMS EVENT
           ------------------------------------------------- */

        const event = await SmsNativeModule.getLatestSmsEvent();

        // Nothing stored yet.
        if (!event) {
          return;
        }

        console.log("📩 SMS event received from native module:", event);

        /* -------------------------------------------------
           PARSE EVENT
           ------------------------------------------------- */

        let parsedEvent;

        try {
          parsedEvent = typeof event === "string" ? JSON.parse(event) : event;
        } catch (parseError) {
          console.error("❌ Failed to parse SMS event:", parseError);

          return;
        }

        console.log("📩 Parsed SMS event:", parsedEvent);

        /* -------------------------------------------------
           IDENTIFY SMS
           ------------------------------------------------- */

        const timestamp = parsedEvent.timestamp;

        /* -------------------------------------------------
           PREVENT DUPLICATE PROCESSING
           ------------------------------------------------- */

        if (timestamp && lastProcessedTimestamp.current === timestamp) {
          return;
        }

        /*
         * Mark this SMS as processed.
         *
         * We do this before updating the UI so that
         * repeated polling does not process it again.
         */

        lastProcessedTimestamp.current = timestamp;

        /* =================================================
           GET LANGGRAPH RESULT
           ================================================= */

        /*
         * New receiver will store the complete backend
         * response under "langgraph_result".
         *
         * The fallback options below also allow this
         * App.js to work with your current stored format
         * during development.
         */

        const result =
          parsedEvent.langgraph_result ||
          parsedEvent.analysis_result ||
          parsedEvent.analysis ||
          parsedEvent;

        console.log("🤖 LangGraph analysis received:", result);

        /* =================================================
           CREATE UI RESULT
           ================================================= */

        const uiResult = {
          ...result,

          /* -----------------------------------------------
             SMS INFORMATION
             ----------------------------------------------- */

          sms: {
            sender: parsedEvent.sender || "",

            body: parsedEvent.body || "",

            timestamp: parsedEvent.timestamp || null,
          },

          /* -----------------------------------------------
             DEVICE INFORMATION
             ----------------------------------------------- */

          foreground_app: parsedEvent.foreground_app || "",

          expected_otp: parsedEvent.expected_otp || false,

          screen_unlocked: parsedEvent.screen_unlocked ?? true,
        };

        /* =================================================
           UPDATE SECURITY CENTER DATA
           ================================================= */

        setAnalysisResult(uiResult);

        console.log("✅ Security Center analysisResult updated");

        /* =================================================
           NAVIGATION
           ================================================= */

        /*
         * Do NOT interrupt onboarding, permissions,
         * or device-data setup.
         *
         * Once the user has entered the main application,
         * automatically show Security Center.
         */

        if (
          stageRef.current !== STAGES.ONBOARDING &&
          stageRef.current !== STAGES.PERMISSIONS &&
          stageRef.current !== STAGES.DEVICE_DATA
        ) {
          setStage(STAGES.SECURITY_CENTER);
        }

        /*
         * Keep the latest event available for the dedicated OTP, URL,
         * and contact screens. The timestamp guard above prevents this
         * monitor from processing the same event repeatedly.
         */
      } catch (error) {
        console.error("❌ Automatic SMS monitoring error:", error);
      }
    };

    /* =====================================================
       CHECK IMMEDIATELY
       ===================================================== */

    checkForNewSms();

    /* =====================================================
       CHECK EVERY 2 SECONDS
       ===================================================== */

    intervalId = setInterval(checkForNewSms, 2000);

    /* =====================================================
       CHECK WHEN APP RETURNS TO FOREGROUND
       ===================================================== */

    appStateSubscription = AppState.addEventListener("change", (nextState) => {
      if (nextState === "active") {
        console.log("📱 App became active - checking SMS");

        checkForNewSms();
      }
    });

    /* =====================================================
       CLEANUP
       ===================================================== */

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }

      if (appStateSubscription) {
        appStateSubscription.remove();
      }
    };
  }, []);

  /* =========================================================
     ONBOARDING
     ========================================================= */

  function handleContinue() {
    if (step === INTRO_STEPS.length - 1) {
      setStage(STAGES.PERMISSIONS);

      return;
    }

    setStep((currentStep) => currentStep + 1);
  }

  function handleSkip() {
    setStage(STAGES.PERMISSIONS);
  }

  /* =========================================================
     PERMISSIONS
     ========================================================= */

  function handleGrantPermissions() {
    setStage(STAGES.DEVICE_DATA);
  }

  /* =========================================================
     DEVICE DATA
     ========================================================= */

  function handleContinueFromDeviceData() {
    setStage(STAGES.SECURITY_CENTER);
  }

  /* =========================================================
     SECURITY CENTER
     ========================================================= */

  function handleBackToIntroduction() {
    setStage(STAGES.ONBOARDING);

    setStep(0);
  }

  function handleOtpAgent() {
    setStage(STAGES.OTP_AGENT);
  }

  function handleUrlAgent() {
    setStage(STAGES.URL_AGENT);
  }

  function handleContactAgent() {
    setStage(STAGES.CONTACT_AGENT);
  }

  /* =========================================================
     OTP AGENT
     ========================================================= */

  function handleBackFromOtpAgent() {
    setStage(STAGES.SECURITY_CENTER);
  }

  /* =========================================================
     URL AGENT
     ========================================================= */

  function handleBackFromUrlAgent() {
    setStage(STAGES.SECURITY_CENTER);
  }

  /* =========================================================
     CONTACT AGENT
     ========================================================= */

  function handleBackFromContactAgent() {
    setStage(STAGES.SECURITY_CENTER);
  }

  /* =========================================================
     MANUAL SCAN
     ========================================================= */

  function handleManualScanFromUrlAgent() {
    setScanReturnStage(STAGES.URL_AGENT);

    setStage(STAGES.SCAN);
  }

  function handleBackFromScan() {
    setStage(scanReturnStage);

    setScanReturnStage(STAGES.SECURITY_CENTER);
  }

  /* =========================================================
     MANUAL LANGGRAPH SMS ANALYSIS
     
     This is kept for ScanScreen.
     
     Automatic SMS detection does NOT depend on this.
     ========================================================= */

  function handleSmsAnalysis(result) {
    console.log("🤖 Manual LangGraph analysis received:", result);

    setAnalysisResult(result);

    setStage(STAGES.SECURITY_CENTER);
  }

  /* =========================================================
     UI
     ========================================================= */

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />

      {/* ===================================================
          ONBOARDING
          =================================================== */}

      {stage === STAGES.ONBOARDING && (
        <OnboardingScreen
          step={step}
          onContinue={handleContinue}
          onSkip={handleSkip}
        />
      )}

      {/* ===================================================
          PERMISSIONS
          =================================================== */}

      {stage === STAGES.PERMISSIONS && (
        <PermissionsScreen onGrantPermissions={handleGrantPermissions} />
      )}

      {/* ===================================================
          DEVICE DATA / SMS INBOX
          =================================================== */}

      {stage === STAGES.DEVICE_DATA && (
        <DeviceDataScreen onContinue={handleContinueFromDeviceData} />
      )}

      {/* ===================================================
          SECURITY CENTER
          =================================================== */}

      {stage === STAGES.SECURITY_CENTER && (
        <SecurityCenter
          onBack={handleBackToIntroduction}
          onOtpAgent={handleOtpAgent}
          onUrlAgent={handleUrlAgent}
          onContactAgent={handleContactAgent}
          analysisResult={analysisResult}
        />
      )}

      {/* ===================================================
          OTP AGENT
          =================================================== */}

      {stage === STAGES.OTP_AGENT && (
        <OtpMonitoringScreen onBack={handleBackFromOtpAgent} />
      )}

      {/* ===================================================
          URL AGENT
          =================================================== */}

      {stage === STAGES.URL_AGENT && (
        <UrlAgentScreen
          onBack={handleBackFromUrlAgent}
          onManualScan={handleManualScanFromUrlAgent}
        />
      )}

      {/* ===================================================
          CONTACT AGENT
          =================================================== */}

      {stage === STAGES.CONTACT_AGENT && (
        <ContactAgentScreen onBack={handleBackFromContactAgent} />
      )}

      {/* ===================================================
          MANUAL SCAN
          =================================================== */}

      {stage === STAGES.SCAN && (
        <ScanScreen
          onBack={handleBackFromScan}
          onAnalysisComplete={handleSmsAnalysis}
        />
      )}
    </SafeAreaProvider>
  );
}

import React, { useState } from "react";
import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider } from "react-native-safe-area-context";

import OnboardingScreen, {
  INTRO_STEPS,
} from "./components/OnboardingScreen";

import PermissionsScreen from "./components/PermissionsScreen";
import DeviceDataScreen from "./components/DeviceDataScreen";
import SecurityCenter from "./components/SecurityCenter";
import ScanScreen from "./components/ScanScreen";
import OtpMonitoringScreen from "./components/OtpMonitoringScreen";
import UrlAgentScreen from "./components/Urlagentscreen";
import ContactAgentScreen from "./components/ContactAgentScreen";

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

export default function App() {
  const [step, setStep] = useState(0);
  const [stage, setStage] = useState(STAGES.ONBOARDING);

  // Used when ScanScreen is launched from another agent.
  const [scanReturnStage, setScanReturnStage] = useState(
    STAGES.SECURITY_CENTER,
  );

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

  function handleGrantPermissions() {
    setStage(STAGES.DEVICE_DATA);
  }

  function handleContinueFromDeviceData() {
    setStage(STAGES.SECURITY_CENTER);
  }

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

  function handleBackFromOtpAgent() {
    setStage(STAGES.SECURITY_CENTER);
  }

  function handleBackFromUrlAgent() {
    setStage(STAGES.SECURITY_CENTER);
  }

  function handleBackFromContactAgent() {
    setStage(STAGES.SECURITY_CENTER);
  }

  function handleManualScanFromUrlAgent() {
    setScanReturnStage(STAGES.URL_AGENT);
    setStage(STAGES.SCAN);
  }

  function handleBackFromScan() {
    setStage(scanReturnStage);
    setScanReturnStage(STAGES.SECURITY_CENTER);
  }

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />

      {/* =========================================================
          ONBOARDING
      ========================================================= */}
      {stage === STAGES.ONBOARDING && (
        <OnboardingScreen
          step={step}
          onContinue={handleContinue}
          onSkip={handleSkip}
        />
      )}

      {/* =========================================================
          PERMISSIONS
      ========================================================= */}
      {stage === STAGES.PERMISSIONS && (
        <PermissionsScreen
          onGrantPermissions={handleGrantPermissions}
        />
      )}

      {/* =========================================================
          DEVICE DATA / SMS INBOX
      ========================================================= */}
      {stage === STAGES.DEVICE_DATA && (
        <DeviceDataScreen
          onContinue={handleContinueFromDeviceData}
        />
      )}

      {/* =========================================================
          SECURITY CENTER
      ========================================================= */}
      {stage === STAGES.SECURITY_CENTER && (
        <SecurityCenter
          onBack={handleBackToIntroduction}
          onOtpAgent={handleOtpAgent}
          onUrlAgent={handleUrlAgent}
          onContactAgent={handleContactAgent}
        />
      )}

      {/* =========================================================
          OTP AGENT
      ========================================================= */}
      {stage === STAGES.OTP_AGENT && (
        <OtpMonitoringScreen
          onBack={handleBackFromOtpAgent}
        />
      )}

      {/* =========================================================
          URL AGENT
      ========================================================= */}
      {stage === STAGES.URL_AGENT && (
        <UrlAgentScreen
          onBack={handleBackFromUrlAgent}
          onManualScan={handleManualScanFromUrlAgent}
        />
      )}

      {/* =========================================================
          CONTACT AGENT
      ========================================================= */}
      {stage === STAGES.CONTACT_AGENT && (
        <ContactAgentScreen
          onBack={handleBackFromContactAgent}
        />
      )}

      {/* =========================================================
          SCAN A MESSAGE
      ========================================================= */}
      {stage === STAGES.SCAN && (
        <ScanScreen
          onBack={handleBackFromScan}
        />
      )}
    </SafeAreaProvider>
  );
}
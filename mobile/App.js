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

const STAGES = {
  ONBOARDING: "onboarding",
  PERMISSIONS: "permissions",
  DEVICE_DATA: "device_data",
  SECURITY_CENTER: "security_center",
  OTP_AGENT: "otp_agent",
  URL_AGENT: "url_agent",
  SCAN: "scan",
};

export default function App() {
  const [step, setStep] = useState(0);
  const [stage, setStage] = useState(STAGES.ONBOARDING);

  // "Scan a specific message" can now be launched from the URL Agent
  // screen as well as (previously) directly from Security Center, so we
  // remember where to send the user back to when they're done.
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

  function handleBackFromOtpAgent() {
    setStage(STAGES.SECURITY_CENTER);
  }

  function handleBackFromUrlAgent() {
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

      {/* ONBOARDING */}
      {stage === STAGES.ONBOARDING && (
        <OnboardingScreen
          step={step}
          onContinue={handleContinue}
          onSkip={handleSkip}
        />
      )}

      {/* PERMISSIONS */}
      {stage === STAGES.PERMISSIONS && (
        <PermissionsScreen
          onGrantPermissions={handleGrantPermissions}
        />
      )}

      {/* DEVICE DATA / SMS INBOX */}
      {stage === STAGES.DEVICE_DATA && (
        <DeviceDataScreen
          onContinue={handleContinueFromDeviceData}
        />
      )}

      {/* SECURITY CENTER */}
      {stage === STAGES.SECURITY_CENTER && (
        <SecurityCenter
          onBack={handleBackToIntroduction}
          onOtpAgent={handleOtpAgent}
          onUrlAgent={handleUrlAgent}
        />
      )}

      {/* OTP AGENT - real-time OTP monitoring (native module + backend) */}
      {stage === STAGES.OTP_AGENT && (
        <OtpMonitoringScreen onBack={handleBackFromOtpAgent} />
      )}

      {/* URL AGENT - last 3 messages + real-time URL/spam monitoring */}
      {stage === STAGES.URL_AGENT && (
        <UrlAgentScreen
          onBack={handleBackFromUrlAgent}
          onManualScan={handleManualScanFromUrlAgent}
        />
      )}

      {/* SCAN A MESSAGE - URL agent (paste text/link -> /analyze-url) */}
      {stage === STAGES.SCAN && (
        <ScanScreen
          onBack={handleBackFromScan}
        />
      )}
    </SafeAreaProvider>
  );
}
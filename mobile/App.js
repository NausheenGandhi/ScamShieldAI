import React, { useState } from "react";
import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider } from "react-native-safe-area-context";

import OnboardingScreen, {
  INTRO_STEPS,
} from "./components/OnboardingScreen";

import PermissionsScreen from "./components/PermissionsScreen";
import DeviceDataScreen from "./components/DeviceDataScreen";
import SecurityCenter from "./components/SecurityCenter";
import OtpMonitoringScreen from "./components/OtpMonitoringScreen";

const STAGES = {
  ONBOARDING: "onboarding",
  PERMISSIONS: "permissions",
  DEVICE_DATA: "device_data",
  SECURITY_CENTER: "security_center",
  OTP_MONITORING: "otp_monitoring",
};

export default function App() {
  const [step, setStep] = useState(0);
  const [stage, setStage] = useState(STAGES.ONBOARDING);

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

  function handleScan() {
    setStage(STAGES.OTP_MONITORING);
  }

  function handleBackFromOtpMonitoring() {
    setStage(STAGES.SECURITY_CENTER);
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
          onScan={handleScan}
        />
      )}

      {/* REAL-TIME OTP MONITORING */}
      {stage === STAGES.OTP_MONITORING && (
        <OtpMonitoringScreen
          onBack={handleBackFromOtpMonitoring}
        />
      )}
    </SafeAreaProvider>
  );
}
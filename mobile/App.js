import React, { useState } from "react";
import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider } from "react-native-safe-area-context";

import OnboardingScreen, { INTRO_STEPS } from "./components/OnboardingScreen";
import PermissionsScreen from "./components/PermissionsScreen";
import SecurityCenter from "./components/SecurityCenter";

const STAGES = {
  ONBOARDING: "onboarding",
  PERMISSIONS: "permissions",
  SECURITY_CENTER: "security_center",
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
    setStage(STAGES.SECURITY_CENTER);
  }

  function handleBackToIntroduction() {
    setStage(STAGES.ONBOARDING);
    setStep(0);
  }

  function handleScan() {
    // Connect your message scanning screen or API here later.
  }

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      {stage === STAGES.ONBOARDING && (
        <OnboardingScreen
          step={step}
          onContinue={handleContinue}
          onSkip={handleSkip}
        />
      )}
      {stage === STAGES.PERMISSIONS && (
        <PermissionsScreen onGrantPermissions={handleGrantPermissions} />
      )}
      {stage === STAGES.SECURITY_CENTER && (
        <SecurityCenter onBack={handleBackToIntroduction} onScan={handleScan} />
      )}
    </SafeAreaProvider>
  );
}

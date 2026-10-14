import React, { useRef } from "react";
import {
  Animated,
  Dimensions,
  Pressable,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";

import ShieldIcon from "./ShieldIcon";
import ProgressIndicator from "./ProgressIndicator";
import { COLORS } from "../constants/colors";

const { width } = Dimensions.get("window");

export const INTRO_STEPS = [
  {
    icon: "shield-checkmark-outline",
    eyebrow: "WELCOME TO",
    title: "ScamShield AI",
    description:
      "A real-time cybersecurity assistant that reads the threats hidden inside your messages — before you tap anything.",
  },
  {
    icon: "hardware-chip-outline",
    eyebrow: "MULTI-AGENT ENGINE",
    title: "Five AI agents. One verdict.",
    description:
      "Contact, URL, Pattern, OTP, and Coordinator agents analyse each message independently, then fuse their findings into a single risk score.",
  },
  {
    icon: "scan-outline",
    eyebrow: "TOTAL COVERAGE",
    title: "Smishing, links, & OTP",
    description:
      "Detects phishing SMS, look-alike domains, unsolicited OTP requests and SIM-swap indicators.",
  },
  {
    icon: "cube-outline",
    eyebrow: "COMMUNITY DEFENCE",
    title: "MongoDB threat intel",
    description:
      "Every confirmed scam is fingerprinted and written on-chain, so a threat caught on one device protects everyone instantly.",
  },
];

export default function OnboardingScreen({ step, onContinue, onSkip }) {
  const fadeAnimation = useRef(new Animated.Value(1)).current;
  const slideAnimation = useRef(new Animated.Value(0)).current;
  const currentSlide = INTRO_STEPS[step];
  const isLastStep = step === INTRO_STEPS.length - 1;

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
      <View style={styles.container}>
        <View style={styles.topGlow} />

        <Animated.View
          style={[
            styles.content,
            {
              opacity: fadeAnimation,
              transform: [{ translateY: slideAnimation }],
            },
          ]}
        >
          <ShieldIcon iconName={currentSlide.icon} />

          <View style={styles.textContent}>
            <Text style={styles.eyebrow}>{currentSlide.eyebrow}</Text>
            <Text style={styles.title}>{currentSlide.title}</Text>
            <Text style={styles.description}>{currentSlide.description}</Text>
          </View>
        </Animated.View>

        <View style={styles.bottomSection}>
          <ProgressIndicator
            currentStep={step}
            totalSteps={INTRO_STEPS.length}
          />

          <Pressable
            onPress={onContinue}
            accessibilityRole="button"
            accessibilityLabel={isLastStep ? "Get started" : "Continue"}
            style={({ pressed }) => [
              styles.continueButton,
              pressed && styles.buttonPressed,
            ]}
          >
            <Text style={styles.continueButtonText}>
              {isLastStep ? "Get started" : "Continue"}
            </Text>
            <Ionicons
              name="arrow-forward"
              size={21}
              color={COLORS.darkIcon}
              style={styles.buttonArrow}
            />
          </Pressable>

          <Pressable
            onPress={onSkip}
            accessibilityRole="button"
            accessibilityLabel="Skip introduction"
            style={({ pressed }) => [
              styles.skipButton,
              pressed && styles.skipPressed,
            ]}
          >
            <Text style={styles.skipButtonText}>Skip introduction</Text>
          </Pressable>
        </View>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: COLORS.background },
  container: {
    flex: 1,
    backgroundColor: COLORS.background,
    paddingHorizontal: 28,
    overflow: "hidden",
  },
  topGlow: {
    position: "absolute",
    top: -80,
    left: -60,
    right: -60,
    height: 330,
    borderRadius: 180,
    backgroundColor: "#0A3046",
    opacity: 0.38,
  },
  content: {
    flex: 1,
    alignItems: "center",
    justifyContent: "center",
    paddingBottom: 18,
  },
  textContent: {
    alignItems: "center",
    maxWidth: 390,
    paddingTop: width < 380 ? 44 : 58,
  },
  eyebrow: {
    color: COLORS.teal,
    fontSize: 15,
    fontWeight: "700",
    letterSpacing: 4,
    marginBottom: 18,
  },
  title: {
    color: COLORS.white,
    fontSize: width < 380 ? 34 : 39,
    fontWeight: "700",
    letterSpacing: -1,
    textAlign: "center",
  },
  description: {
    color: COLORS.muted,
    fontSize: 16,
    lineHeight: 27,
    fontWeight: "400",
    textAlign: "center",
    marginTop: 22,
    maxWidth: 370,
  },
  bottomSection: { alignItems: "center", paddingBottom: 2 },
  continueButton: {
    width: "100%",
    minHeight: 66,
    borderRadius: 34,
    backgroundColor: COLORS.cyan,
    alignItems: "center",
    justifyContent: "center",
    flexDirection: "row",
    shadowColor: COLORS.cyan,
    shadowOffset: { width: 0, height: 10 },
    shadowOpacity: 0.2,
    shadowRadius: 18,
    elevation: 8,
  },
  continueButtonText: {
    color: COLORS.darkIcon,
    fontSize: 17,
    fontWeight: "700",
  },
  buttonArrow: { marginLeft: 10 },
  skipButton: {
    minHeight: 58,
    minWidth: 180,
    alignItems: "center",
    justifyContent: "center",
  },
  skipButtonText: { color: COLORS.muted, fontSize: 14, fontWeight: "500" },
  buttonPressed: { opacity: 0.75, transform: [{ scale: 0.985 }] },
  skipPressed: { opacity: 0.6 },
});

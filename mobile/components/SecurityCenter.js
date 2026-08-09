import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import { COLORS } from "../constants/colors";

export default function SecurityCenter({ onBack, onOtpAgent, onUrlAgent }) {
  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
      <View style={styles.securityContainer}>
        <View style={styles.securityHeader}>
          <View>
            <Text style={styles.securityEyebrow}>SCAMSHIELD AI</Text>
            <Text style={styles.securityTitle}>Security Center</Text>
          </View>
          <View style={styles.protectedBadge}>
            <View style={styles.protectedDot} />
            <Text style={styles.protectedText}>Protected</Text>
          </View>
        </View>

        <View style={styles.readyCard}>
          <View style={styles.readyIcon}>
            <Ionicons
              name="shield-checkmark"
              size={31}
              color={COLORS.darkIcon}
            />
          </View>
          <View style={styles.readyTextContainer}>
            <Text style={styles.readyTitle}>You are ready</Text>
            <Text style={styles.readyDescription}>
              Pick an agent below to see what it's watching for.
            </Text>
          </View>
        </View>

        <View style={styles.agentsRow}>
          <Pressable
            onPress={onOtpAgent}
            accessibilityRole="button"
            accessibilityLabel="Open OTP Agent"
            style={({ pressed }) => [
              styles.agentCard,
              pressed && styles.buttonPressed,
            ]}
          >
            <View
              style={[styles.agentIconCircle, { backgroundColor: COLORS.cyan }]}
            >
              <Ionicons name="key-outline" size={26} color={COLORS.darkIcon} />
            </View>
            <Text style={styles.agentCardTitle}>OTP Agent</Text>
            <Text style={styles.agentCardSubtitle}>
              Real-time OTP protection
            </Text>
          </Pressable>

          <Pressable
            onPress={onUrlAgent}
            accessibilityRole="button"
            accessibilityLabel="Open URL Agent"
            style={({ pressed }) => [
              styles.agentCard,
              pressed && styles.buttonPressed,
            ]}
          >
            <View
              style={[styles.agentIconCircle, { backgroundColor: COLORS.teal }]}
            >
              <Ionicons name="link-outline" size={26} color={COLORS.darkIcon} />
            </View>
            <Text style={styles.agentCardTitle}>URL Agent</Text>
            <Text style={styles.agentCardSubtitle}>
              Link & spam detection
            </Text>
          </Pressable>
        </View>

        <Pressable
          onPress={onBack}
          accessibilityRole="button"
          style={({ pressed }) => [
            styles.backButton,
            pressed && styles.skipPressed,
          ]}
        >
          <Text style={styles.backButtonText}>View introduction again</Text>
        </Pressable>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: COLORS.background },
  securityContainer: {
    flex: 1,
    backgroundColor: COLORS.background,
    paddingHorizontal: 28,
  },
  securityHeader: {
    paddingTop: 26,
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-start",
  },
  securityEyebrow: {
    color: COLORS.teal,
    fontSize: 12,
    fontWeight: "700",
    letterSpacing: 2.4,
    marginBottom: 8,
  },
  securityTitle: {
    color: COLORS.white,
    fontSize: 30,
    fontWeight: "700",
    letterSpacing: -0.8,
  },
  protectedBadge: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: COLORS.surface,
    borderRadius: 18,
    paddingHorizontal: 12,
    paddingVertical: 9,
    marginTop: 3,
  },
  protectedDot: {
    width: 7,
    height: 7,
    borderRadius: 7,
    backgroundColor: COLORS.teal,
    marginRight: 7,
  },
  protectedText: { color: COLORS.white, fontSize: 12, fontWeight: "600" },
  readyCard: {
    minHeight: 150,
    borderRadius: 28,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: "#16435A",
    marginTop: 32,
    padding: 22,
    flexDirection: "row",
    alignItems: "center",
  },
  readyIcon: {
    width: 64,
    height: 64,
    borderRadius: 22,
    backgroundColor: COLORS.cyan,
    alignItems: "center",
    justifyContent: "center",
  },
  readyTextContainer: { flex: 1, paddingLeft: 16 },
  readyTitle: {
    color: COLORS.white,
    fontSize: 21,
    fontWeight: "700",
    marginBottom: 8,
  },
  readyDescription: { color: COLORS.muted, fontSize: 14, lineHeight: 21 },

  agentsRow: {
    flexDirection: "row",
    gap: 14,
    marginTop: 18,
  },
  agentCard: {
    flex: 1,
    minHeight: 150,
    borderRadius: 26,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: "#16435A",
    alignItems: "center",
    justifyContent: "center",
    paddingVertical: 22,
    paddingHorizontal: 12,
  },
  agentIconCircle: {
    width: 58,
    height: 58,
    borderRadius: 20,
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 14,
  },
  agentCardTitle: {
    color: COLORS.white,
    fontSize: 16,
    fontWeight: "700",
    marginBottom: 6,
  },
  agentCardSubtitle: {
    color: COLORS.muted,
    fontSize: 12,
    textAlign: "center",
    lineHeight: 17,
  },

  backButton: {
    minHeight: 58,
    alignItems: "center",
    justifyContent: "center",
    marginTop: 16,
  },
  backButtonText: { color: COLORS.muted, fontSize: 14, fontWeight: "500" },
  buttonPressed: { opacity: 0.75, transform: [{ scale: 0.985 }] },
  skipPressed: { opacity: 0.6 },
});
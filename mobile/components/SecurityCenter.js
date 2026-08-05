import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import { COLORS } from "../constants/colors";

export default function SecurityCenter({ onBack, onScan }) {
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
              Paste a message or link to check it before you open it.
            </Text>
          </View>
        </View>

        <Pressable
          onPress={onScan}
          accessibilityRole="button"
          accessibilityLabel="Scan a message"
          style={({ pressed }) => [
            styles.scanButton,
            pressed && styles.buttonPressed,
          ]}
        >
          <Ionicons name="search-outline" size={23} color={COLORS.darkIcon} />
          <Text style={styles.scanButtonText}>Scan a message</Text>
          <Ionicons name="arrow-up-outline" size={22} color={COLORS.darkIcon} />
        </Pressable>

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
    minHeight: 180,
    borderRadius: 28,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: "#16435A",
    marginTop: 42,
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
  scanButton: {
    minHeight: 62,
    borderRadius: 31,
    backgroundColor: COLORS.cyan,
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 22,
    marginTop: 18,
  },
  scanButtonText: {
    flex: 1,
    color: COLORS.darkIcon,
    fontSize: 16,
    fontWeight: "700",
    paddingLeft: 12,
  },
  backButton: {
    minHeight: 58,
    alignItems: "center",
    justifyContent: "center",
    marginTop: 12,
  },
  backButtonText: { color: COLORS.muted, fontSize: 14, fontWeight: "500" },
  buttonPressed: { opacity: 0.75, transform: [{ scale: 0.985 }] },
  skipPressed: { opacity: 0.6 },
});

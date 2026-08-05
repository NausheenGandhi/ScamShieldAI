import React, { useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import { COLORS } from "../constants/colors";

const PERMISSIONS = [
  {
    id: "sms",
    icon: "chatbubble-outline",
    title: "SMS access",
    badge: "REQUIRED",
    description:
      "Reads incoming messages locally so the agents can detect phishing links, fake OTP requests and scam campaigns. Message text never leaves your device unencrypted.",
  },
  {
    id: "contacts",
    icon: "people-outline",
    title: "Contacts access",
    badge: "REQUIRED",
    description:
      "Lets the Contact Agent tell known senders apart from unknown or spoofed numbers, and score sender trust from your interaction history.",
  },
  {
    id: "notifications",
    icon: "notifications-outline",
    title: "Notifications",
    badge: "REQUIRED",
    description:
      "Warns you the instant a scam is detected — before you open the message or tap a malicious link.",
  },
  {
    id: "internet",
    icon: "globe-outline",
    title: "Internet access",
    badge: "RECOMMENDED",
    description:
      "Needed for URL reputation lookups, Gemini AI explanations and syncing verified threat hashes with the blockchain network.",
  },
];

export default function PermissionsScreen({ onGrantPermissions }) {
  const [granted, setGranted] = useState({});

  function handleAllow(id) {
    setGranted((prev) => ({ ...prev, [id]: true }));
    // Hook up actual permission requests here later
    // (e.g. expo-notifications, expo-contacts, native SMS module).
  }

  const requiredIds = PERMISSIONS.filter((p) => p.badge === "REQUIRED").map(
    (p) => p.id,
  );
  const allRequiredGranted = requiredIds.every((id) => granted[id]);

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
      <View style={styles.container}>
        <ScrollView
          contentContainerStyle={styles.scrollContent}
          showsVerticalScrollIndicator={false}
        >
          <View style={styles.noticeCard}>
            <Ionicons
              name="shield-checkmark-outline"
              size={20}
              color={COLORS.teal}
              style={styles.noticeIcon}
            />
            <Text style={styles.noticeText}>
              ScamShield AI runs its detection agents on-device. We ask for the
              minimum access needed and never sell, share or store the content
              of your messages.
            </Text>
          </View>

          {PERMISSIONS.map((permission) => (
            <View key={permission.id} style={styles.permissionCard}>
              <View style={styles.permissionHeader}>
                <View style={styles.permissionIconCircle}>
                  <Ionicons
                    name={permission.icon}
                    size={20}
                    color={COLORS.teal}
                  />
                </View>

                <View style={styles.permissionTitleRow}>
                  <Text style={styles.permissionTitle}>{permission.title}</Text>
                  <View
                    style={[
                      styles.badge,
                      permission.badge === "RECOMMENDED" &&
                        styles.badgeRecommended,
                    ]}
                  >
                    <Text style={styles.badgeText}>{permission.badge}</Text>
                  </View>
                </View>
              </View>

              <Text style={styles.permissionDescription}>
                {permission.description}
              </Text>

              <Pressable
                onPress={() => handleAllow(permission.id)}
                accessibilityRole="button"
                accessibilityLabel={`Allow ${permission.title}`}
                style={({ pressed }) => [
                  styles.allowButton,
                  granted[permission.id] && styles.allowedButton,
                  pressed && styles.buttonPressed,
                ]}
              >
                <Text
                  style={[
                    styles.allowButtonText,
                    granted[permission.id] && styles.allowedButtonText,
                  ]}
                >
                  {granted[permission.id] ? "Allowed" : "Allow"}
                </Text>
              </Pressable>
            </View>
          ))}
        </ScrollView>

        <Pressable
          onPress={onGrantPermissions}
          disabled={!allRequiredGranted}
          accessibilityRole="button"
          accessibilityLabel="Grant required permissions"
          style={({ pressed }) => [
            styles.grantButton,
            !allRequiredGranted && styles.grantButtonDisabled,
            pressed && allRequiredGranted && styles.buttonPressed,
          ]}
        >
          <Text
            style={[
              styles.grantButtonText,
              !allRequiredGranted && styles.grantButtonTextDisabled,
            ]}
          >
            Grant required permissions
          </Text>
        </Pressable>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: COLORS.background },
  container: {
    flex: 1,
    backgroundColor: COLORS.background,
    paddingHorizontal: 20,
  },
  scrollContent: { paddingTop: 20, paddingBottom: 20 },

  noticeCard: {
    flexDirection: "row",
    backgroundColor: COLORS.surface,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: "#16435A",
    padding: 18,
    marginBottom: 18,
  },
  noticeIcon: { marginRight: 12, marginTop: 2 },
  noticeText: {
    flex: 1,
    color: COLORS.muted,
    fontSize: 13,
    lineHeight: 20,
  },

  permissionCard: {
    backgroundColor: COLORS.surface,
    borderRadius: 22,
    borderWidth: 1,
    borderColor: "#16435A",
    padding: 20,
    marginBottom: 16,
  },
  permissionHeader: {
    flexDirection: "row",
    alignItems: "flex-start",
    marginBottom: 12,
  },
  permissionIconCircle: {
    width: 40,
    height: 40,
    borderRadius: 14,
    backgroundColor: COLORS.inactive,
    alignItems: "center",
    justifyContent: "center",
    marginRight: 12,
  },
  permissionTitleRow: {
    flex: 1,
    flexDirection: "row",
    alignItems: "center",
    flexWrap: "wrap",
    gap: 8,
  },
  permissionTitle: {
    color: COLORS.white,
    fontSize: 16,
    fontWeight: "700",
  },
  badge: {
    backgroundColor: COLORS.inactive,
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 3,
  },
  badgeRecommended: {
    backgroundColor: "#1A3A2E",
  },
  badgeText: {
    color: COLORS.muted,
    fontSize: 10,
    fontWeight: "700",
    letterSpacing: 0.5,
  },
  permissionDescription: {
    color: COLORS.muted,
    fontSize: 13,
    lineHeight: 20,
    marginBottom: 16,
  },

  allowButton: {
    backgroundColor: COLORS.white,
    borderRadius: 20,
    paddingVertical: 10,
    paddingHorizontal: 20,
    alignSelf: "flex-start",
  },
  allowButtonText: {
    color: COLORS.darkIcon,
    fontSize: 14,
    fontWeight: "700",
  },
  allowedButton: {
    backgroundColor: COLORS.cyan,
  },
  allowedButtonText: {
    color: COLORS.darkIcon,
  },

  grantButton: {
    minHeight: 58,
    borderRadius: 30,
    backgroundColor: COLORS.white,
    alignItems: "center",
    justifyContent: "center",
    marginTop: 4,
    marginBottom: 8,
  },
  grantButtonDisabled: {
    backgroundColor: COLORS.inactive,
  },
  grantButtonText: {
    color: COLORS.darkIcon,
    fontSize: 16,
    fontWeight: "700",
  },
  grantButtonTextDisabled: {
    color: COLORS.muted,
  },

  buttonPressed: {
    opacity: 0.8,
  },
});

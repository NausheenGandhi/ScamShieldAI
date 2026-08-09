import React, { useState } from "react";
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import { COLORS } from "../constants/colors";
import { API_BASE_URL } from "../constants/api";

// Status colors keyed by the backend's "category" field.
// If your constants/colors.js already defines danger/warning/safe colors,
// swap these out for COLORS.danger / COLORS.warning / COLORS.safe instead.
const STATUS_STYLES = {
  phishing: { color: "#FF5C5C", label: "Likely a scam" },
  spam: { color: "#F5C542", label: "Spam / risky" },
  legitimate: { color: "#3DDC97", label: "Looks safe" },
  unknown: { color: COLORS.muted, label: "Unable to determine" },
};

export default function ScanScreen({ onBack }) {
  const [inputText, setInputText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showDetails, setShowDetails] = useState(false);

  const canScan = inputText.trim().length > 0 && !loading;

  async function handleScan() {
    if (!canScan) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setShowDetails(false);

    try {
      const response = await fetch(`${API_BASE_URL}/analyze-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sender: "manual_scan",
          body: inputText.trim(),
        }),
      });

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        throw new Error(errBody.detail || `Server error (${response.status})`);
      }

      const data = await response.json();
      setResult(data);
    } catch (e) {
      setError(e.message || "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  function handleReset() {
    setInputText("");
    setResult(null);
    setError(null);
    setShowDetails(false);
  }

  const statusStyle =
    STATUS_STYLES[result?.category] || STATUS_STYLES.unknown;

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
      <ScrollView
        contentContainerStyle={styles.scrollContent}
        keyboardShouldPersistTaps="handled"
      >
        <View style={styles.header}>
          <Pressable onPress={onBack} hitSlop={12}>
            <Ionicons name="arrow-back" size={24} color={COLORS.white} />
          </Pressable>
          <Text style={styles.title}>Scan a Message</Text>
          <View style={{ width: 24 }} />
        </View>

        <Text style={styles.subtitle}>
          Paste the SMS text or link you want to check.
        </Text>

        <TextInput
          style={styles.input}
          placeholder="Paste message or link here..."
          placeholderTextColor={COLORS.muted}
          value={inputText}
          onChangeText={setInputText}
          multiline
          textAlignVertical="top"
          editable={!loading}
        />

        <Pressable
          onPress={handleScan}
          disabled={!canScan}
          style={({ pressed }) => [
            styles.scanButton,
            !canScan && styles.scanButtonDisabled,
            pressed && canScan && styles.buttonPressed,
          ]}
        >
          {loading ? (
            <ActivityIndicator color={COLORS.darkIcon} />
          ) : (
            <>
              <Ionicons
                name="search-outline"
                size={20}
                color={COLORS.darkIcon}
              />
              <Text style={styles.scanButtonText}>Check this message</Text>
            </>
          )}
        </Pressable>

        {loading && (
          <Text style={styles.loadingHint}>
            Checking links, sender info, and context — this can take a few
            seconds...
          </Text>
        )}

        {error && (
          <View style={styles.errorCard}>
            <Ionicons name="alert-circle-outline" size={20} color="#FF5C5C" />
            <Text style={styles.errorText}>{error}</Text>
          </View>
        )}

        {result && (
          <View
            style={[
              styles.resultCard,
              { borderColor: statusStyle.color },
            ]}
          >
            <View style={styles.resultHeader}>
              <View
                style={[styles.statusDot, { backgroundColor: statusStyle.color }]}
              />
              <Text style={[styles.resultLabel, { color: statusStyle.color }]}>
                {statusStyle.label}
              </Text>
              {result.confidence && (
                <Text style={styles.confidenceText}>
                  {result.confidence} confidence
                </Text>
              )}
            </View>

            {result.brand_impersonated && (
              <Text style={styles.brandText}>
                Claims to be from: {result.brand_impersonated}
              </Text>
            )}

            <Text style={styles.explanationText}>
              {result.short_explanation}
            </Text>

            {result.context && (
              <Pressable
                onPress={() => setShowDetails((v) => !v)}
                style={styles.detailsToggle}
              >
                <Text style={styles.detailsToggleText}>
                  {showDetails ? "Hide details" : "View details"}
                </Text>
                <Ionicons
                  name={showDetails ? "chevron-up" : "chevron-down"}
                  size={16}
                  color={COLORS.teal}
                />
              </Pressable>
            )}

            {showDetails && result.context && (
              <View style={styles.detailsBox}>
                {result.context.final_url && (
                  <DetailRow
                    label="Final destination"
                    value={result.context.final_url}
                  />
                )}
                {result.context.domain_info?.domain && (
                  <DetailRow
                    label="Domain"
                    value={result.context.domain_info.domain}
                  />
                )}
                {result.context.domain_info?.age_days != null && (
                  <DetailRow
                    label="Domain age"
                    value={`${result.context.domain_info.age_days} days`}
                  />
                )}
                {result.context.brand_domain?.official_domain && (
                  <DetailRow
                    label="Brand's real domain"
                    value={result.context.brand_domain.official_domain}
                  />
                )}
                {result.context.html_summary && (
                  <DetailRow
                    label="Page content"
                    value={result.context.html_summary}
                  />
                )}
                {result.reasoning && (
                  <DetailRow label="Full reasoning" value={result.reasoning} />
                )}
              </View>
            )}
          </View>
        )}

        {(result || error) && (
          <Pressable onPress={handleReset} style={styles.resetButton}>
            <Text style={styles.resetButtonText}>Scan another message</Text>
          </Pressable>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

function DetailRow({ label, value }) {
  return (
    <View style={styles.detailRow}>
      <Text style={styles.detailLabel}>{label}</Text>
      <Text style={styles.detailValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: COLORS.background },
  scrollContent: { padding: 24, paddingBottom: 48 },
  header: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 20,
  },
  title: { color: COLORS.white, fontSize: 20, fontWeight: "700" },
  subtitle: { color: COLORS.muted, fontSize: 14, marginBottom: 16 },
  input: {
    minHeight: 120,
    borderRadius: 20,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: "#16435A",
    padding: 16,
    color: COLORS.white,
    fontSize: 15,
    marginBottom: 16,
  },
  scanButton: {
    minHeight: 58,
    borderRadius: 29,
    backgroundColor: COLORS.cyan,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 10,
  },
  scanButtonDisabled: { opacity: 0.4 },
  scanButtonText: { color: COLORS.darkIcon, fontSize: 16, fontWeight: "700" },
  buttonPressed: { opacity: 0.8 },
  loadingHint: {
    color: COLORS.muted,
    fontSize: 12,
    textAlign: "center",
    marginTop: 10,
  },
  errorCard: {
    marginTop: 20,
    borderRadius: 16,
    backgroundColor: "#2A1414",
    borderWidth: 1,
    borderColor: "#FF5C5C",
    padding: 16,
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
  },
  errorText: { color: "#FF9C9C", flex: 1, fontSize: 13 },
  resultCard: {
    marginTop: 20,
    borderRadius: 20,
    backgroundColor: COLORS.surface,
    borderWidth: 1.5,
    padding: 20,
  },
  resultHeader: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
    marginBottom: 12,
  },
  statusDot: { width: 10, height: 10, borderRadius: 5 },
  resultLabel: { fontSize: 17, fontWeight: "700", flex: 1 },
  confidenceText: { color: COLORS.muted, fontSize: 12 },
  brandText: { color: COLORS.muted, fontSize: 13, marginBottom: 8 },
  explanationText: { color: COLORS.white, fontSize: 14, lineHeight: 21 },
  detailsToggle: {
    flexDirection: "row",
    alignItems: "center",
    gap: 4,
    marginTop: 14,
  },
  detailsToggleText: { color: COLORS.teal, fontSize: 13, fontWeight: "600" },
  detailsBox: {
    marginTop: 12,
    borderTopWidth: 1,
    borderTopColor: "#16435A",
    paddingTop: 12,
    gap: 10,
  },
  detailRow: { gap: 2 },
  detailLabel: {
    color: COLORS.teal,
    fontSize: 11,
    fontWeight: "700",
    letterSpacing: 1,
    textTransform: "uppercase",
  },
  detailValue: { color: COLORS.muted, fontSize: 13, lineHeight: 18 },
  resetButton: { marginTop: 16, alignItems: "center", paddingVertical: 12 },
  resetButtonText: { color: COLORS.muted, fontSize: 14, fontWeight: "500" },
});
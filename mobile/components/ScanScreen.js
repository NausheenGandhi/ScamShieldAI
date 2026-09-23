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

// ============================================================
// RISK STYLES
// ============================================================

const RISK_STYLES = {
  CRITICAL: {
    color: "#FF3B30",
    label: "CRITICAL RISK",
  },

  HIGH: {
    color: "#FF5C5C",
    label: "HIGH RISK",
  },

  MEDIUM: {
    color: "#F5C542",
    label: "MEDIUM RISK",
  },

  LOW: {
    color: "#3DDC97",
    label: "LOW RISK",
  },

  SAFE: {
    color: "#3DDC97",
    label: "SAFE",
  },

  unknown: {
    color: COLORS.muted,
    label: "UNKNOWN",
  },
};

// ============================================================
// COMPONENT
// ============================================================

export default function ScanScreen({ onBack, onAnalysisComplete }) {
  const [inputText, setInputText] = useState("");

  const [loading, setLoading] = useState(false);

  const [result, setResult] = useState(null);

  const [error, setError] = useState(null);

  const [showDetails, setShowDetails] = useState(false);

  const canScan = inputText.trim().length > 0 && !loading;

  // ==========================================================
  // ANALYZE SMS USING LANGGRAPH
  // ==========================================================

  async function handleScan() {
    if (!canScan) return;

    setLoading(true);
    setError(null);
    setResult(null);
    setShowDetails(false);

    try {
      console.log("=================================");
      console.log("SCAMSHIELD AI - LANGGRAPH ANALYSIS");
      console.log("=================================");
      console.log("Message:", inputText.trim());

      const response = await fetch(`${API_BASE_URL}/analyze-sms`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify({
          sender: "manual_scan",

          body: inputText.trim(),

          timestamp: Date.now(),

          source: "manual_scan",

          expected_otp: false,

          foreground_app: "Messages",

          screen_unlocked: true,

          is_saved_contact: false,

          contact_name: "",
        }),
      });

      // ======================================================
      // HANDLE SERVER ERROR
      // ======================================================

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));

        throw new Error(errBody.detail || `Server error (${response.status})`);
      }

      // ======================================================
      // READ LANGGRAPH RESPONSE
      // ======================================================

      const data = await response.json();

      console.log("LangGraph response:", JSON.stringify(data, null, 2));

      if (!data.success) {
        throw new Error("SMS analysis was not successful.");
      }

      // ======================================================
      // SAVE RESULT LOCALLY
      // ======================================================

      setResult(data);

      // ======================================================
      // SEND RESULT TO APP.JS
      // ======================================================

      if (onAnalysisComplete) {
        onAnalysisComplete(data);
      }
    } catch (e) {
      console.error("LangGraph SMS analysis error:", e);

      setError(e.message || "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  // ==========================================================
  // RESET
  // ==========================================================

  function handleReset() {
    setInputText("");

    setResult(null);

    setError(null);

    setShowDetails(false);
  }

  // ==========================================================
  // EXTRACT FINAL ANALYSIS
  // ==========================================================

  const analysis = result?.analysis || null;

  const riskStatus = analysis?.status || "unknown";

  const riskStyle = RISK_STYLES[riskStatus] || RISK_STYLES.unknown;

  const riskScore = typeof analysis?.score === "number" ? analysis.score : 0;

  const routes = result?.routes || [];

  const agentResults = analysis?.agent_results || {};

  const reasons = analysis?.reasons || [];

  // ==========================================================
  // RENDER
  // ==========================================================

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
      <ScrollView
        contentContainerStyle={styles.scrollContent}
        keyboardShouldPersistTaps="handled"
      >
        {/* ====================================================
            HEADER
        ==================================================== */}

        <View style={styles.header}>
          <Pressable onPress={onBack} hitSlop={12}>
            <Ionicons name="arrow-back" size={24} color={COLORS.white} />
          </Pressable>

          <Text style={styles.title}>Scan a Message</Text>

          <View style={{ width: 24 }} />
        </View>

        {/* ====================================================
            DESCRIPTION
        ==================================================== */}

        <Text style={styles.subtitle}>
          Paste the SMS text or message you want ScamShield AI to analyze.
        </Text>

        {/* ====================================================
            INPUT
        ==================================================== */}

        <TextInput
          style={styles.input}
          placeholder="Paste message here..."
          placeholderTextColor={COLORS.muted}
          value={inputText}
          onChangeText={setInputText}
          multiline
          textAlignVertical="top"
          editable={!loading}
        />

        {/* ====================================================
            SCAN BUTTON
        ==================================================== */}

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
            <>
              <ActivityIndicator color={COLORS.darkIcon} />

              <Text style={styles.scanButtonText}>Analyzing...</Text>
            </>
          ) : (
            <>
              <Ionicons
                name="shield-checkmark-outline"
                size={20}
                color={COLORS.darkIcon}
              />

              <Text style={styles.scanButtonText}>
                Analyze with ScamShield AI
              </Text>
            </>
          )}
        </Pressable>

        {/* ====================================================
            LOADING
        ==================================================== */}

        {loading && (
          <Text style={styles.loadingHint}>
            Running LangGraph agents and calculating the final risk...
          </Text>
        )}

        {/* ====================================================
            ERROR
        ==================================================== */}

        {error && (
          <View style={styles.errorCard}>
            <Ionicons name="alert-circle-outline" size={22} color="#FF5C5C" />

            <Text style={styles.errorText}>{error}</Text>
          </View>
        )}

        {/* ====================================================
            LANGGRAPH RESULT
        ==================================================== */}

        {analysis && (
          <View
            style={[
              styles.resultCard,
              {
                borderColor: riskStyle.color,
              },
            ]}
          >
            {/* ================================================
                RISK HEADER
            ================================================= */}

            <View style={styles.riskHeader}>
              <View
                style={[
                  styles.statusDot,
                  {
                    backgroundColor: riskStyle.color,
                  },
                ]}
              />

              <Text
                style={[
                  styles.resultLabel,
                  {
                    color: riskStyle.color,
                  },
                ]}
              >
                {riskStyle.label}
              </Text>
            </View>

            {/* ================================================
                SCORE
            ================================================= */}

            <View style={styles.scoreContainer}>
              <Text style={styles.scoreNumber}>{riskScore}</Text>

              <Text style={styles.scoreTotal}>/100</Text>
            </View>

            <Text style={styles.scoreDescription}>
              Final risk score calculated by the LangGraph Coordinator.
            </Text>

            {/* ================================================
                ROUTES
            ================================================= */}

            <View style={styles.section}>
              <Text style={styles.sectionTitle}>AGENTS USED</Text>

              <View style={styles.routeRow}>
                {routes.includes("otp") && (
                  <AgentBadge icon="key-outline" label="OTP" />
                )}

                {routes.includes("url") && (
                  <AgentBadge icon="link-outline" label="URL" />
                )}

                {routes.includes("content") && (
                  <AgentBadge icon="document-text-outline" label="CONTENT" />
                )}
              </View>
            </View>

            {/* ================================================
                AGENT RESULTS
            ================================================= */}

            <View style={styles.section}>
              <Text style={styles.sectionTitle}>AGENT RESULTS</Text>

              {/* OTP AGENT */}

              {routes.includes("otp") && agentResults.otp && (
                <AgentResultCard
                  icon="key-outline"
                  title="OTP Agent"
                  result={agentResults.otp}
                />
              )}

              {/* URL AGENT */}

              {routes.includes("url") && agentResults.url && (
                <AgentResultCard
                  icon="link-outline"
                  title="URL Agent"
                  result={agentResults.url}
                />
              )}

              {/* CONTENT AGENT */}

              {routes.includes("content") && agentResults.content && (
                <AgentResultCard
                  icon="document-text-outline"
                  title="Content Agent"
                  result={agentResults.content}
                />
              )}
            </View>

            {/* ================================================
                WHY FLAGGED
            ================================================= */}

            {reasons.length > 0 && (
              <View style={styles.section}>
                <Text style={styles.sectionTitle}>WHY THIS WAS FLAGGED</Text>

                {reasons.map((reason, index) => (
                  <View key={`${reason}-${index}`} style={styles.reasonRow}>
                    <Ionicons
                      name="alert-circle-outline"
                      size={17}
                      color={riskStyle.color}
                    />

                    <Text style={styles.reasonText}>{reason}</Text>
                  </View>
                ))}
              </View>
            )}

            {/* ================================================
                DETAILS
            ================================================= */}

            <Pressable
              onPress={() => setShowDetails((value) => !value)}
              style={styles.detailsToggle}
            >
              <Text style={styles.detailsToggleText}>
                {showDetails
                  ? "Hide technical details"
                  : "View technical details"}
              </Text>

              <Ionicons
                name={showDetails ? "chevron-up" : "chevron-down"}
                size={16}
                color={COLORS.teal}
              />
            </Pressable>

            {showDetails && (
              <View style={styles.detailsBox}>
                <DetailRow label="Routes" value={routes.join(", ") || "None"} />

                <DetailRow label="Risk status" value={riskStatus} />

                <DetailRow label="Risk score" value={`${riskScore}/100`} />

                {result?.sms?.sender && (
                  <DetailRow label="Sender" value={result.sms.sender} />
                )}

                {result?.sms?.body && (
                  <DetailRow label="Message" value={result.sms.body} />
                )}
              </View>
            )}
          </View>
        )}

        {/* ====================================================
            RESET
        ==================================================== */}

        {(result || error) && (
          <Pressable onPress={handleReset} style={styles.resetButton}>
            <Text style={styles.resetButtonText}>Scan another message</Text>
          </Pressable>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

// ============================================================
// AGENT BADGE
// ============================================================

function AgentBadge({ icon, label }) {
  return (
    <View style={styles.agentBadge}>
      <Ionicons name={icon} size={15} color={COLORS.darkIcon} />

      <Text style={styles.agentBadgeText}>{label}</Text>
    </View>
  );
}

// ============================================================
// AGENT RESULT CARD
// ============================================================

function AgentResultCard({ icon, title, result }) {
  const level = result?.level || result?.verdict || "UNKNOWN";

  const score =
    typeof result?.score === "number"
      ? result.score
      : typeof result?.trust?.score === "number"
        ? result.trust.score
        : null;

  return (
    <View style={styles.agentResultCard}>
      <View style={styles.agentResultHeader}>
        <View style={styles.agentResultIcon}>
          <Ionicons name={icon} size={18} color={COLORS.darkIcon} />
        </View>

        <View style={styles.agentResultTitleBox}>
          <Text style={styles.agentResultTitle}>{title}</Text>

          <Text style={styles.agentResultLevel}>{level}</Text>
        </View>

        {score !== null && <Text style={styles.agentScore}>{score}/100</Text>}
      </View>

      {result?.reasons && result.reasons.length > 0 && (
        <View style={styles.agentReasons}>
          {result.reasons.slice(0, 3).map((reason, index) => (
            <Text key={`${reason}-${index}`} style={styles.agentReasonText}>
              • {reason}
            </Text>
          ))}
        </View>
      )}
    </View>
  );
}

// ============================================================
// DETAIL ROW
// ============================================================

function DetailRow({ label, value }) {
  return (
    <View style={styles.detailRow}>
      <Text style={styles.detailLabel}>{label}</Text>

      <Text style={styles.detailValue}>{String(value)}</Text>
    </View>
  );
}

// ============================================================
// STYLES
// ============================================================

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.background,
  },

  scrollContent: {
    padding: 24,
    paddingBottom: 48,
  },

  // ========================================================
  // HEADER
  // ========================================================

  header: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 20,
  },

  title: {
    color: COLORS.white,
    fontSize: 20,
    fontWeight: "700",
  },

  subtitle: {
    color: COLORS.muted,
    fontSize: 14,
    lineHeight: 21,
    marginBottom: 16,
  },

  // ========================================================
  // INPUT
  // ========================================================

  input: {
    minHeight: 140,
    borderRadius: 20,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: "#16435A",
    padding: 16,
    color: COLORS.white,
    fontSize: 15,
    marginBottom: 16,
  },

  // ========================================================
  // SCAN BUTTON
  // ========================================================

  scanButton: {
    minHeight: 58,
    borderRadius: 29,
    backgroundColor: COLORS.cyan,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 10,
  },

  scanButtonDisabled: {
    opacity: 0.4,
  },

  scanButtonText: {
    color: COLORS.darkIcon,
    fontSize: 16,
    fontWeight: "700",
  },

  buttonPressed: {
    opacity: 0.8,
  },

  loadingHint: {
    color: COLORS.muted,
    fontSize: 12,
    lineHeight: 18,
    textAlign: "center",
    marginTop: 10,
  },

  // ========================================================
  // ERROR
  // ========================================================

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

  errorText: {
    color: "#FF9C9C",
    flex: 1,
    fontSize: 13,
    lineHeight: 19,
  },

  // ========================================================
  // RESULT CARD
  // ========================================================

  resultCard: {
    marginTop: 20,
    borderRadius: 24,
    backgroundColor: COLORS.surface,
    borderWidth: 1.5,
    padding: 20,
  },

  riskHeader: {
    flexDirection: "row",
    alignItems: "center",
    gap: 9,
  },

  statusDot: {
    width: 11,
    height: 11,
    borderRadius: 6,
  },

  resultLabel: {
    fontSize: 18,
    fontWeight: "800",
  },

  // ========================================================
  // SCORE
  // ========================================================

  scoreContainer: {
    flexDirection: "row",
    alignItems: "baseline",
    marginTop: 8,
  },

  scoreNumber: {
    color: COLORS.white,
    fontSize: 48,
    fontWeight: "800",
  },

  scoreTotal: {
    color: COLORS.muted,
    fontSize: 18,
    fontWeight: "600",
    marginLeft: 4,
  },

  scoreDescription: {
    color: COLORS.muted,
    fontSize: 12,
    lineHeight: 18,
    marginTop: 2,
  },

  // ========================================================
  // SECTIONS
  // ========================================================

  section: {
    marginTop: 22,
  },

  sectionTitle: {
    color: COLORS.teal,
    fontSize: 11,
    fontWeight: "800",
    letterSpacing: 1.2,
    marginBottom: 10,
  },

  // ========================================================
  // ROUTES
  // ========================================================

  routeRow: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },

  agentBadge: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    backgroundColor: COLORS.cyan,
    borderRadius: 16,
    paddingHorizontal: 11,
    paddingVertical: 7,
  },

  agentBadgeText: {
    color: COLORS.darkIcon,
    fontSize: 11,
    fontWeight: "800",
  },

  // ========================================================
  // AGENT RESULT
  // ========================================================

  agentResultCard: {
    backgroundColor: "#102C3A",
    borderRadius: 16,
    borderWidth: 1,
    borderColor: "#16435A",
    padding: 14,
    marginBottom: 10,
  },

  agentResultHeader: {
    flexDirection: "row",
    alignItems: "center",
  },

  agentResultIcon: {
    width: 36,
    height: 36,
    borderRadius: 12,
    backgroundColor: COLORS.cyan,
    alignItems: "center",
    justifyContent: "center",
  },

  agentResultTitleBox: {
    flex: 1,
    marginLeft: 10,
  },

  agentResultTitle: {
    color: COLORS.white,
    fontSize: 14,
    fontWeight: "700",
  },

  agentResultLevel: {
    color: COLORS.muted,
    fontSize: 11,
    marginTop: 2,
  },

  agentScore: {
    color: COLORS.white,
    fontSize: 15,
    fontWeight: "800",
  },

  agentReasons: {
    marginTop: 10,
    paddingTop: 10,
    borderTopWidth: 1,
    borderTopColor: "#16435A",
  },

  agentReasonText: {
    color: COLORS.muted,
    fontSize: 12,
    lineHeight: 18,
    marginBottom: 3,
  },

  // ========================================================
  // REASONS
  // ========================================================

  reasonRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    marginBottom: 8,
    gap: 8,
  },

  reasonText: {
    flex: 1,
    color: COLORS.white,
    fontSize: 13,
    lineHeight: 19,
  },

  // ========================================================
  // DETAILS
  // ========================================================

  detailsToggle: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 5,
    marginTop: 16,
    paddingVertical: 8,
  },

  detailsToggleText: {
    color: COLORS.teal,
    fontSize: 13,
    fontWeight: "600",
  },

  detailsBox: {
    marginTop: 8,
    borderTopWidth: 1,
    borderTopColor: "#16435A",
    paddingTop: 12,
    gap: 12,
  },

  detailRow: {
    gap: 3,
  },

  detailLabel: {
    color: COLORS.teal,
    fontSize: 10,
    fontWeight: "800",
    letterSpacing: 1,
    textTransform: "uppercase",
  },

  detailValue: {
    color: COLORS.muted,
    fontSize: 12,
    lineHeight: 18,
  },

  // ========================================================
  // RESET
  // ========================================================

  resetButton: {
    marginTop: 16,
    alignItems: "center",
    paddingVertical: 12,
  },

  resetButtonText: {
    color: COLORS.muted,
    fontSize: 14,
    fontWeight: "500",
  },
});

import React from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import { COLORS } from "../constants/colors";

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
    label: "NO ANALYSIS",
  },
};

// ============================================================
// SECURITY CENTER
// ============================================================

export default function SecurityCenter({
  onBack,
  onOtpAgent,
  onUrlAgent,
  onContactAgent,
  analysisResult,
}) {
  // ==========================================================
  // SUPPORT BOTH:
  //
  // 1. event.langgraph_result
  // 2. direct FastAPI response
  // ==========================================================

  const graphResponse =
    analysisResult?.langgraph_result || analysisResult || null;

  const analysis = graphResponse?.analysis || null;

  const status = analysis?.status || "unknown";

  const score = typeof analysis?.score === "number" ? analysis.score : null;

  const safeScore =
    typeof analysis?.safe_score === "number" ? analysis.safe_score : null;

  const confidenceScore =
    typeof analysis?.confidence_score === "number"
      ? analysis.confidence_score
      : null;

  const riskStyle = RISK_STYLES[status] || RISK_STYLES.unknown;

  const routes = graphResponse?.routes || [];

  const agentResults = analysis?.agent_results || {};

  const otpResult = agentResults?.otp || null;

  const urlResult = agentResults?.url || null;

  const contactResult = agentResults?.contact || null;

  // ==========================================================
  // ALL FINAL REASONS
  // ==========================================================

  const finalReasons = Array.isArray(analysis?.reasons) ? analysis.reasons : [];

  // ==========================================================
  // INDIVIDUAL AGENT REASONS
  // ==========================================================

  const getAgentReasons = (result) => {
    if (!result) {
      return [];
    }

    const reasons = [];

    if (Array.isArray(result.reasons)) {
      reasons.push(...result.reasons);
    }

    return [...new Set(reasons)];
  };

  const otpReasons = getAgentReasons(otpResult);

  const urlReasons = getAgentReasons(urlResult);

  const contactReasons = getAgentReasons(contactResult);

  // ==========================================================
  // FINAL REASONS
  //
  // Use LangGraph final reasons first.
  // If unavailable, collect all agent reasons.
  // ==========================================================

  const allReasons =
    finalReasons.length > 0
      ? [...new Set(finalReasons)]
      : [...new Set([...otpReasons, ...urlReasons, ...contactReasons])];

  // ==========================================================
  // AGENT ACTIVE STATE
  // ==========================================================

  const otpActive = routes.includes("otp") || otpResult !== null;

  const urlActive = routes.includes("url") || urlResult !== null;

  const contactActive = routes.includes("contact") || contactResult !== null;

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.securityContainer}
        showsVerticalScrollIndicator={false}
      >
        {/* ====================================================
            HEADER
        ==================================================== */}

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

        {/* ====================================================
            READY CARD
        ==================================================== */}

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
              ScamShield AI is monitoring your messages and checking them with
              multiple AI agents.
            </Text>
          </View>
        </View>

        {/* ====================================================
            AGENT CARDS
        ==================================================== */}

        <View style={styles.agentsGrid}>
          {/* OTP AGENT */}

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
              style={[
                styles.agentIconCircle,
                {
                  backgroundColor: COLORS.cyan,
                },
              ]}
            >
              <Ionicons name="key-outline" size={26} color={COLORS.darkIcon} />
            </View>

            <Text style={styles.agentCardTitle}>OTP Agent</Text>

            <Text style={styles.agentCardSubtitle}>
              Real-time OTP protection
            </Text>
          </Pressable>

          {/* URL AGENT */}

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
              style={[
                styles.agentIconCircle,
                {
                  backgroundColor: COLORS.teal,
                },
              ]}
            >
              <Ionicons name="link-outline" size={26} color={COLORS.darkIcon} />
            </View>

            <Text style={styles.agentCardTitle}>URL Agent</Text>

            <Text style={styles.agentCardSubtitle}>Link & spam detection</Text>
          </Pressable>

          {/* CONTACT AGENT */}

          <Pressable
            onPress={onContactAgent}
            accessibilityRole="button"
            accessibilityLabel="Open Contact Agent"
            style={({ pressed }) => [
              styles.agentCard,
              styles.contactCard,
              pressed && styles.buttonPressed,
            ]}
          >
            <View
              style={[
                styles.agentIconCircle,
                {
                  backgroundColor: COLORS.teal,
                },
              ]}
            >
              <Ionicons
                name="people-outline"
                size={26}
                color={COLORS.darkIcon}
              />
            </View>

            <Text style={styles.agentCardTitle}>Contact Agent</Text>

            <Text style={styles.agentCardSubtitle}>
              Sender & message checks
            </Text>
          </Pressable>
        </View>

        {/* ====================================================
            LATEST SMS ANALYSIS
        ==================================================== */}

        {analysis ? (
          <View
            style={[
              styles.analysisCard,
              {
                borderColor: riskStyle.color,
              },
            ]}
          >
            {/* ==================================================
                ANALYSIS HEADER
            ================================================== */}

            <View style={styles.analysisHeader}>
              <View>
                <Text style={styles.analysisEyebrow}>LATEST SMS ANALYSIS</Text>

                <Text style={styles.analysisTitle}>LangGraph Result</Text>
              </View>

              <View
                style={[
                  styles.riskBadge,
                  {
                    borderColor: riskStyle.color,
                  },
                ]}
              >
                <View
                  style={[
                    styles.riskDot,
                    {
                      backgroundColor: riskStyle.color,
                    },
                  ]}
                />

                <Text
                  style={[
                    styles.riskBadgeText,
                    {
                      color: riskStyle.color,
                    },
                  ]}
                >
                  {status}
                </Text>
              </View>
            </View>

            {/* ==================================================
                FINAL SCORE
            ================================================== */}

            <View style={styles.scoreRow}>
              <View>
                <Text style={styles.scoreLabel}>FINAL RISK SCORE</Text>

                <View style={styles.scoreNumberRow}>
                  <Text style={styles.scoreNumber}>
                    {score !== null ? score : "--"}
                  </Text>

                  <Text style={styles.scoreTotal}>/100</Text>
                </View>

                {/* SAFE + CONFIDENCE */}

                <View style={styles.scoreMetaRow}>
                  <View style={styles.scoreMetaBox}>
                    <Text style={styles.scoreMetaLabel}>SAFE</Text>

                    <Text style={styles.scoreMetaValue}>
                      {safeScore !== null ? `${safeScore}/100` : "--"}
                    </Text>
                  </View>

                  <View style={styles.scoreMetaBox}>
                    <Text style={styles.scoreMetaLabel}>CONFIDENCE</Text>

                    <Text style={styles.scoreMetaValue}>
                      {confidenceScore !== null ? `${confidenceScore}%` : "--"}
                    </Text>
                  </View>
                </View>
              </View>

              <View
                style={[
                  styles.shieldScoreIcon,
                  {
                    backgroundColor: riskStyle.color,
                  },
                ]}
              >
                <Ionicons
                  name="shield-checkmark-outline"
                  size={27}
                  color="#08151C"
                />
              </View>
            </View>

            {/* ==================================================
                AGENTS USED
            ================================================== */}

            <View style={styles.analysisSection}>
              <Text style={styles.sectionTitle}>AGENTS USED</Text>

              <View style={styles.agentStatusList}>
                {/* OTP */}

                <AgentStatusRow
                  icon="key-outline"
                  title="OTP Agent"
                  active={otpActive}
                  result={otpResult}
                />

                {/* URL */}

                <AgentStatusRow
                  icon="link-outline"
                  title="URL Agent"
                  active={urlActive}
                  result={urlResult}
                />

                {/* CONTACT */}

                <AgentStatusRow
                  icon="people-outline"
                  title="Contact Agent"
                  active={contactActive}
                  result={contactResult}
                />
              </View>
            </View>

            {/* ==================================================
                OVERALL REASONS
            ================================================== */}

            {allReasons.length > 0 && (
              <View style={styles.analysisSection}>
                <Text style={styles.sectionTitle}>WHY THIS WAS FLAGGED</Text>

                {allReasons.map((reason, index) => (
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

            {/* ==================================================
                AGENT-SPECIFIC ANALYSIS
            ================================================== */}

            {(otpReasons.length > 0 ||
              urlReasons.length > 0 ||
              contactReasons.length > 0) && (
              <View style={styles.analysisSection}>
                <Text style={styles.sectionTitle}>AGENT ANALYSIS</Text>

                {/* OTP ANALYSIS */}

                {otpReasons.length > 0 && (
                  <AgentReasonBlock
                    title="OTP Agent"
                    icon="key-outline"
                    reasons={otpReasons}
                  />
                )}

                {/* URL ANALYSIS */}

                {urlReasons.length > 0 && (
                  <AgentReasonBlock
                    title="URL Agent"
                    icon="link-outline"
                    reasons={urlReasons}
                  />
                )}

                {/* CONTACT ANALYSIS */}

                {contactReasons.length > 0 && (
                  <AgentReasonBlock
                    title="Contact Agent"
                    icon="people-outline"
                    reasons={contactReasons}
                  />
                )}
              </View>
            )}

            {/* ==================================================
                AGENT EXPLANATIONS
            ================================================== */}

            <AgentExplanation
              title="OTP Agent"
              result={otpResult}
              active={otpActive}
            />

            <AgentExplanation
              title="URL Agent"
              result={urlResult}
              active={urlActive}
            />

            <AgentExplanation
              title="Contact Agent"
              result={contactResult}
              active={contactActive}
            />

            {/* ==================================================
                SMS INFORMATION
            ================================================== */}

            {graphResponse?.sms && (
              <View style={styles.smsBox}>
                <Text style={styles.sectionTitle}>ANALYZED MESSAGE</Text>

                <Text style={styles.senderText}>
                  {graphResponse.sms.sender}
                </Text>

                <Text style={styles.smsText} numberOfLines={6}>
                  {graphResponse.sms.body}
                </Text>
              </View>
            )}
          </View>
        ) : (
          /* ==================================================
             NO ANALYSIS
          ================================================== */

          <View style={styles.noAnalysisCard}>
            <View style={styles.noAnalysisIcon}>
              <Ionicons name="scan-outline" size={26} color={COLORS.darkIcon} />
            </View>

            <View style={styles.noAnalysisText}>
              <Text style={styles.noAnalysisTitle}>No SMS analyzed yet</Text>

              <Text style={styles.noAnalysisDescription}>
                Wait for an incoming SMS to see the LangGraph AI analysis and
                final risk score here.
              </Text>
            </View>
          </View>
        )}

        {/* ====================================================
            BACK
        ==================================================== */}

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
      </ScrollView>
    </SafeAreaView>
  );
}

// ============================================================
// AGENT STATUS ROW
// ============================================================

function AgentStatusRow({ icon, title, active, result }) {
  const score =
    typeof result?.score === "number"
      ? result.score
      : typeof result?.trust?.score === "number"
        ? result.trust.score
        : null;

  const level = result?.level || result?.verdict || "Analyzed";

  return (
    <View style={styles.agentStatusRow}>
      <View
        style={[
          styles.agentStatusIcon,
          {
            opacity: active ? 1 : 0.35,
          },
        ]}
      >
        <Ionicons name={icon} size={18} color={COLORS.darkIcon} />
      </View>

      <View style={styles.agentStatusInfo}>
        <Text style={[styles.agentStatusTitle, !active && styles.inactiveText]}>
          {title}
        </Text>

        <Text style={styles.agentStatusSubtitle}>
          {active ? level : "Not used"}
        </Text>
      </View>

      {active && score !== null && (
        <Text style={styles.agentStatusScore}>{score}/100</Text>
      )}
    </View>
  );
}

// ============================================================
// AGENT REASON BLOCK
// ============================================================

function AgentReasonBlock({ title, icon, reasons }) {
  return (
    <View style={styles.agentReasonBlock}>
      <View style={styles.agentReasonHeader}>
        <Ionicons name={icon} size={17} color={COLORS.teal} />

        <Text style={styles.agentReasonTitle}>{title}</Text>
      </View>

      {reasons.map((reason, index) => (
        <View key={`${title}-${reason}-${index}`} style={styles.agentReasonRow}>
          <View style={styles.reasonBullet} />

          <Text style={styles.agentReasonText}>{reason}</Text>
        </View>
      ))}
    </View>
  );
}

// ============================================================
// AGENT SHORT EXPLANATION
// ============================================================

function AgentExplanation({ title, result, active }) {
  if (!active || !result) {
    return null;
  }

  const explanation =
    result?.short_explanation ||
    result?.llm_reason ||
    result?.explanation ||
    null;

  if (!explanation) {
    return null;
  }

  return (
    <View style={styles.explanationBox}>
      <Text style={styles.explanationTitle}>{title} Analysis</Text>

      <Text style={styles.explanationText}>{explanation}</Text>
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

  scrollView: {
    flex: 1,
  },

  securityContainer: {
    paddingHorizontal: 28,
    paddingBottom: 40,
  },

  // ========================================================
  // HEADER
  // ========================================================

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

  protectedText: {
    color: COLORS.white,
    fontSize: 12,
    fontWeight: "600",
  },

  // ========================================================
  // READY CARD
  // ========================================================

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

  readyTextContainer: {
    flex: 1,
    paddingLeft: 16,
  },

  readyTitle: {
    color: COLORS.white,
    fontSize: 21,
    fontWeight: "700",
    marginBottom: 8,
  },

  readyDescription: {
    color: COLORS.muted,
    fontSize: 14,
    lineHeight: 21,
  },

  // ========================================================
  // AGENTS
  // ========================================================

  agentsGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 14,
    marginTop: 18,
  },

  agentCard: {
    width: "47%",
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

  contactCard: {
    width: "100%",
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

  // ========================================================
  // ANALYSIS CARD
  // ========================================================

  analysisCard: {
    marginTop: 22,
    borderRadius: 28,
    backgroundColor: COLORS.surface,
    borderWidth: 1.5,
    padding: 20,
  },

  analysisHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },

  analysisEyebrow: {
    color: COLORS.teal,
    fontSize: 10,
    fontWeight: "800",
    letterSpacing: 1.4,
    marginBottom: 5,
  },

  analysisTitle: {
    color: COLORS.white,
    fontSize: 19,
    fontWeight: "700",
  },

  riskBadge: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    borderWidth: 1,
    borderRadius: 18,
    paddingHorizontal: 10,
    paddingVertical: 7,
  },

  riskDot: {
    width: 7,
    height: 7,
    borderRadius: 4,
  },

  riskBadgeText: {
    fontSize: 10,
    fontWeight: "800",
  },

  // ========================================================
  // SCORE
  // ========================================================

  scoreRow: {
    marginTop: 22,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
  },

  scoreLabel: {
    color: COLORS.muted,
    fontSize: 10,
    fontWeight: "700",
    letterSpacing: 1,
    marginBottom: 3,
  },

  scoreNumberRow: {
    flexDirection: "row",
    alignItems: "baseline",
  },

  scoreNumber: {
    color: COLORS.white,
    fontSize: 46,
    fontWeight: "800",
  },

  scoreTotal: {
    color: COLORS.muted,
    fontSize: 17,
    fontWeight: "600",
    marginLeft: 3,
  },

  scoreMetaRow: {
    flexDirection: "row",
    marginTop: 12,
    gap: 10,
  },

  scoreMetaBox: {
    backgroundColor: "#102C3A",
    borderRadius: 12,
    paddingHorizontal: 10,
    paddingVertical: 7,
    minWidth: 85,
  },

  scoreMetaLabel: {
    color: COLORS.muted,
    fontSize: 8,
    fontWeight: "700",
    letterSpacing: 1,
  },

  scoreMetaValue: {
    color: COLORS.white,
    fontSize: 12,
    fontWeight: "800",
    marginTop: 2,
  },

  shieldScoreIcon: {
    width: 58,
    height: 58,
    borderRadius: 20,
    alignItems: "center",
    justifyContent: "center",
  },

  // ========================================================
  // ANALYSIS SECTIONS
  // ========================================================

  analysisSection: {
    marginTop: 22,
  },

  sectionTitle: {
    color: COLORS.teal,
    fontSize: 10,
    fontWeight: "800",
    letterSpacing: 1.2,
    marginBottom: 10,
  },

  // ========================================================
  // AGENT STATUS
  // ========================================================

  agentStatusList: {
    gap: 9,
  },

  agentStatusRow: {
    minHeight: 58,
    borderRadius: 16,
    backgroundColor: "#102C3A",
    borderWidth: 1,
    borderColor: "#16435A",
    paddingHorizontal: 12,
    flexDirection: "row",
    alignItems: "center",
  },

  agentStatusIcon: {
    width: 36,
    height: 36,
    borderRadius: 12,
    backgroundColor: COLORS.cyan,
    alignItems: "center",
    justifyContent: "center",
  },

  agentStatusInfo: {
    flex: 1,
    marginLeft: 10,
  },

  agentStatusTitle: {
    color: COLORS.white,
    fontSize: 13,
    fontWeight: "700",
  },

  agentStatusSubtitle: {
    color: COLORS.muted,
    fontSize: 10,
    marginTop: 2,
  },

  inactiveText: {
    opacity: 0.5,
  },

  agentStatusScore: {
    color: COLORS.white,
    fontSize: 14,
    fontWeight: "800",
  },

  // ========================================================
  // REASONS
  // ========================================================

  reasonRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    gap: 8,
    marginBottom: 9,
  },

  reasonText: {
    flex: 1,
    color: COLORS.white,
    fontSize: 12,
    lineHeight: 18,
  },

  // ========================================================
  // AGENT REASONS
  // ========================================================

  agentReasonBlock: {
    backgroundColor: "#102C3A",
    borderWidth: 1,
    borderColor: "#16435A",
    borderRadius: 16,
    padding: 12,
    marginBottom: 10,
  },

  agentReasonHeader: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: 8,
  },

  agentReasonTitle: {
    color: COLORS.white,
    fontSize: 12,
    fontWeight: "800",
    marginLeft: 7,
  },

  agentReasonRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    marginTop: 5,
  },

  reasonBullet: {
    width: 5,
    height: 5,
    borderRadius: 3,
    backgroundColor: COLORS.teal,
    marginTop: 6,
    marginRight: 8,
  },

  agentReasonText: {
    flex: 1,
    color: COLORS.muted,
    fontSize: 11,
    lineHeight: 17,
  },

  // ========================================================
  // AGENT EXPLANATION
  // ========================================================

  explanationBox: {
    backgroundColor: "#102C3A",
    borderWidth: 1,
    borderColor: "#16435A",
    borderRadius: 16,
    padding: 13,
    marginTop: 10,
  },

  explanationTitle: {
    color: COLORS.teal,
    fontSize: 11,
    fontWeight: "800",
    marginBottom: 6,
  },

  explanationText: {
    color: COLORS.muted,
    fontSize: 11,
    lineHeight: 17,
  },

  // ========================================================
  // SMS
  // ========================================================

  smsBox: {
    marginTop: 20,
    paddingTop: 16,
    borderTopWidth: 1,
    borderTopColor: "#16435A",
  },

  senderText: {
    color: COLORS.white,
    fontSize: 12,
    fontWeight: "700",
    marginBottom: 6,
  },

  smsText: {
    color: COLORS.muted,
    fontSize: 12,
    lineHeight: 18,
  },

  // ========================================================
  // NO ANALYSIS
  // ========================================================

  noAnalysisCard: {
    marginTop: 22,
    borderRadius: 24,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: "#16435A",
    padding: 20,
    flexDirection: "row",
    alignItems: "center",
  },

  noAnalysisIcon: {
    width: 54,
    height: 54,
    borderRadius: 18,
    backgroundColor: COLORS.cyan,
    alignItems: "center",
    justifyContent: "center",
  },

  noAnalysisText: {
    flex: 1,
    marginLeft: 14,
  },

  noAnalysisTitle: {
    color: COLORS.white,
    fontSize: 15,
    fontWeight: "700",
    marginBottom: 5,
  },

  noAnalysisDescription: {
    color: COLORS.muted,
    fontSize: 12,
    lineHeight: 18,
  },

  // ========================================================
  // BACK
  // ========================================================

  backButton: {
    minHeight: 58,
    alignItems: "center",
    justifyContent: "center",
    marginTop: 16,
  },

  backButtonText: {
    color: COLORS.muted,
    fontSize: 14,
    fontWeight: "500",
  },

  buttonPressed: {
    opacity: 0.75,
    transform: [
      {
        scale: 0.985,
      },
    ],
  },

  skipPressed: {
    opacity: 0.6,
  },
});

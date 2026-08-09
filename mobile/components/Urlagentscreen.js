import React, { useState, useEffect, useCallback } from "react";
import {
  ActivityIndicator,
  NativeModules,
  Pressable,
  RefreshControl,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { SafeAreaView } from "react-native-safe-area-context";
import SmsAndroid from "react-native-get-sms-android";
import { COLORS } from "../constants/colors";
import { API_BASE_URL } from "../constants/api";

const { SmsNativeModule } = NativeModules;

// Same category set the backend's URL agent returns, mirrored from
// ScanScreen so verdicts look consistent everywhere in the app.
const STATUS_STYLES = {
  phishing: { color: "#FF5C5C", label: "Likely a scam" },
  spam: { color: "#F5C542", label: "Spam / risky" },
  legitimate: { color: "#3DDC97", label: "Looks safe" },
  unknown: { color: COLORS.muted, label: "Unable to determine" },
};

function getStatus(category) {
  return STATUS_STYLES[category] || STATUS_STYLES.unknown;
}

async function analyzeMessage(sender, body) {
  const response = await fetch(`${API_BASE_URL}/analyze-url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sender: sender || "unknown", body }),
  });

  if (!response.ok) {
    const errBody = await response.json().catch(() => ({}));
    throw new Error(errBody.detail || `Server error (${response.status})`);
  }

  return response.json();
}

export default function UrlAgentScreen({ onBack, onManualScan }) {
  // Last 3 inbox messages, each independently analyzed.
  const [recent, setRecent] = useState([]);
  const [loadingRecent, setLoadingRecent] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Live incoming-message verdict, polled from the native event store
  // that SmsReceiver.kt writes to on every new SMS.
  const [liveEvent, setLiveEvent] = useState(null);
  const [isConnected, setIsConnected] = useState(false);

  const loadRecentMessages = useCallback(() => {
    setLoadingRecent(true);

    SmsAndroid.list(
      JSON.stringify({ box: "inbox", maxCount: 3 }),
      (fail) => {
        console.log("URL Agent: SMS read failed:", fail);
        setLoadingRecent(false);
        setRefreshing(false);
      },
      (count, smsList) => {
        const messages = JSON.parse(smsList).slice(0, 3);

        const initial = messages.map((m) => ({
          sender: m.address,
          body: m.body,
          timestamp: m.date,
          result: null,
          error: null,
          loading: true,
        }));

        setRecent(initial);
        setLoadingRecent(false);
        setRefreshing(false);

        // Fire all three analyses in parallel; each updates its own slot
        // so a slow or failed lookup doesn't hold up the other two.
        initial.forEach((item, index) => {
          analyzeMessage(item.sender, item.body)
            .then((result) => {
              setRecent((prev) => {
                const next = [...prev];
                if (next[index]) {
                  next[index] = { ...next[index], result, loading: false };
                }
                return next;
              });
            })
            .catch((e) => {
              setRecent((prev) => {
                const next = [...prev];
                if (next[index]) {
                  next[index] = {
                    ...next[index],
                    error: e.message || "Analysis failed",
                    loading: false,
                  };
                }
                return next;
              });
            });
        });
      },
    );
  }, []);

  const loadLiveEvent = useCallback(async () => {
    try {
      if (!SmsNativeModule) {
        setIsConnected(false);
        return;
      }

      const raw = await SmsNativeModule.getLatestSmsEvent();
      setIsConnected(true);

      if (!raw) return;

      const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
      setLiveEvent(parsed);
    } catch (e) {
      setIsConnected(false);
    }
  }, []);

  useEffect(() => {
    loadRecentMessages();
  }, [loadRecentMessages]);

  useEffect(() => {
    loadLiveEvent();
    const interval = setInterval(loadLiveEvent, 2000);
    return () => clearInterval(interval);
  }, [loadLiveEvent]);

  function handleRefresh() {
    setRefreshing(true);
    loadRecentMessages();
  }

  // url_analysis is the field SmsReceiver.kt adds alongside the existing
  // OTP "analysis" field on the same stored event.
  const liveResult =
    liveEvent?.url_analysis && Object.keys(liveEvent.url_analysis).length
      ? liveEvent.url_analysis
      : null;
  const liveStatus = getStatus(liveResult?.category);

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
      <ScrollView
        contentContainerStyle={styles.scrollContent}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={handleRefresh}
            tintColor={COLORS.cyan}
          />
        }
      >
        <View style={styles.header}>
          <Pressable onPress={onBack} hitSlop={12}>
            <Ionicons name="arrow-back" size={24} color={COLORS.white} />
          </Pressable>
          <Text style={styles.title}>URL Agent</Text>
          <View style={{ width: 24 }} />
        </View>

        <Text style={styles.subtitle}>
          Checks links and message content for phishing or spam, on your
          recent messages and as new ones arrive.
        </Text>

        {/* LIVE MONITORING */}
        <View style={styles.sectionRow}>
          <Text style={styles.sectionTitle}>Real-time monitoring</Text>
          <View
            style={[
              styles.liveBadge,
              { backgroundColor: isConnected ? "#0E3029" : "#30291B" },
            ]}
          >
            <View
              style={[
                styles.liveDot,
                { backgroundColor: isConnected ? COLORS.teal : "#FFB020" },
              ]}
            />
            <Text
              style={[
                styles.liveText,
                { color: isConnected ? COLORS.teal : "#FFB020" },
              ]}
            >
              {isConnected ? "LIVE" : "WAITING"}
            </Text>
          </View>
        </View>

        <View
          style={[
            styles.card,
            { borderColor: liveResult ? liveStatus.color : "#16435A" },
          ]}
        >
          {liveResult ? (
            <>
              <View style={styles.resultHeader}>
                <View
                  style={[styles.statusDot, { backgroundColor: liveStatus.color }]}
                />
                <Text style={[styles.resultLabel, { color: liveStatus.color }]}>
                  {liveStatus.label}
                </Text>
                {liveResult.confidence && (
                  <Text style={styles.confidenceText}>
                    {liveResult.confidence} confidence
                  </Text>
                )}
              </View>
              <Text style={styles.senderText}>
                {liveEvent?.sender || "Unknown sender"}
              </Text>
              <Text style={styles.bodyText} numberOfLines={2}>
                {liveEvent?.body}
              </Text>
              <Text style={styles.explanationText}>
                {liveResult.short_explanation}
              </Text>
            </>
          ) : (
            <Text style={styles.emptyText}>
              No incoming message analyzed yet. New SMS will appear here
              automatically.
            </Text>
          )}
        </View>

        {/* RECENT MESSAGES */}
        <Text style={styles.sectionTitle}>Last 3 messages</Text>

        {loadingRecent ? (
          <ActivityIndicator color={COLORS.cyan} style={styles.spinner} />
        ) : recent.length === 0 ? (
          <View style={styles.card}>
            <Text style={styles.emptyText}>
              No messages found on this device.
            </Text>
          </View>
        ) : (
          recent.map((item, index) => {
            const status = getStatus(item.result?.category);
            return (
              <View
                key={`${item.sender}-${item.timestamp}-${index}`}
                style={[
                  styles.card,
                  { borderColor: item.result ? status.color : "#16435A" },
                ]}
              >
                <Text style={styles.senderText}>
                  {item.sender || "Unknown sender"}
                </Text>
                <Text style={styles.bodyText} numberOfLines={2}>
                  {item.body}
                </Text>

                {item.loading && (
                  <View style={styles.inlineLoading}>
                    <ActivityIndicator size="small" color={COLORS.cyan} />
                    <Text style={styles.inlineLoadingText}>Analyzing...</Text>
                  </View>
                )}

                {item.error && (
                  <Text style={styles.errorText}>{item.error}</Text>
                )}

                {item.result && (
                  <>
                    <View style={styles.resultHeader}>
                      <View
                        style={[
                          styles.statusDot,
                          { backgroundColor: status.color },
                        ]}
                      />
                      <Text style={[styles.resultLabel, { color: status.color }]}>
                        {status.label}
                      </Text>
                      {item.result.confidence && (
                        <Text style={styles.confidenceText}>
                          {item.result.confidence} confidence
                        </Text>
                      )}
                    </View>

                    {item.result.brand_impersonated && (
                      <Text style={styles.brandText}>
                        Claims to be from: {item.result.brand_impersonated}
                      </Text>
                    )}

                    <Text style={styles.explanationText}>
                      {item.result.short_explanation}
                    </Text>
                  </>
                )}
              </View>
            );
          })
        )}

        <Pressable
          onPress={onManualScan}
          style={({ pressed }) => [
            styles.scanButton,
            pressed && styles.buttonPressed,
          ]}
        >
          <Ionicons name="search-outline" size={20} color={COLORS.darkIcon} />
          <Text style={styles.scanButtonText}>Scan a specific message</Text>
        </Pressable>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: COLORS.background },
  scrollContent: { padding: 24, paddingBottom: 48 },
  header: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 12,
  },
  title: { color: COLORS.white, fontSize: 20, fontWeight: "700" },
  subtitle: { color: COLORS.muted, fontSize: 13, lineHeight: 19, marginBottom: 20 },

  sectionRow: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 10,
  },
  sectionTitle: {
    color: COLORS.white,
    fontSize: 15,
    fontWeight: "700",
    marginTop: 18,
    marginBottom: 10,
  },

  liveBadge: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 16,
  },
  liveDot: { width: 6, height: 6, borderRadius: 4, marginRight: 6 },
  liveText: { fontSize: 10, fontWeight: "900" },

  card: {
    borderRadius: 18,
    backgroundColor: COLORS.surface,
    borderWidth: 1.5,
    padding: 16,
    marginBottom: 12,
  },
  emptyText: { color: COLORS.muted, fontSize: 13, lineHeight: 19 },

  senderText: { color: COLORS.white, fontSize: 14, fontWeight: "700" },
  bodyText: { color: COLORS.muted, fontSize: 12, marginTop: 4, marginBottom: 10 },

  spinner: { marginVertical: 12 },
  inlineLoading: { flexDirection: "row", alignItems: "center", gap: 8 },
  inlineLoadingText: { color: COLORS.muted, fontSize: 12 },
  errorText: { color: "#FF9C9C", fontSize: 12 },

  resultHeader: { flexDirection: "row", alignItems: "center", gap: 8, marginBottom: 6 },
  statusDot: { width: 8, height: 8, borderRadius: 4 },
  resultLabel: { fontSize: 14, fontWeight: "700", flex: 1 },
  confidenceText: { color: COLORS.muted, fontSize: 11 },
  brandText: { color: COLORS.muted, fontSize: 12, marginBottom: 6 },
  explanationText: { color: COLORS.white, fontSize: 13, lineHeight: 19 },

  scanButton: {
    minHeight: 58,
    borderRadius: 29,
    backgroundColor: COLORS.cyan,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 10,
    marginTop: 8,
  },
  scanButtonText: { color: COLORS.darkIcon, fontSize: 15, fontWeight: "700" },
  buttonPressed: { opacity: 0.8 },
});
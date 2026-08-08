import React, { useEffect, useState, useCallback } from "react";
import {
  NativeModules,
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
  RefreshControl,
} from "react-native";
import { LinearGradient } from "expo-linear-gradient";
import { Ionicons } from "@expo/vector-icons";

const { SmsNativeModule } = NativeModules;

/* =========================================================
   DEFAULT STATE
========================================================= */

const EMPTY_EVENT = {
  sender: "",
  body: "",
  timestamp: null,
  foreground_app: "",
  expected_otp: false,
  screen_unlocked: true,

  analysis: {
    level: "WAITING",
    score: 0,
    confidence: 0,
    otp_code: null,

    reasons: [],

    signals: {
      otp_detected: false,
      otp_code_detected: false,

      expected_otp: false,
      foreground_app: "",
      relevant_foreground_app: false,
      screen_unlocked: true,

      possible_unrequested: false,
      sharing_request: false,
      third_party_request: false,

      plain_mobile_sender: false,
      has_url: false,
      urgency: false,
      threat: false,
      repeated_otp: false,
    },
  },
};

/* =========================================================
   NORMALIZE EVENT
========================================================= */

function normalizeEvent(data) {
  if (!data) {
    return EMPTY_EVENT;
  }

  return {
    ...EMPTY_EVENT,

    ...data,

    analysis: {
      ...EMPTY_EVENT.analysis,

      ...(data.analysis || {}),

      signals: {
        ...EMPTY_EVENT.analysis.signals,

        ...(data.analysis?.signals || {}),
      },
    },
  };
}

/* =========================================================
   MAIN SCREEN
========================================================= */

export default function OtpMonitoringScreen({ onBack }) {
  const [event, setEvent] = useState(EMPTY_EVENT);
  const [isConnected, setIsConnected] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastChecked, setLastChecked] = useState(null);

  /* =======================================================
     LOAD SMS FROM KOTLIN
  ======================================================= */

  const loadLatestSms = useCallback(async () => {
    try {
      console.log("================================");
      console.log("OTP UI: Checking native module");

      if (!SmsNativeModule) {
        console.error(
          "OTP UI: SmsNativeModule is undefined"
        );

        setIsConnected(false);
        return;
      }

      console.log(
        "OTP UI: SmsNativeModule available"
      );

      const result =
        await SmsNativeModule.getLatestSmsEvent();

      console.log(
        "OTP UI: Native result:",
        result
      );

      setIsConnected(true);

      if (!result) {
        console.log(
          "OTP UI: No SMS event stored yet"
        );

        return;
      }

      let parsed;

      try {
        parsed =
          typeof result === "string"
            ? JSON.parse(result)
            : result;
      } catch (jsonError) {
        console.error(
          "OTP UI: JSON parsing failed:",
          jsonError
        );

        return;
      }

      console.log(
        "OTP UI: Parsed event:",
        parsed
      );

      const normalized =
        normalizeEvent(parsed);

      console.log(
        "OTP UI: Verdict:",
        normalized.analysis.level
      );

      console.log(
        "OTP UI: Score:",
        normalized.analysis.score
      );

      console.log(
        "OTP UI: Confidence:",
        normalized.analysis.confidence
      );

      setEvent(normalized);
      setLastChecked(new Date());

    } catch (error) {
      console.error(
        "OTP UI: Failed to load SMS:",
        error
      );

      setIsConnected(false);

    } finally {
      setRefreshing(false);
    }
  }, []);

  /* =======================================================
     START REAL-TIME POLLING
  ======================================================= */

  useEffect(() => {
    loadLatestSms();

    const interval =
      setInterval(() => {
        loadLatestSms();
      }, 1000);

    return () => {
      clearInterval(interval);
    };
  }, [loadLatestSms]);

  /* =======================================================
     MANUAL REFRESH
  ======================================================= */

  const handleRefresh = () => {
    setRefreshing(true);
    loadLatestSms();
  };

  /* =======================================================
     DATA
  ======================================================= */

  const analysis =
    event.analysis || EMPTY_EVENT.analysis;

  const signals =
    analysis.signals ||
    EMPTY_EVENT.analysis.signals;

  const level =
    String(
      analysis.level || "WAITING"
    ).toUpperCase();

  const score =
    Number(analysis.score || 0);

  const confidence =
    Number(
      analysis.confidence || 0
    );

  /* =======================================================
     COLORS
  ======================================================= */

  const getLevelColor = () => {
    if (level === "DANGER") {
      return "#FF3B5C";
    }

    if (level === "CAUTION") {
      return "#FFB020";
    }

    if (level === "SAFE") {
      return "#31D6A3";
    }

    return "#7C8CA5";
  };

  const levelColor =
    getLevelColor();

  /* =======================================================
     ICON
  ======================================================= */

  const getLevelIcon = () => {
    if (level === "DANGER") {
      return "warning";
    }

    if (level === "CAUTION") {
      return "alert-circle";
    }

    if (level === "SAFE") {
      return "shield-checkmark";
    }

    return "hourglass-outline";
  };

  /* =======================================================
     SIGNAL COLOR
  ======================================================= */

  const getSignalColor = (
    value
  ) => {
    return value
      ? "#FF3B5C"
      : "#31D6A3";
  };

  /* =======================================================
     TIME
  ======================================================= */

  const formatTime = (
    timestamp
  ) => {
    if (!timestamp) {
      return "--";
    }

    try {
      return new Date(
        Number(timestamp)
      ).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    } catch {
      return "--";
    }
  };

  /* =======================================================
     SIGNAL ROWS
  ======================================================= */

  const signalRows = [
    {
      label: "Unrequested OTP",
      value:
        !!signals.possible_unrequested,
      icon: "person-remove-outline",
    },

    {
      label: "OTP sharing request",
      value:
        !!signals.sharing_request,
      icon: "share-social-outline",
    },

    {
      label: "Customer-care request",
      value:
        !!signals.third_party_request,
      icon: "call-outline",
    },

    {
      label: "Sender mismatch",
      value:
        !!signals.plain_mobile_sender,
      icon: "phone-portrait-outline",
    },

    {
      label: "Suspicious URL",
      value:
        !!signals.has_url,
      icon: "link-outline",
    },

    {
      label: "Urgency / pressure",
      value:
        !!signals.urgency,
      icon: "time-outline",
    },

    {
      label: "Account threat",
      value:
        !!signals.threat,
      icon: "warning-outline",
    },

    {
      label: "Repeated OTP",
      value:
        !!signals.repeated_otp,
      icon: "repeat-outline",
    },
  ];

  /* =======================================================
     RENDER
  ======================================================= */

  return (
    <View style={styles.container}>

      <LinearGradient
        colors={[
          "#071A2D",
          "#061425",
          "#050B17",
        ]}
        style={StyleSheet.absoluteFill}
      />

      {/* ===================================================
          HEADER
      =================================================== */}

      <View style={styles.header}>

        <TouchableOpacity
          style={styles.backButton}
          onPress={onBack}
        >
          <Ionicons
            name="arrow-back"
            size={24}
            color="#FFFFFF"
          />
        </TouchableOpacity>

        <View style={styles.headerText}>

          <Text style={styles.headerTitle}>
            OTP Monitoring
          </Text>

          <Text style={styles.headerSubtitle}>
            Real-time protection
          </Text>

        </View>

        <View
          style={[
            styles.liveBadge,
            {
              backgroundColor:
                isConnected
                  ? "#0E3029"
                  : "#30291B",
            },
          ]}
        >

          <View
            style={[
              styles.liveDot,
              {
                backgroundColor:
                  isConnected
                    ? "#31D6A3"
                    : "#FFB020",
              },
            ]}
          />

          <Text
            style={[
              styles.liveText,
              {
                color:
                  isConnected
                    ? "#31D6A3"
                    : "#FFB020",
              },
            ]}
          >
            {isConnected
              ? "LIVE"
              : "WAITING"}
          </Text>

        </View>

      </View>

      {/* ===================================================
          CONTENT
      =================================================== */}

      <ScrollView
        showsVerticalScrollIndicator={false}
        contentContainerStyle={
          styles.scrollContent
        }
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={handleRefresh}
            tintColor="#31D6A3"
          />
        }
      >

        {/* =================================================
            AGENT STATUS
        ================================================= */}

        <View style={styles.monitorCard}>

          <View
            style={styles.monitorIcon}
          >
            <Ionicons
              name="shield-checkmark"
              size={28}
              color="#31D6A3"
            />
          </View>

          <View
            style={styles.monitorInfo}
          >

            <Text
              style={styles.monitorTitle}
            >
              OTP Agent Active
            </Text>

            <Text
              style={
                styles.monitorDescription
              }
            >
              Incoming SMS messages are
              being analyzed in real time.
            </Text>

          </View>

          <View
            style={styles.activeBadge}
          >
            <Text
              style={styles.activeText}
            >
              ACTIVE
            </Text>
          </View>

        </View>

        {/* =================================================
            VERDICT
        ================================================= */}

        <View
          style={[
            styles.verdictCard,
            {
              borderColor:
                levelColor + "70",
            },
          ]}
        >

          <View
            style={[
              styles.verdictIcon,
              {
                backgroundColor:
                  levelColor + "18",
              },
            ]}
          >
            <Ionicons
              name={getLevelIcon()}
              size={40}
              color={levelColor}
            />
          </View>

          <Text
            style={styles.verdictLabel}
          >
            CURRENT VERDICT
          </Text>

          <Text
            style={[
              styles.verdictLevel,
              {
                color: levelColor,
              },
            ]}
          >
            {level}
          </Text>

          <View
            style={styles.scoreRow}
          >

            <View
              style={styles.scoreItem}
            >

              <Text
                style={styles.scoreValue}
              >
                {score}
              </Text>

              <Text
                style={styles.scoreLabel}
              >
                RISK SCORE
              </Text>

            </View>

            <View
              style={styles.verticalDivider}
            />

            <View
              style={styles.scoreItem}
            >

              <Text
                style={styles.scoreValue}
              >
                {confidence}%
              </Text>

              <Text
                style={styles.scoreLabel}
              >
                CONFIDENCE
              </Text>

            </View>

          </View>

        </View>

        {/* =================================================
            LATEST SMS
        ================================================= */}

        <Text
          style={styles.sectionTitle}
        >
          Latest SMS
        </Text>

        <View style={styles.smsCard}>

          <View
            style={styles.smsHeader}
          >

            <View
              style={styles.smsIcon}
            >
              <Ionicons
                name="chatbubble-ellipses"
                size={21}
                color="#6EA8FF"
              />
            </View>

            <View
              style={styles.senderInfo}
            >

              <Text
                style={styles.sender}
              >
                {event.sender ||
                  "Waiting for SMS"}
              </Text>

              <Text
                style={styles.time}
              >
                {formatTime(
                  event.timestamp
                )}
              </Text>

            </View>

          </View>

          <View
            style={styles.messageBox}
          >

            <Text
              style={styles.message}
            >
              {event.body ||
                "Waiting for an incoming SMS..."}
            </Text>

          </View>

        </View>

        {/* =================================================
            OTP
        ================================================= */}

        {analysis.otp_code && (

          <>
            <Text
              style={styles.sectionTitle}
            >
              OTP Information
            </Text>

            <View
              style={styles.otpCard}
            >

              <View>

                <Text
                  style={styles.otpLabel}
                >
                  DETECTED OTP
                </Text>

                <Text
                  style={styles.otpCode}
                >
                  {analysis.otp_code}
                </Text>

              </View>

              <View
                style={styles.detectedBadge}
              >

                <Ionicons
                  name="checkmark-circle"
                  size={16}
                  color="#31D6A3"
                />

                <Text
                  style={styles.detectedText}
                >
                  DETECTED
                </Text>

              </View>

            </View>

          </>
        )}

        {/* =================================================
            CONTEXT
        ================================================= */}

        <Text
          style={styles.sectionTitle}
        >
          OTP Context
        </Text>

        <View
          style={styles.contextCard}
        >

          <ContextRow
            icon="phone-portrait-outline"
            label="Foreground App"
            value={
              signals.foreground_app ||
              event.foreground_app ||
              "None detected"
            }
          />

          <View
            style={styles.rowDivider}
          />

          <ContextRow
            icon="checkmark-circle-outline"
            label="Expected OTP"
            value={
              signals.expected_otp
                ? "Yes — likely requested"
                : "No — not confirmed"
            }
            valueColor={
              signals.expected_otp
                ? "#31D6A3"
                : "#FFB020"
            }
          />

          <View
            style={styles.rowDivider}
          />

          <ContextRow
            icon="lock-open-outline"
            label="Screen"
            value={
              signals.screen_unlocked
                ? "Unlocked"
                : "Locked"
            }
          />

        </View>

        {/* =================================================
            SIGNALS
        ================================================= */}

        <Text
          style={styles.sectionTitle}
        >
          OTP Detection Signals
        </Text>

        <View
          style={styles.signalsCard}
        >

          {signalRows.map(
            (signal, index) => {

              const color =
                getSignalColor(
                  signal.value
                );

              return (

                <View
                  key={signal.label}
                  style={[
                    styles.signalRow,

                    index !==
                      signalRows.length - 1 &&
                      styles.signalBorder,
                  ]}
                >

                  <View
                    style={[
                      styles.signalIcon,
                      {
                        backgroundColor:
                          color + "18",
                      },
                    ]}
                  >

                    <Ionicons
                      name={signal.icon}
                      size={19}
                      color={color}
                    />

                  </View>

                  <Text
                    style={styles.signalLabel}
                  >
                    {signal.label}
                  </Text>

                  <Text
                    style={[
                      styles.signalStatus,
                      {
                        color,
                      },
                    ]}
                  >
                    {signal.value
                      ? "DETECTED"
                      : "CLEAR"}
                  </Text>

                </View>

              );
            }
          )}

        </View>

        {/* =================================================
            REASONS
        ================================================= */}

        {analysis.reasons?.length >
          0 && (

          <>
            <Text
              style={styles.sectionTitle}
            >
              Why this verdict?
            </Text>

            <View
              style={styles.reasonsCard}
            >

              {analysis.reasons.map(
                (reason, index) => (

                  <View
                    key={`${reason}-${index}`}
                    style={styles.reasonRow}
                  >

                    <Ionicons
                      name="warning"
                      size={17}
                      color="#FFB020"
                    />

                    <Text
                      style={styles.reasonText}
                    >
                      {reason}
                    </Text>

                  </View>

                )
              )}

            </View>

          </>
        )}

        {/* =================================================
            AGENT
        ================================================= */}

        <View
          style={styles.agentCard}
        >

          <View
            style={styles.agentIcon}
          >
            <Ionicons
              name="hardware-chip-outline"
              size={23}
              color="#8C7BFF"
            />
          </View>

          <View
            style={styles.agentInfo}
          >

            <Text
              style={styles.agentTitle}
            >
              OTP Agent
            </Text>

            <Text
              style={styles.agentDescription}
            >
              NLP-based contextual analysis
            </Text>

          </View>

          <View
            style={styles.onlineBadge}
          >

            <View
              style={styles.onlineDot}
            />

            <Text
              style={styles.onlineText}
            >
              ONLINE
            </Text>

          </View>

        </View>

        <Text
          style={styles.lastChecked}
        >
          Last checked:{" "}
          {lastChecked
            ? lastChecked.toLocaleTimeString()
            : "--"}
        </Text>

        <View
          style={styles.bottomSpace}
        />

      </ScrollView>

    </View>
  );
}

/* =========================================================
   CONTEXT ROW
========================================================= */

function ContextRow({
  icon,
  label,
  value,
  valueColor,
}) {
  return (
    <View style={styles.contextRow}>

      <View
        style={styles.contextIcon}
      >
        <Ionicons
          name={icon}
          size={19}
          color="#7FA8FF"
        />
      </View>

      <Text
        style={styles.contextLabel}
      >
        {label}
      </Text>

      <Text
        style={[
          styles.contextValue,
          valueColor && {
            color: valueColor,
          },
        ]}
        numberOfLines={1}
      >
        {value}
      </Text>

    </View>
  );
}

/* =========================================================
   STYLES
========================================================= */

const styles = StyleSheet.create({

  container: {
    flex: 1,
    backgroundColor: "#050B17",
  },

  scrollContent: {
    paddingHorizontal: 20,
    paddingBottom: 40,
  },

  /* HEADER */

  header: {
    height: 82,
    paddingHorizontal: 20,
    flexDirection: "row",
    alignItems: "center",
    borderBottomWidth: 1,
    borderBottomColor: "#17253B",
  },

  backButton: {
    width: 42,
    height: 42,
    borderRadius: 13,
    backgroundColor: "#101D32",
    justifyContent: "center",
    alignItems: "center",
    marginRight: 13,
  },

  headerText: {
    flex: 1,
  },

  headerTitle: {
    color: "#FFFFFF",
    fontSize: 21,
    fontWeight: "800",
  },

  headerSubtitle: {
    color: "#71819A",
    fontSize: 12,
    marginTop: 2,
  },

  liveBadge: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 11,
    paddingVertical: 7,
    borderRadius: 20,
  },

  liveDot: {
    width: 7,
    height: 7,
    borderRadius: 5,
    marginRight: 6,
  },

  liveText: {
    fontSize: 10,
    fontWeight: "900",
  },

  /* MONITOR */

  monitorCard: {
    marginTop: 20,
    padding: 16,
    borderRadius: 18,
    backgroundColor: "#0D1A2D",
    borderWidth: 1,
    borderColor: "#1B314C",
    flexDirection: "row",
    alignItems: "center",
  },

  monitorIcon: {
    width: 50,
    height: 50,
    borderRadius: 15,
    backgroundColor: "#0C2C29",
    justifyContent: "center",
    alignItems: "center",
    marginRight: 13,
  },

  monitorInfo: {
    flex: 1,
  },

  monitorTitle: {
    color: "#FFFFFF",
    fontSize: 16,
    fontWeight: "800",
  },

  monitorDescription: {
    color: "#71819A",
    fontSize: 11,
    lineHeight: 16,
    marginTop: 3,
  },

  activeBadge: {
    backgroundColor: "#10342D",
    paddingHorizontal: 9,
    paddingVertical: 6,
    borderRadius: 8,
  },

  activeText: {
    color: "#31D6A3",
    fontSize: 9,
    fontWeight: "900",
  },

  /* VERDICT */

  verdictCard: {
    marginTop: 16,
    borderRadius: 23,
    backgroundColor: "#0B1728",
    borderWidth: 1,
    padding: 23,
    alignItems: "center",
  },

  verdictIcon: {
    width: 76,
    height: 76,
    borderRadius: 38,
    justifyContent: "center",
    alignItems: "center",
  },

  verdictLabel: {
    color: "#64758F",
    fontSize: 10,
    fontWeight: "900",
    letterSpacing: 1.6,
    marginTop: 15,
  },

  verdictLevel: {
    fontSize: 31,
    fontWeight: "900",
    marginTop: 3,
  },

  scoreRow: {
    flexDirection: "row",
    width: "100%",
    marginTop: 20,
    paddingTop: 17,
    borderTopWidth: 1,
    borderTopColor: "#1A2A40",
  },

  scoreItem: {
    flex: 1,
    alignItems: "center",
  },

  scoreValue: {
    color: "#FFFFFF",
    fontSize: 23,
    fontWeight: "900",
  },

  scoreLabel: {
    color: "#65758C",
    fontSize: 9,
    fontWeight: "800",
    marginTop: 4,
  },

  verticalDivider: {
    width: 1,
    backgroundColor: "#1A2A40",
  },

  /* SECTIONS */

  sectionTitle: {
    color: "#DDE7F5",
    fontSize: 16,
    fontWeight: "800",
    marginTop: 24,
    marginBottom: 10,
  },

  /* SMS */

  smsCard: {
    backgroundColor: "#0D192B",
    borderRadius: 18,
    borderWidth: 1,
    borderColor: "#1A2B43",
    padding: 15,
  },

  smsHeader: {
    flexDirection: "row",
    alignItems: "center",
  },

  smsIcon: {
    width: 42,
    height: 42,
    borderRadius: 12,
    backgroundColor: "#102342",
    justifyContent: "center",
    alignItems: "center",
    marginRight: 11,
  },

  senderInfo: {
    flex: 1,
  },

  sender: {
    color: "#FFFFFF",
    fontSize: 15,
    fontWeight: "800",
  },

  time: {
    color: "#65758D",
    fontSize: 10,
    marginTop: 3,
  },

  messageBox: {
    backgroundColor: "#081322",
    marginTop: 12,
    padding: 14,
    borderRadius: 13,
  },

  message: {
    color: "#B7C4D5",
    fontSize: 13,
    lineHeight: 20,
  },

  /* OTP */

  otpCard: {
    backgroundColor: "#0D192B",
    borderRadius: 18,
    borderWidth: 1,
    borderColor: "#1A2B43",
    padding: 17,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
  },

  otpLabel: {
    color: "#687A93",
    fontSize: 9,
    fontWeight: "900",
    letterSpacing: 1,
  },

  otpCode: {
    color: "#FFFFFF",
    fontSize: 27,
    fontWeight: "900",
    letterSpacing: 5,
    marginTop: 5,
  },

  detectedBadge: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#0C2B27",
    paddingHorizontal: 9,
    paddingVertical: 7,
    borderRadius: 9,
  },

  detectedText: {
    color: "#31D6A3",
    fontSize: 9,
    fontWeight: "900",
    marginLeft: 4,
  },

  /* CONTEXT */

  contextCard: {
    backgroundColor: "#0D192B",
    borderRadius: 18,
    borderWidth: 1,
    borderColor: "#1A2B43",
    paddingHorizontal: 15,
  },

  contextRow: {
    minHeight: 57,
    flexDirection: "row",
    alignItems: "center",
  },

  contextIcon: {
    width: 35,
    height: 35,
    borderRadius: 10,
    backgroundColor: "#10213A",
    justifyContent: "center",
    alignItems: "center",
    marginRight: 10,
  },

  contextLabel: {
    color: "#8393A9",
    fontSize: 12,
    flex: 1,
  },

  contextValue: {
    color: "#D8E2EF",
    fontSize: 11,
    maxWidth: 170,
  },

  rowDivider: {
    height: 1,
    backgroundColor: "#17263A",
  },

  /* SIGNALS */

  signalsCard: {
    backgroundColor: "#0D192B",
    borderRadius: 18,
    borderWidth: 1,
    borderColor: "#1A2B43",
    paddingHorizontal: 15,
  },

  signalRow: {
    minHeight: 58,
    flexDirection: "row",
    alignItems: "center",
  },

  signalBorder: {
    borderBottomWidth: 1,
    borderBottomColor: "#17263A",
  },

  signalIcon: {
    width: 36,
    height: 36,
    borderRadius: 10,
    justifyContent: "center",
    alignItems: "center",
    marginRight: 11,
  },

  signalLabel: {
    flex: 1,
    color: "#B8C5D5",
    fontSize: 12,
  },

  signalStatus: {
    fontSize: 9,
    fontWeight: "900",
  },

  /* REASONS */

  reasonsCard: {
    backgroundColor: "#0D192B",
    borderRadius: 18,
    borderWidth: 1,
    borderColor: "#332C1A",
    padding: 15,
  },

  reasonRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    marginBottom: 12,
  },

  reasonText: {
    flex: 1,
    color: "#B7C2D0",
    fontSize: 12,
    lineHeight: 18,
    marginLeft: 9,
  },

  /* AGENT */

  agentCard: {
    marginTop: 22,
    padding: 15,
    backgroundColor: "#0B1627",
    borderRadius: 17,
    borderWidth: 1,
    borderColor: "#1B2A40",
    flexDirection: "row",
    alignItems: "center",
  },

  agentIcon: {
    width: 43,
    height: 43,
    borderRadius: 12,
    backgroundColor: "#191635",
    justifyContent: "center",
    alignItems: "center",
    marginRight: 11,
  },

  agentInfo: {
    flex: 1,
  },

  agentTitle: {
    color: "#FFFFFF",
    fontSize: 14,
    fontWeight: "800",
  },

  agentDescription: {
    color: "#65768E",
    fontSize: 10,
    marginTop: 3,
  },

  onlineBadge: {
    flexDirection: "row",
    alignItems: "center",
  },

  onlineDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: "#31D6A3",
    marginRight: 5,
  },

  onlineText: {
    color: "#31D6A3",
    fontSize: 8,
    fontWeight: "900",
  },

  lastChecked: {
    color: "#4F6077",
    textAlign: "center",
    fontSize: 9,
    marginTop: 15,
  },

  bottomSpace: {
    height: 30,
  },
});
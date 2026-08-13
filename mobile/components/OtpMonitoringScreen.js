import React, {
  useEffect,
  useState,
  useCallback,
} from "react";

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

  // URL Agent / Groq explanation
  url_analysis: {
    short_explanation: "",
    explanation: "",
  },

  analysis: {
    level: "WAITING",

    score: 0,

    confidence: 0,

    otp_code: null,

    short_explanation: "",

    explanation: "",

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

    url_analysis: {
      ...EMPTY_EVENT.url_analysis,

      ...(data.url_analysis || {}),
    },

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
   MASK OTP FOR UI
========================================================= */

function maskOtpInMessage(body, otpCode) {

  if (!body) {
    return "";
  }

  if (!otpCode) {
    return body;
  }

  return body.replace(
    otpCode,
    "[OTP]"
  );
}


/* =========================================================
   GROQ AI EXPLANATION
========================================================= */

/*
 * The explanation can come from:
 *
 * 1. OTP Agent:
 *      analysis.short_explanation
 *
 * 2. URL Agent:
 *      url_analysis.short_explanation
 *
 * 3. Generic explanation field.
 *
 * The frontend only displays the explanation.
 * The risk engine remains responsible for the final verdict.
 */

function getGroqExplanation(
  event,
  analysis
) {

  if (
    analysis?.short_explanation &&
    String(
      analysis.short_explanation
    ).trim()
  ) {

    return String(
      analysis.short_explanation
    ).trim();
  }


  if (
    event?.url_analysis?.short_explanation &&
    String(
      event.url_analysis.short_explanation
    ).trim()
  ) {

    return String(
      event.url_analysis.short_explanation
    ).trim();
  }


  if (
    analysis?.explanation &&
    String(
      analysis.explanation
    ).trim()
  ) {

    return String(
      analysis.explanation
    ).trim();
  }


  if (
    event?.url_analysis?.explanation &&
    String(
      event.url_analysis.explanation
    ).trim()
  ) {

    return String(
      event.url_analysis.explanation
    ).trim();
  }


  return (
    "The AI security analysis is still being prepared."
  );
}


/* =========================================================
   MAIN SCREEN
========================================================= */

export default function OtpMonitoringScreen({
  onBack,
}) {

  const [
    event,
    setEvent,
  ] = useState(
    EMPTY_EVENT
  );

  const [
    isConnected,
    setIsConnected,
  ] = useState(false);

  const [
    refreshing,
    setRefreshing,
  ] = useState(false);

  const [
    lastChecked,
    setLastChecked,
  ] = useState(null);


  /* =======================================================
     LOAD SMS FROM KOTLIN
  ======================================================= */

  const loadLatestSms =
    useCallback(async () => {

      try {

        console.log(
          "================================"
        );

        console.log(
          "OTP UI: Checking native module"
        );


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
          await SmsNativeModule
            .getLatestSmsEvent();


        console.log(
          "OTP UI: Native result:",
          result
        );


        setIsConnected(true);


        if (!result) {

          console.log(
            "OTP UI: No SMS event stored yet"
          );

          setLastChecked(
            new Date()
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

        setLastChecked(
          new Date()
        );


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
     START MONITORING
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
    event.analysis ||
    EMPTY_EVENT.analysis;


  const signals =
    analysis.signals ||
    EMPTY_EVENT.analysis.signals;


  const level =
    String(
      analysis.level ||
      "WAITING"
    ).toUpperCase();


  const score =
    Number(
      analysis.score || 0
    );


  const confidence =
    Number(
      analysis.confidence || 0
    );


  // Groq-generated explanation
  const groqExplanation =
    getGroqExplanation(
      event,
      analysis
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

    return "shield-outline";
  };


  /* =======================================================
     USER-FRIENDLY VERDICT
  ======================================================= */

  const getVerdictTitle = () => {

    switch (level) {

      case "DANGER":
        return "Don't share your OTP.";

      case "CAUTION":
        return "Be careful with this message.";

      case "SAFE":
        return "This OTP appears safe.";

      default:
        return "You're protected.";
    }
  };


  const getVerdictDescription = () => {

    switch (level) {

      case "DANGER":
        return (
          "This message shows signs of an OTP scam. "
          + "Do not share your verification code."
        );

      case "CAUTION":
        return (
          "Some signals suggest you should "
          + "verify this message before taking action."
        );

      case "SAFE":
        return (
          "No suspicious OTP behavior was detected "
          + "in this message."
        );

      default:
        return (
          "Your phone is ready to monitor "
          + "incoming SMS messages."
        );
    }
  };


  /* =======================================================
     USER ACTION
  ======================================================= */

  const getActionTitle = () => {

    switch (level) {

      case "DANGER":
        return "What should you do?";

      case "CAUTION":
        return "Stay cautious";

      case "SAFE":
        return "Good to know";

      default:
        return "Your protection";
    }
  };


  const getActionText = () => {

    switch (level) {

      case "DANGER":
        return [
          "Do not share the OTP with anyone.",
          "Never provide an OTP to customer-care representatives.",
          "Contact your bank through its official app or website.",
        ];

      case "CAUTION":
        return [
          "Don't share the OTP until you confirm the request.",
          "Check whether you actually initiated the transaction.",
        ];

      case "SAFE":
        return [
          "Never share an OTP with another person.",
          "Only enter it in the official app or website.",
        ];

      default:
        return [
          "Incoming OTP messages will be checked automatically.",
        ];
    }
  };


  /* =======================================================
     RISK PERCENTAGE
  ======================================================= */

  const riskPercentage =
    Math.min(
      Math.round(
        (score / 20) * 100
      ),
      100
    );


  /* =======================================================
     DETECTED SIGNALS
  ======================================================= */

  const signalRows = [

    {
      label:
        "Someone may be asking for your OTP",

      value:
        !!signals.sharing_request,

      icon:
        "share-social-outline",
    },

    {
      label:
        "OTP may not have been requested",

      value:
        !!signals.possible_unrequested,

      icon:
        "person-remove-outline",
    },

    {
      label:
        "Customer-care or third-party request",

      value:
        !!signals.third_party_request,

      icon:
        "call-outline",
    },

    {
      label:
        "Message came from a plain mobile number",

      value:
        !!signals.plain_mobile_sender,

      icon:
        "phone-portrait-outline",
    },

    {
      label:
        "Message contains a link",

      value:
        !!signals.has_url,

      icon:
        "link-outline",
    },

    {
      label:
        "Urgent or pressuring language",

      value:
        !!signals.urgency,

      icon:
        "time-outline",
    },

    {
      label:
        "Account threat detected",

      value:
        !!signals.threat,

      icon:
        "warning-outline",
    },

    {
      label:
        "Repeated OTP activity",

      value:
        !!signals.repeated_otp,

      icon:
        "repeat-outline",
    },

  ];


  const detectedSignals =
    signalRows.filter(
      (signal) =>
        signal.value
    );


  /* =======================================================
     MASKED SMS
  ======================================================= */

  const displayedMessage =
    maskOtpInMessage(
      event.body,
      analysis.otp_code
    );


  /* =======================================================
     RENDER
  ======================================================= */

  return (

    <View
      style={styles.container}
    >

      <LinearGradient
        colors={[
          "#071A2D",
          "#061425",
          "#050B17",
        ]}
        style={
          StyleSheet.absoluteFill
        }
      />


      {/* =================================================
          HEADER
      ================================================= */}

      <View
        style={styles.header}
      >

        <TouchableOpacity
          style={styles.backButton}
          onPress={onBack}
        >

          <Ionicons
            name="arrow-back"
            size={23}
            color="#FFFFFF"
          />

        </TouchableOpacity>


        <View
          style={styles.headerText}
        >

          <Text
            style={styles.headerTitle}
          >
            OTP Protection
          </Text>


          <Text
            style={styles.headerSubtitle}
          >
            Automatic SMS security
          </Text>

        </View>


        <View
          style={[
            styles.monitorBadge,

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
              styles.monitorText,

              {
                color:
                  isConnected
                    ? "#31D6A3"
                    : "#FFB020",
              },
            ]}
          >

            {isConnected
              ? "MONITORING"
              : "WAITING"}

          </Text>

        </View>

      </View>


      {/* =================================================
          CONTENT
      ================================================= */}

      <ScrollView

        showsVerticalScrollIndicator={
          false
        }

        contentContainerStyle={
          styles.scrollContent
        }

        refreshControl={

          <RefreshControl

            refreshing={
              refreshing
            }

            onRefresh={
              handleRefresh
            }

            tintColor="#31D6A3"

          />

        }

      >


        {/* =================================================
            MONITORING STATUS
        ================================================= */}

        <View
          style={styles.monitorCard}
        >

          <View
            style={styles.monitorIcon}
          >

            <Ionicons
              name="shield-checkmark"
              size={27}
              color="#31D6A3"
            />

          </View>


          <View
            style={styles.monitorInfo}
          >

            <Text
              style={styles.monitorTitle}
            >
              Protection is active
            </Text>


            <Text
              style={
                styles.monitorDescription
              }
            >
              Incoming SMS messages are
              checked automatically.
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
                levelColor + "65",
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
              name={
                getLevelIcon()
              }
              size={39}
              color={
                levelColor
              }
            />

          </View>


          <Text
            style={styles.verdictLabel}
          >
            SECURITY STATUS
          </Text>


          <Text
            style={[
              styles.verdictLevel,

              {
                color:
                  levelColor,
              },
            ]}
          >
            {level}
          </Text>


          <Text
            style={styles.verdictTitle}
          >
            {getVerdictTitle()}
          </Text>


          <Text
            style={
              styles.verdictDescription
            }
          >
            {getVerdictDescription()}
          </Text>


          {/* RISK BAR */}

          {level !== "WAITING" && (

            <View
              style={styles.riskContainer}
            >

              <View
                style={styles.riskBarHeader}
              >

                <Text
                  style={styles.riskLabel}
                >
                  Risk level
                </Text>


                <Text
                  style={[
                    styles.riskPercentage,

                    {
                      color:
                        levelColor,
                    },
                  ]}
                >
                  {riskPercentage}%
                </Text>

              </View>


              <View
                style={
                  styles.riskBarBackground
                }
              >

                <View
                  style={[
                    styles.riskBarFill,

                    {
                      width:
                        `${riskPercentage}%`,

                      backgroundColor:
                        levelColor,
                    },
                  ]}
                />

              </View>

            </View>

          )}


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
            ACTION CARD
        ================================================= */}

        <Text
          style={styles.sectionTitle}
        >
          {getActionTitle()}
        </Text>


        <View
          style={[
            styles.actionCard,

            {
              borderColor:
                levelColor + "35",
            },
          ]}
        >

          {getActionText().map(
            (text, index) => (

              <View
                key={`${text}-${index}`}
                style={styles.actionRow}
              >

                <View
                  style={[
                    styles.actionIcon,

                    {
                      backgroundColor:
                        levelColor + "15",
                    },
                  ]}
                >

                  <Ionicons
                    name={
                      level === "DANGER"
                        ? "close"
                        : "checkmark"
                    }
                    size={16}
                    color={
                      levelColor
                    }
                  />

                </View>


                <Text
                  style={
                    styles.actionText
                  }
                >
                  {text}
                </Text>

              </View>

            )
          )}

        </View>


        {/* =================================================
            WHY FLAGGED
        ================================================= */}

        <Text
          style={styles.sectionTitle}
        >
          Why was this flagged?
        </Text>


        <View
          style={styles.reasonsCard}
        >

          {detectedSignals.length ===
          0 ? (

            <View
              style={styles.clearRow}
            >

              <View
                style={styles.clearIcon}
              >

                <Ionicons
                  name="checkmark"
                  size={17}
                  color="#31D6A3"
                />

              </View>


              <Text
                style={
                  styles.clearText
                }
              >
                No suspicious OTP behavior
                was detected.
              </Text>

            </View>

          ) : (

            detectedSignals.map(
              (signal) => (

                <View
                  key={signal.label}
                  style={styles.reasonRow}
                >

                  <View
                    style={styles.reasonIcon}
                  >

                    <Ionicons
                      name={
                        signal.icon
                      }
                      size={17}
                      color="#FFB020"
                    />

                  </View>


                  <Text
                    style={
                      styles.reasonText
                    }
                  >
                    {signal.label}
                  </Text>

                </View>

              )
            )

          )}

        </View>


        {/* =================================================
            LATEST SMS
        ================================================= */}

        <Text
          style={styles.sectionTitle}
        >
          Latest message
        </Text>


        <View
          style={styles.smsCard}
        >

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
              {displayedMessage ||
                "Your next SMS will appear here."}
            </Text>

          </View>

        </View>


        {/* =================================================
            GROQ AI EXPLANATION
        ================================================= */}

        <Text
          style={styles.sectionTitle}
        >
          Why was this message flagged?
        </Text>


        <View
          style={[
            styles.aiExplanationCard,

            {
              borderColor:
                levelColor + "45",
            },
          ]}
        >

          {/* AI HEADER */}

          <View
            style={styles.aiExplanationHeader}
          >

            <View
              style={[
                styles.aiExplanationIcon,

                {
                  backgroundColor:
                    levelColor + "18",
                },
              ]}
            >

              <Ionicons
                name="sparkles"
                size={21}
                color={levelColor}
              />

            </View>


            <View
              style={
                styles.aiExplanationHeaderText
              }
            >

              <Text
                style={
                  styles.aiExplanationTitle
                }
              >
                AI Security Analysis
              </Text>


              <Text
                style={
                  styles.aiExplanationSubtitle
                }
              >
                Explanation generated by Groq
              </Text>

            </View>

          </View>


          {/* AI EXPLANATION */}

          <View
            style={
              styles.aiExplanationBody
            }
          >

            <Text
              style={
                styles.aiExplanationText
              }
            >
              {groqExplanation}
            </Text>

          </View>

        </View>


        {/* =================================================
            OTP PRIVACY
        ================================================= */}

        {signals.otp_detected && (

          <View
            style={styles.privacyCard}
          >

            <View
              style={styles.privacyIcon}
            >

              <Ionicons
                name="lock-closed"
                size={20}
                color="#31D6A3"
              />

            </View>


            <View
              style={styles.privacyInfo}
            >

              <Text
                style={styles.privacyTitle}
              >
                OTP privacy protected
              </Text>


              <Text
                style={styles.privacyText}
              >
                Your actual verification code
                stays on your device.
              </Text>

            </View>

          </View>

        )}


        {/* =================================================
            CONTEXT
        ================================================= */}

        <Text
          style={styles.sectionTitle}
        >
          Message context
        </Text>


        <View
          style={styles.contextCard}
        >

          <ContextRow
            icon="phone-portrait-outline"
            label="Recently active app"
            value={
              formatAppName(
                signals.foreground_app ||
                event.foreground_app
              )
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
                ? "Likely requested"
                : "Not confirmed"
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
            TECHNICAL DETAILS
        ================================================= */}

        <Text
          style={styles.sectionTitle}
        >
          Detection details
        </Text>


        <View
          style={styles.signalsCard}
        >

          {signalRows.map(
            (signal, index) => {

              const color =
                signal.value
                  ? "#FFB020"
                  : "#31D6A3";


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
                          color + "15",
                      },
                    ]}
                  >

                    <Ionicons
                      name={
                        signal.icon
                      }
                      size={18}
                      color={color}
                    />

                  </View>


                  <Text
                    style={
                      styles.signalLabel
                    }
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
            PRIVACY FOOTER
        ================================================= */}

        <View
          style={styles.privacyFooter}
        >

          <Ionicons
            name="shield-checkmark-outline"
            size={18}
            color="#31D6A3"
          />


          <Text
            style={
              styles.privacyFooterText
            }
          >
            Your OTP is processed locally
            before AI analysis.
          </Text>

        </View>


        {/* =================================================
            LAST CHECKED
        ================================================= */}

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

    <View
      style={styles.contextRow}
    >

      <View
        style={styles.contextIcon}
      >

        <Ionicons
          name={icon}
          size={18}
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
            color:
              valueColor,
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
   APP NAME FORMATTER
========================================================= */

function formatAppName(
  packageName
) {

  if (!packageName) {
    return "Not detected";
  }


  /*
   * Avoid displaying raw package names
   * such as:
   *
   * com.naush12.mobile
   *
   * in the normal user interface.
   */

  if (
    packageName.includes(".")
  ) {

    const parts =
      packageName.split(".");

    const lastPart =
      parts[parts.length - 1];

    if (
      lastPart &&
      lastPart.length > 2
    ) {

      return capitalize(
        lastPart
      );
    }
  }


  return packageName;
}


/* =========================================================
   CAPITALIZE
========================================================= */

function capitalize(
  text
) {

  if (!text) {
    return "";
  }

  return (
    text.charAt(0).toUpperCase() +
    text.slice(1)
  );
}


/* =========================================================
   FORMAT TIME
========================================================= */

function formatTime(
  timestamp
) {

  if (!timestamp) {
    return "--";
  }


  try {

    return new Date(
      Number(timestamp)
    ).toLocaleTimeString(
      [],
      {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }
    );

  } catch {

    return "--";
  }
}


/* =========================================================
   STYLES
========================================================= */

const styles =
  StyleSheet.create({

    container: {
      flex: 1,
      backgroundColor: "#050B17",
    },


    scrollContent: {
      paddingHorizontal: 20,
      paddingBottom: 40,
    },


    /* =====================================================
       HEADER
    ===================================================== */

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

      fontSize: 11,

      marginTop: 3,
    },


    monitorBadge: {
      flexDirection: "row",

      alignItems: "center",

      paddingHorizontal: 10,

      paddingVertical: 7,

      borderRadius: 20,
    },


    liveDot: {
      width: 7,

      height: 7,

      borderRadius: 5,

      marginRight: 6,
    },


    monitorText: {
      fontSize: 8,

      fontWeight: "900",

      letterSpacing: 0.4,
    },


    /* =====================================================
       MONITOR CARD
    ===================================================== */

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

      fontSize: 15,

      fontWeight: "800",
    },


    monitorDescription: {
      color: "#71819A",

      fontSize: 10.5,

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

      fontSize: 8,

      fontWeight: "900",

      letterSpacing: 0.5,
    },


    /* =====================================================
       VERDICT
    ===================================================== */

    verdictCard: {
      marginTop: 16,

      borderRadius: 23,

      backgroundColor: "#0B1728",

      borderWidth: 1,

      padding: 23,

      alignItems: "center",
    },


    verdictIcon: {
      width: 74,

      height: 74,

      borderRadius: 37,

      justifyContent: "center",

      alignItems: "center",
    },


    verdictLabel: {
      color: "#64758F",

      fontSize: 9,

      fontWeight: "900",

      letterSpacing: 1.5,

      marginTop: 14,
    },


    verdictLevel: {
      fontSize: 30,

      fontWeight: "900",

      marginTop: 2,
    },


    verdictTitle: {
      color: "#FFFFFF",

      fontSize: 16,

      fontWeight: "800",

      textAlign: "center",

      marginTop: 7,
    },


    verdictDescription: {
      color: "#8796AA",

      fontSize: 11,

      lineHeight: 17,

      textAlign: "center",

      maxWidth: 310,

      marginTop: 7,
    },


    riskContainer: {
      width: "100%",

      marginTop: 20,
    },


    riskBarHeader: {
      flexDirection: "row",

      justifyContent: "space-between",

      marginBottom: 7,
    },


    riskLabel: {
      color: "#718198",

      fontSize: 10,

      fontWeight: "700",
    },


    riskPercentage: {
      fontSize: 10,

      fontWeight: "900",
    },


    riskBarBackground: {
      height: 7,

      backgroundColor: "#18283D",

      borderRadius: 10,

      overflow: "hidden",

      width: "100%",
    },


    riskBarFill: {
      height: "100%",

      borderRadius: 10,
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

      fontSize: 21,

      fontWeight: "900",
    },


    scoreLabel: {
      color: "#65758C",

      fontSize: 8,

      fontWeight: "800",

      marginTop: 4,

      letterSpacing: 0.4,
    },


    verticalDivider: {
      width: 1,

      backgroundColor: "#1A2A40",
    },


    /* =====================================================
       SECTION
    ===================================================== */

    sectionTitle: {
      color: "#DDE7F5",

      fontSize: 15,

      fontWeight: "800",

      marginTop: 24,

      marginBottom: 10,
    },


    /* =====================================================
       ACTION CARD
    ===================================================== */

    actionCard: {
      backgroundColor: "#0D192B",

      borderRadius: 18,

      borderWidth: 1,

      padding: 15,
    },


    actionRow: {
      flexDirection: "row",

      alignItems: "flex-start",

      marginBottom: 12,
    },


    actionRowLast: {
      marginBottom: 0,
    },


    actionIcon: {
      width: 30,

      height: 30,

      borderRadius: 9,

      justifyContent: "center",

      alignItems: "center",

      marginRight: 10,
    },


    actionText: {
      flex: 1,

      color: "#B9C6D6",

      fontSize: 12,

      lineHeight: 18,

      paddingTop: 5,
    },


    /* =====================================================
       WHY FLAGGED
    ===================================================== */

    reasonsCard: {
      backgroundColor: "#0D192B",

      borderRadius: 18,

      borderWidth: 1,

      borderColor: "#293042",

      padding: 15,
    },


    reasonRow: {
      flexDirection: "row",

      alignItems: "center",

      marginBottom: 12,
    },


    reasonIcon: {
      width: 34,

      height: 34,

      borderRadius: 10,

      backgroundColor: "#2B2517",

      justifyContent: "center",

      alignItems: "center",

      marginRight: 10,
    },


    reasonText: {
      flex: 1,

      color: "#B8C4D3",

      fontSize: 12,

      lineHeight: 18,
    },


    clearRow: {
      flexDirection: "row",

      alignItems: "center",
    },


    clearIcon: {
      width: 34,

      height: 34,

      borderRadius: 10,

      backgroundColor: "#0C2B27",

      justifyContent: "center",

      alignItems: "center",

      marginRight: 10,
    },


    clearText: {
      flex: 1,

      color: "#AFC1B9",

      fontSize: 12,

      lineHeight: 18,
    },


    /* =====================================================
       SMS
    ===================================================== */

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


    /* =====================================================
       GROQ AI EXPLANATION
    ===================================================== */

    aiExplanationCard: {
      backgroundColor: "#0D192B",

      borderRadius: 19,

      borderWidth: 1,

      padding: 16,
    },


    aiExplanationHeader: {
      flexDirection: "row",

      alignItems: "center",

      marginBottom: 14,
    },


    aiExplanationIcon: {
      width: 43,

      height: 43,

      borderRadius: 13,

      justifyContent: "center",

      alignItems: "center",

      marginRight: 11,
    },


    aiExplanationHeaderText: {
      flex: 1,
    },


    aiExplanationTitle: {
      color: "#FFFFFF",

      fontSize: 14,

      fontWeight: "800",
    },


    aiExplanationSubtitle: {
      color: "#687A91",

      fontSize: 9.5,

      marginTop: 3,
    },


    aiExplanationBody: {
      backgroundColor: "#081322",

      borderRadius: 13,

      padding: 14,
    },


    aiExplanationText: {
      color: "#B9C6D6",

      fontSize: 12,

      lineHeight: 20,
    },


    /* =====================================================
       PRIVACY
    ===================================================== */

    privacyCard: {
      marginTop: 14,

      padding: 14,

      borderRadius: 16,

      backgroundColor: "#0B2421",

      borderWidth: 1,

      borderColor: "#17453E",

      flexDirection: "row",

      alignItems: "center",
    },


    privacyIcon: {
      width: 40,

      height: 40,

      borderRadius: 12,

      backgroundColor: "#0D332E",

      justifyContent: "center",

      alignItems: "center",

      marginRight: 11,
    },


    privacyInfo: {
      flex: 1,
    },


    privacyTitle: {
      color: "#D5F5EA",

      fontSize: 13,

      fontWeight: "800",
    },


    privacyText: {
      color: "#7EA79C",

      fontSize: 10.5,

      lineHeight: 16,

      marginTop: 3,
    },


    /* =====================================================
       CONTEXT
    ===================================================== */

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

      fontSize: 11,

      flex: 1,
    },


    contextValue: {
      color: "#D8E2EF",

      fontSize: 11,

      maxWidth: 165,
    },


    rowDivider: {
      height: 1,

      backgroundColor: "#17263A",
    },


    /* =====================================================
       TECHNICAL SIGNALS
    ===================================================== */

    signalsCard: {
      backgroundColor: "#0D192B",

      borderRadius: 18,

      borderWidth: 1,

      borderColor: "#1A2B43",

      paddingHorizontal: 15,
    },


    signalRow: {
      minHeight: 56,

      flexDirection: "row",

      alignItems: "center",
    },


    signalBorder: {
      borderBottomWidth: 1,

      borderBottomColor: "#17263A",
    },


    signalIcon: {
      width: 35,

      height: 35,

      borderRadius: 10,

      justifyContent: "center",

      alignItems: "center",

      marginRight: 10,
    },


    signalLabel: {
      flex: 1,

      color: "#B8C5D5",

      fontSize: 11,
    },


    signalStatus: {
      fontSize: 8,

      fontWeight: "900",

      letterSpacing: 0.3,
    },


    /* =====================================================
       PRIVACY FOOTER
    ===================================================== */

    privacyFooter: {
      marginTop: 20,

      padding: 13,

      borderRadius: 14,

      backgroundColor: "#081A19",

      flexDirection: "row",

      alignItems: "center",

      justifyContent: "center",
    },


    privacyFooterText: {
      color: "#70958D",

      fontSize: 10,

      marginLeft: 8,

      textAlign: "center",
    },


    /* =====================================================
       LAST CHECKED
    ===================================================== */

    lastChecked: {
      color: "#4F6077",

      textAlign: "center",

      fontSize: 9,

      marginTop: 13,
    },


    bottomSpace: {
      height: 30,
    },

  });
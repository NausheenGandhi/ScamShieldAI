import React, {
  useState,
  useEffect,
  useCallback,
} from "react";

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
import * as Contacts from "expo-contacts/legacy";

import { COLORS } from "../constants/colors";
import { API_BASE_URL } from "../constants/api";

const { SmsNativeModule } = NativeModules;

/* ============================================================
   STATUS
============================================================ */

const STATUS_STYLES = {
  DANGER: {
    color: "#FF5C5C",
    label: "HIGH RISK",
  },

  CAUTION: {
    color: "#F5C542",
    label: "CAUTION",
  },

  SAFE: {
    color: "#3DDC97",
    label: "SAFE",
  },
};

function getStatus(level) {
  return (
    STATUS_STYLES[level] ||
    STATUS_STYLES.CAUTION
  );
}

/* ============================================================
   NUMBER NORMALIZATION
============================================================ */

function normalizeNumber(number) {
  return (number || "").replace(
    /[\s()+-]/g,
    "",
  );
}

/* ============================================================
   CONTACT LOOKUP
============================================================ */

async function buildContactLookup() {
  try {
    const { data } =
      await Contacts.getContactsAsync({
        fields: [
          Contacts.Fields.PhoneNumbers,
        ],
      });

    const map = new Map();

    data.forEach((contact) => {
      (contact.phoneNumbers || []).forEach(
        (phone) => {
          const key = normalizeNumber(
            phone.number,
          );

          if (key) {
            map.set(
              key,
              contact.name,
            );
          }
        },
      );
    });

    return map;
  } catch (error) {
    console.log(
      "Contact lookup failed:",
      error,
    );

    return new Map();
  }
}

/* ============================================================
   MATCH CONTACT
============================================================ */

function matchContact(
  sender,
  lookup,
) {
  const senderKey =
    normalizeNumber(sender);

  if (!senderKey) {
    return {
      isSaved: false,
      name: null,
    };
  }

  /* Exact match */

  if (lookup.has(senderKey)) {
    return {
      isSaved: true,
      name: lookup.get(senderKey),
    };
  }

  /* Last 7 digits fallback */

  for (const [
    key,
    name,
  ] of lookup.entries()) {
    if (
      key.length >= 7 &&
      senderKey.length >= 7
    ) {
      if (
        key.endsWith(
          senderKey.slice(-7),
        ) ||
        senderKey.endsWith(
          key.slice(-7),
        )
      ) {
        return {
          isSaved: true,
          name,
        };
      }
    }
  }

  return {
    isSaved: false,
    name: null,
  };
}

/* ============================================================
   BACKEND CONTACT ANALYSIS
============================================================ */

async function analyzeContact(
  sender,
  body,
  isSavedContact,
  contactName,
  timestamp,
) {
  const response = await fetch(
    `${API_BASE_URL}/analyze-contact`,
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json",
      },

      body: JSON.stringify({
        sender:
          sender || "unknown",

        body:
          body || "",

        timestamp:
          timestamp || Date.now(),

        source:
          "react_native_contact_agent",

        is_saved_contact:
          Boolean(isSavedContact),

        contact_name:
          contactName || null,
      }),
    },
  );

  if (!response.ok) {
    const errorBody =
      await response
        .json()
        .catch(() => ({}));

    throw new Error(
      errorBody.detail ||
        `Server error (${response.status})`,
    );
  }

  return response.json();
}

/* ============================================================
   FORMATTERS
============================================================ */

function formatSenderType(
  senderType,
) {
  if (
    !senderType ||
    senderType === "UNKNOWN"
  ) {
    return "Unknown";
  }

  return String(senderType)
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}

function formatClassification(
  classification,
) {
  if (!classification) {
    return "UNKNOWN";
  }

  return String(classification)
    .replace(/_/g, " ")
    .toUpperCase();
}

function formatVerdict(verdict) {
  if (!verdict) {
    return "Unknown";
  }

  return String(verdict)
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}

/* ============================================================
   BACKEND RESPONSE MAPPING
============================================================ */

/*
  CURRENT BACKEND RESPONSE:

  {
    "level": "SAFE",
    "score": 86,

    "sender": {
      "normalized": "+918291429060",
      "type": "PERSONAL_NUMBER",
      "confidence": 0.95
    },

    "message_analysis": {
      "classification": "NORMAL",
      "spam_probability": 0.0,
      "scam_probability": 0.0
    },

    "sender_reputation": {
      "status": "LOW_RISK",
      "spam_score": 35,
      "total_messages": 1,
      "suspicious_messages": 0,
      "spam_messages": 0,
      "mongo_available": true
    },

    "trust": {
      "score": 86,
      "verdict": "TRUSTED"
    },

    "risk_signals": {
      "financial_request": false,
      "credential_request": false,
      "urgency": false,
      "threat": false,
      "impersonation": false,
      "suspicious_link": false,
      "secrecy_request": false
    }
  }
*/

/* ============================================================
   TRUST SCORE
============================================================ */

function getTrustScore(result) {
  const score = Number(
    result?.trust?.score ??
      result?.trust_score ??
      result?.score,
  );

  if (Number.isNaN(score)) {
    return null;
  }

  return Math.round(score);
}

/* ============================================================
   MESSAGE CLASSIFICATION
============================================================ */

function getClassification(result) {
  return (
    result?.message_analysis
      ?.classification ||
    result?.classification ||
    result?.message_classification ||
    "UNKNOWN"
  );
}

/* ============================================================
   TRUST VERDICT
============================================================ */

function getVerdict(result) {
  return (
    result?.trust?.verdict ||
    result?.verdict ||
    "UNKNOWN"
  );
}

/* ============================================================
   SENDER TYPE
============================================================ */

function getSenderType(result) {
  return (
    result?.sender?.type ||
    result?.sender_type ||
    "UNKNOWN"
  );
}

/* ============================================================
   SENDER CONFIDENCE
============================================================ */

function getSenderConfidence(
  result,
) {
  const confidence =
    result?.sender?.confidence;

  if (
    confidence === undefined ||
    confidence === null
  ) {
    return null;
  }

  return Math.round(
    Number(confidence) * 100,
  );
}

/* ============================================================
   MESSAGE PROBABILITIES
============================================================ */

function getSpamProbability(
  result,
) {
  const value =
    result?.message_analysis
      ?.spam_probability;

  if (
    value === undefined ||
    value === null
  ) {
    return null;
  }

  return Math.round(
    Number(value) * 100,
  );
}

function getScamProbability(
  result,
) {
  const value =
    result?.message_analysis
      ?.scam_probability;

  if (
    value === undefined ||
    value === null
  ) {
    return null;
  }

  return Math.round(
    Number(value) * 100,
  );
}

/* ============================================================
   REPUTATION
============================================================ */

function getReputation(result) {
  return (
    result?.sender_reputation ||
    result?.reputation ||
    null
  );
}

/* ============================================================
   CLASSIFICATION COLOR
============================================================ */

function getClassificationColor(
  classification,
) {
  switch (
    String(
      classification,
    ).toUpperCase()
  ) {
    case "SCAM":
      return "#FF5C5C";

    case "SUSPICIOUS":
      return "#F5C542";

    case "NORMAL":
      return COLORS.teal;

    default:
      return COLORS.muted;
  }
}

/* ============================================================
   RISK SIGNAL LABEL
============================================================ */

const RISK_SIGNAL_LABELS = {
  financial_request:
    "Message requests money or a financial transaction",

  credential_request:
    "Message requests credentials or sensitive information",

  urgency:
    "Message uses urgent or time-pressured language",

  threat:
    "Message contains threatening language",

  impersonation:
    "Message may be impersonating an organization or person",

  suspicious_link:
    "Message contains a suspicious link",

  secrecy_request:
    "Message asks you to keep the request secret",
};

/* ============================================================
   ANALYSIS CARD
============================================================ */

function ContactAnalysisCard({
  result,
  sender,
  contactName,
  isSavedContact,
}) {
  if (!result) {
    return null;
  }

  const status =
    getStatus(result.level);

  const trustScore =
    getTrustScore(result);

  const senderType =
    formatSenderType(
      getSenderType(result),
    );

  const senderConfidence =
    getSenderConfidence(
      result,
    );

  const classification =
    getClassification(result);

  const formattedClassification =
    formatClassification(
      classification,
    );

  const classificationColor =
    getClassificationColor(
      classification,
    );

  const verdict =
    getVerdict(result);

  const reputation =
    getReputation(result);

  const spamProbability =
    getSpamProbability(result);

  const scamProbability =
    getScamProbability(result);

  const impersonation =
    result?.impersonation;

  const riskSignals =
    result?.risk_signals || {};

  const reasons =
    Array.isArray(
      result?.reasons,
    )
      ? [
          ...new Set(
            result.reasons,
          ),
        ]
      : [];

  const explanation =
    result?.short_explanation ||
    result?.explanation ||
    "No additional explanation available.";

  return (
    <View
      style={[
        styles.analysisCard,
        {
          borderColor:
            status.color,
        },
      ]}
    >
      {/* =====================================================
          STATUS
      ===================================================== */}

      <View
        style={
          styles.resultHeader
        }
      >
        <View
          style={[
            styles.statusDot,
            {
              backgroundColor:
                status.color,
            },
          ]}
        />

        <Text
          style={[
            styles.resultLabel,
            {
              color:
                status.color,
            },
          ]}
        >
          {status.label}
        </Text>

        {trustScore !== null && (
          <Text
            style={
              styles.confidenceText
            }
          >
            {trustScore}/100
          </Text>
        )}
      </View>

      {/* =====================================================
          SENDER
      ===================================================== */}

      <Text
        style={
          styles.senderLarge
        }
      >
        {contactName ||
          sender ||
          "Unknown sender"}
      </Text>

      <Text
        style={
          styles.phoneText
        }
      >
        {sender ||
          "Unknown number"}
      </Text>

      {/* =====================================================
          TRUST SCORE
      ===================================================== */}

      {trustScore !== null && (
        <View
          style={
            styles.scoreContainer
          }
        >
          <View
            style={
              styles.scoreCircle
            }
          >
            <Text
              style={[
                styles.scoreValue,
                {
                  color:
                    status.color,
                },
              ]}
            >
              {trustScore}
            </Text>
          </View>

          <View
            style={
              styles.scoreTextContainer
            }
          >
            <Text
              style={
                styles.scoreTitle
              }
            >
              Trust Score
            </Text>

            <Text
              style={
                styles.scoreDescription
              }
            >
              {formatVerdict(
                verdict,
              )}
            </Text>
          </View>
        </View>
      )}

      {/* =====================================================
          CONTACT
      ===================================================== */}

      <View
        style={styles.infoRow}
      >
        <Text
          style={
            styles.infoLabel
          }
        >
          CONTACT
        </Text>

        <View
          style={
            styles.infoValueContainer
          }
        >
          <Ionicons
            name={
              isSavedContact
                ? "checkmark-circle"
                : "help-circle-outline"
            }
            size={17}
            color={
              isSavedContact
                ? COLORS.teal
                : COLORS.muted
            }
          />

          <Text
            style={
              styles.infoValue
            }
          >
            {isSavedContact
              ? "Saved Contact"
              : "Not In Contacts"}
          </Text>
        </View>
      </View>

      {/* =====================================================
          SENDER TYPE
      ===================================================== */}

      <View
        style={styles.infoRow}
      >
        <View>
          <Text
            style={
              styles.infoLabel
            }
          >
            SENDER TYPE
          </Text>

          {senderConfidence !==
            null && (
            <Text
              style={
                styles.smallMetaText
              }
            >
              Confidence{" "}
              {senderConfidence}%
            </Text>
          )}
        </View>

        <Text
          style={
            styles.infoValue
          }
        >
          {senderType}
        </Text>
      </View>

      {/* =====================================================
          MESSAGE RISK
      ===================================================== */}

      <View
        style={styles.infoRow}
      >
        <Text
          style={
            styles.infoLabel
          }
        >
          MESSAGE RISK
        </Text>

        <Text
          style={[
            styles.infoValue,
            {
              color:
                classificationColor,
            },
          ]}
        >
          {formattedClassification}
        </Text>
      </View>

      {/* =====================================================
          SPAM / SCAM PROBABILITY
      ===================================================== */}

      {(spamProbability !==
        null ||
        scamProbability !==
          null) && (
        <View
          style={
            styles.probabilityBox
          }
        >
          <Text
            style={
              styles.sectionMiniTitle
            }
          >
            MESSAGE ANALYSIS
          </Text>

          <View
            style={
              styles.probabilityRow
            }
          >
            <View
              style={
                styles.probabilityItem
              }
            >
              <Text
                style={
                  styles.probabilityValue
                }
              >
                {spamProbability ??
                  0}
                %
              </Text>

              <Text
                style={
                  styles.probabilityLabel
                }
              >
                Spam Probability
              </Text>
            </View>

            <View
              style={
                styles.probabilityItem
              }
            >
              <Text
                style={[
                  styles.probabilityValue,
                  {
                    color:
                      "#FF5C5C",
                  },
                ]}
              >
                {scamProbability ??
                  0}
                %
              </Text>

              <Text
                style={
                  styles.probabilityLabel
                }
              >
                Scam Probability
              </Text>
            </View>
          </View>
        </View>
      )}

      {/* =====================================================
          IMPERSONATION
      ===================================================== */}

      {impersonation?.detected && (
        <View
          style={
            styles.warningBox
          }
        >
          <Ionicons
            name="warning"
            size={22}
            color="#FF5C5C"
          />

          <View
            style={
              styles.warningContent
            }
          >
            <Text
              style={
                styles.warningTitle
              }
            >
              Possible Impersonation
            </Text>

            {impersonation
              .claimed_entity && (
              <Text
                style={
                  styles.warningText
                }
              >
                Claims to represent{" "}
                <Text
                  style={
                    styles.warningStrong
                  }
                >
                  {
                    impersonation.claimed_entity
                  }
                </Text>
                .
              </Text>
            )}

            {impersonation.reason && (
              <Text
                style={
                  styles.warningText
                }
              >
                {
                  impersonation.reason
                }
              </Text>
            )}
          </View>
        </View>
      )}

      {/* =====================================================
          SENDER REPUTATION
      ===================================================== */}

      {reputation && (
        <View
          style={
            styles.reputationBox
          }
        >
          <Text
            style={
              styles.sectionMiniTitle
            }
          >
            SENDER REPUTATION
          </Text>

          <View
            style={
              styles.reputationHeader
            }
          >
            <Text
              style={
                styles.reputationStatus
              }
            >
              {String(
                reputation.status ||
                  "UNKNOWN",
              ).replace(
                /_/g,
                " ",
              )}
            </Text>

            {reputation
              .spam_score !==
              null &&
              reputation
                .spam_score !==
                undefined && (
                <Text
                  style={
                    styles.reputationScore
                  }
                >
                  Risk{" "}
                  {
                    reputation.spam_score
                  }
                </Text>
              )}
          </View>

          <View
            style={
              styles.reputationStats
            }
          >
            <View
              style={
                styles.reputationStat
              }
            >
              <Text
                style={
                  styles.reputationStatValue
                }
              >
                {
                  reputation.total_messages ??
                  0
                }
              </Text>

              <Text
                style={
                  styles.reputationStatLabel
                }
              >
                Messages
              </Text>
            </View>

            <View
              style={
                styles.reputationStat
              }
            >
              <Text
                style={[
                  styles.reputationStatValue,
                  {
                    color:
                      "#F5C542",
                  },
                ]}
              >
                {
                  reputation.suspicious_messages ??
                  0
                }
              </Text>

              <Text
                style={
                  styles.reputationStatLabel
                }
              >
                Suspicious
              </Text>
            </View>

            <View
              style={
                styles.reputationStat
              }
            >
              <Text
                style={[
                  styles.reputationStatValue,
                  {
                    color:
                      "#FF5C5C",
                  },
                ]}
              >
                {
                  reputation.spam_messages ??
                  0
                }
              </Text>

              <Text
                style={
                  styles.reputationStatLabel
                }
              >
                Spam
              </Text>
            </View>
          </View>
        </View>
      )}

      {/* =====================================================
          RISK SIGNALS
      ===================================================== */}

      {reasons.length > 0 && (
        <View
          style={
            styles.reasonsBox
          }
        >
          <Text
            style={
              styles.sectionMiniTitle
            }
          >
            RISK SIGNALS
          </Text>

          {reasons.map(
            (
              reason,
              index,
            ) => (
              <View
                key={`${reason}-${index}`}
                style={
                  styles.reasonRow
                }
              >
                <View
                  style={
                    styles.reasonBulletContainer
                  }
                >
                  <Ionicons
                    name="alert-circle"
                    size={15}
                    color={
                      status.color
                    }
                  />
                </View>

                <Text
                  style={
                    styles.reasonText
                  }
                >
                  {reason}
                </Text>
              </View>
            ),
          )}
        </View>
      )}

      {/* =====================================================
          RAW RISK SIGNAL DETAILS
      ===================================================== */}

      {Object.keys(
        riskSignals,
      ).some(
        (key) =>
          riskSignals[key] ===
          true,
      ) && (
        <View
          style={
            styles.signalDetailsBox
          }
        >
          <Text
            style={
              styles.sectionMiniTitle
            }
          >
            DETECTED SIGNALS
          </Text>

          {Object.entries(
            riskSignals,
          )
            .filter(
              ([, value]) =>
                value === true,
            )
            .map(
              ([
                key,
              ]) => (
                <View
                  key={key}
                  style={
                    styles.signalDetailRow
                  }
                >
                  <Ionicons
                    name="warning-outline"
                    size={15}
                    color="#F5C542"
                  />

                  <Text
                    style={
                      styles.signalDetailText
                    }
                  >
                    {RISK_SIGNAL_LABELS[
                      key
                    ] ||
                      key}
                  </Text>
                </View>
              ),
            )}
        </View>
      )}

      {/* =====================================================
          EXPLANATION
      ===================================================== */}

      <View
        style={
          styles.explanationBox
        }
      >
        <View
          style={
            styles.explanationHeader
          }
        >
          <Ionicons
            name="information-circle-outline"
            size={18}
            color={
              COLORS.teal
            }
          />

          <Text
            style={
              styles.sectionMiniTitle
            }
          >
            WHY?
          </Text>
        </View>

        <Text
          style={
            styles.explanationText
          }
        >
          {explanation}
        </Text>
      </View>
    </View>
  );
}

/* ============================================================
   MAIN SCREEN
============================================================ */

export default function ContactAgentScreen({
  onBack,
}) {
  const [
    recent,
    setRecent,
  ] = useState([]);

  const [
    loadingRecent,
    setLoadingRecent,
  ] = useState(true);

  const [
    refreshing,
    setRefreshing,
  ] = useState(false);

  const [
    liveEvent,
    setLiveEvent,
  ] = useState(null);

  const [
    isConnected,
    setIsConnected,
  ] = useState(false);

  /* ==========================================================
     LOAD LAST 3 SMS
  ========================================================== */

  const loadRecentMessages =
    useCallback(() => {
      setLoadingRecent(true);

      SmsAndroid.list(
        JSON.stringify({
          box: "inbox",
          maxCount: 3,
        }),

        (fail) => {
          console.log(
            "Contact Agent SMS read failed:",
            fail,
          );

          setLoadingRecent(false);
          setRefreshing(false);
        },

        async (
          count,
          smsList,
        ) => {
          try {
            const messages =
              JSON.parse(
                smsList,
              ).slice(0, 3);

            const lookup =
              await buildContactLookup();

            const initial =
              messages.map(
                (message) => {
                  const {
                    isSaved,
                    name,
                  } =
                    matchContact(
                      message.address,
                      lookup,
                    );

                  return {
                    sender:
                      message.address,

                    body:
                      message.body,

                    timestamp:
                      message.date,

                    isSavedContact:
                      isSaved,

                    contactName:
                      name,

                    result: null,

                    error: null,

                    loading: true,
                  };
                },
              );

            setRecent(initial);
            setLoadingRecent(false);
            setRefreshing(false);

            /* Analyze each message */

            initial.forEach(
              (
                item,
                index,
              ) => {
                analyzeContact(
                  item.sender,
                  item.body,
                  item.isSavedContact,
                  item.contactName,
                  item.timestamp,
                )
                  .then(
                    (result) => {
                      setRecent(
                        (
                          previous,
                        ) => {
                          const next =
                            [
                              ...previous,
                            ];

                          if (
                            next[index]
                          ) {
                            next[index] =
                              {
                                ...next[
                                  index
                                ],
                                result,
                                loading:
                                  false,
                              };
                          }

                          return next;
                        },
                      );
                    },
                  )
                  .catch(
                    (error) => {
                      setRecent(
                        (
                          previous,
                        ) => {
                          const next =
                            [
                              ...previous,
                            ];

                          if (
                            next[index]
                          ) {
                            next[index] =
                              {
                                ...next[
                                  index
                                ],
                                error:
                                  error.message ||
                                  "Analysis failed",
                                loading:
                                  false,
                              };
                          }

                          return next;
                        },
                      );
                    },
                  );
              },
            );
          } catch (error) {
            console.log(
              "Contact Agent parsing failed:",
              error,
            );

            setLoadingRecent(false);
            setRefreshing(false);
          }
        },
      );
    }, []);

  /* ==========================================================
     LOAD LIVE NATIVE EVENT
  ========================================================== */

  const loadLiveEvent =
    useCallback(
      async () => {
        try {
          if (!SmsNativeModule) {
            setIsConnected(false);
            return;
          }

          const raw =
            await SmsNativeModule.getLatestSmsEvent();

          setIsConnected(true);

          if (!raw) {
            return;
          }

          const parsed =
            typeof raw === "string"
              ? JSON.parse(raw)
              : raw;

          setLiveEvent(parsed);
        } catch (error) {
          console.log(
            "Contact Agent native event error:",
            error,
          );

          setIsConnected(false);
        }
      },
      [],
    );

  /* ==========================================================
     INITIAL LOAD
  ========================================================== */

  useEffect(() => {
    loadRecentMessages();
  }, [
    loadRecentMessages,
  ]);

  /* ==========================================================
     REAL-TIME POLLING
  ========================================================== */

  useEffect(() => {
    loadLiveEvent();

    const interval =
      setInterval(
        loadLiveEvent,
        2000,
      );

    return () =>
      clearInterval(
        interval,
      );
  }, [
    loadLiveEvent,
  ]);

  /* ==========================================================
     REFRESH
  ========================================================== */

  function handleRefresh() {
    setRefreshing(true);
    loadRecentMessages();
  }

  /* ==========================================================
     LIVE RESULT
  ========================================================== */

  const liveResult =
    liveEvent?.contact_analysis &&
    Object.keys(
      liveEvent.contact_analysis,
    ).length > 0
      ? liveEvent.contact_analysis
      : null;

  const livePatternResult =
    liveEvent?.pattern_analysis &&
    Object.keys(
      liveEvent.pattern_analysis,
    ).length > 0
      ? liveEvent.pattern_analysis
      : null;

  /* ==========================================================
     RENDER
  ========================================================== */

  return (
    <SafeAreaView
      style={styles.safeArea}
      edges={[
        "top",
        "bottom",
      ]}
    >
      <ScrollView
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
            tintColor={
              COLORS.cyan
            }
          />
        }
      >
        {/* ====================================================
            HEADER
        ==================================================== */}

        <View
          style={styles.header}
        >
          <Pressable
            onPress={onBack}
            hitSlop={12}
          >
            <Ionicons
              name="arrow-back"
              size={24}
              color={
                COLORS.white
              }
            />
          </Pressable>

          <Text
            style={styles.title}
          >
            Contact Agent
          </Text>

          <View
            style={{
              width: 24,
            }}
          />
        </View>

        {/* ====================================================
            DESCRIPTION
        ==================================================== */}

        <Text
          style={styles.subtitle}
        >
          Checks whether the sender is saved
          in your contacts and analyzes sender
          identity, message risk, impersonation,
          reputation, and messaging patterns.
        </Text>

        {/* ====================================================
            REAL-TIME MONITORING
        ==================================================== */}

        <View
          style={
            styles.sectionRow
          }
        >
          <Text
            style={
              styles.sectionTitle
            }
          >
            Real-time monitoring
          </Text>

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
                      ? COLORS.teal
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
                      ? COLORS.teal
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

        {/* ====================================================
            LIVE RESULT
        ==================================================== */}

        {liveResult ? (
          <ContactAnalysisCard
            result={
              liveResult
            }
            sender={
              liveEvent?.sender
            }
            contactName={
              liveEvent?.contact_name
            }
            isSavedContact={
              liveEvent?.is_saved_contact
            }
          />
        ) : (
          <View
            style={styles.card}
          >
            <View
              style={
                styles.emptyIcon
              }
            >
              <Ionicons
                name="chatbubble-ellipses-outline"
                size={28}
                color={
                  COLORS.cyan
                }
              />
            </View>

            <Text
              style={
                styles.emptyTitle
              }
            >
              Waiting for an SMS
            </Text>

            <Text
              style={
                styles.emptyText
              }
            >
              A new incoming SMS will
              automatically be analyzed by
              the Contact Agent.
            </Text>
          </View>
        )}

        {livePatternResult && (
          <View
            style={[
              styles.card,
              {
                marginTop: 16,
                borderColor: "#1F5F77",
                borderWidth: 1,
              },
            ]}
          >
            <Text
              style={styles.sectionTitle}
            >
              Pattern Risk
            </Text>

            <Text
              style={[
                styles.detailValue,
                {
                  color:
                    livePatternResult.pattern_risk === "HIGH"
                      ? "#FF5C5C"
                      : livePatternResult.pattern_risk === "MEDIUM"
                        ? "#FFB020"
                        : "#3DDC97",
                  marginBottom: 8,
                },
              ]}
            >
              {livePatternResult.pattern_risk || livePatternResult.pattern?.risk || "UNKNOWN"}
            </Text>

            <Text
              style={styles.detailLabel}
            >
              Score: {livePatternResult.pattern_score ?? livePatternResult.pattern?.score ?? "n/a"}
            </Text>

            <Text
              style={styles.detailLabel}
            >
              Signals: {Object.entries(livePatternResult.signals || {})
                .filter(([, value]) => Boolean(value))
                .map(([key]) => key.replace(/_/g, " "))
                .join(", ") || "none"}
            </Text>

            {(livePatternResult.reasons || []).length > 0 && (
              <Text
                style={styles.detailText}
              >
                {livePatternResult.reasons.slice(0, 3).join(" ")}
              </Text>
            )}
          </View>
        )}

        {/* ====================================================
            LAST 3 MESSAGES
        ==================================================== */}

        <Text
          style={
            styles.sectionTitle
          }
        >
          Last 3 messages
        </Text>

        {loadingRecent ? (
          <ActivityIndicator
            color={
              COLORS.cyan
            }
            style={
              styles.spinner
            }
          />
        ) : recent.length ===
          0 ? (
          <View
            style={styles.card}
          >
            <Text
              style={
                styles.emptyText
              }
            >
              No messages found on this device.
            </Text>
          </View>
        ) : (
          recent.map(
            (
              item,
              index,
            ) => (
              <View
                key={`${item.sender}-${item.timestamp}-${index}`}
                style={
                  styles.messageCard
                }
              >
                {/* Sender */}

                <View
                  style={
                    styles.messageHeader
                  }
                >
                  <View
                    style={
                      styles.messageSenderContainer
                    }
                  >
                    <Text
                      style={
                        styles.senderText
                      }
                    >
                      {item.contactName ||
                        item.sender ||
                        "Unknown sender"}
                    </Text>

                    <Text
                      style={
                        styles.metaText
                      }
                    >
                      {item.isSavedContact
                        ? "✓ Saved contact"
                        : "Not in your contacts"}
                    </Text>
                  </View>

                  <Ionicons
                    name={
                      item.isSavedContact
                        ? "person-circle"
                        : "person-outline"
                    }
                    size={25}
                    color={
                      item.isSavedContact
                        ? COLORS.teal
                        : COLORS.muted
                    }
                  />
                </View>

                {/* Message */}

                <View
                  style={
                    styles.messageBubble
                  }
                >
                  <Text
                    style={
                      styles.bodyText
                    }
                    numberOfLines={
                      3
                    }
                  >
                    {item.body}
                  </Text>
                </View>

                {/* Loading */}

                {item.loading && (
                  <View
                    style={
                      styles.inlineLoading
                    }
                  >
                    <ActivityIndicator
                      size="small"
                      color={
                        COLORS.cyan
                      }
                    />

                    <Text
                      style={
                        styles.inlineLoadingText
                      }
                    >
                      Analyzing with Contact Agent...
                    </Text>
                  </View>
                )}

                {/* Error */}

                {item.error && (
                  <View
                    style={
                      styles.errorBox
                    }
                  >
                    <Ionicons
                      name="alert-circle-outline"
                      size={18}
                      color="#FF5C5C"
                    />

                    <Text
                      style={
                        styles.errorText
                      }
                    >
                      {item.error}
                    </Text>
                  </View>
                )}

                {/* Result */}

                {item.result && (
                  <ContactAnalysisCard
                    result={
                      item.result
                    }
                    sender={
                      item.sender
                    }
                    contactName={
                      item.contactName
                    }
                    isSavedContact={
                      item.isSavedContact
                    }
                  />
                )}
              </View>
            ),
          )
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

/* ============================================================
   STYLES
============================================================ */

const styles =
  StyleSheet.create({
    safeArea: {
      flex: 1,
      backgroundColor:
        COLORS.background,
    },

    scrollContent: {
      padding: 24,
      paddingBottom: 60,
    },

    /* ========================================================
       HEADER
    ======================================================== */

    header: {
      flexDirection:
        "row",
      alignItems:
        "center",
      justifyContent:
        "space-between",
      marginBottom: 12,
    },

    title: {
      color:
        COLORS.white,
      fontSize: 20,
      fontWeight:
        "700",
    },

    subtitle: {
      color:
        COLORS.muted,
      fontSize: 13,
      lineHeight: 19,
      marginBottom: 20,
    },

    /* ========================================================
       SECTION
    ======================================================== */

    sectionRow: {
      flexDirection:
        "row",
      alignItems:
        "center",
      justifyContent:
        "space-between",
      marginBottom: 10,
    },

    sectionTitle: {
      color:
        COLORS.white,
      fontSize: 15,
      fontWeight:
        "700",
      marginTop: 18,
      marginBottom: 10,
    },

    /* ========================================================
       LIVE
    ======================================================== */

    liveBadge: {
      flexDirection:
        "row",
      alignItems:
        "center",
      paddingHorizontal:
        10,
      paddingVertical:
        6,
      borderRadius: 16,
    },

    liveDot: {
      width: 6,
      height: 6,
      borderRadius: 4,
      marginRight: 6,
    },

    liveText: {
      fontSize: 10,
      fontWeight:
        "900",
    },

    /* ========================================================
       GENERIC CARD
    ======================================================== */

    card: {
      borderRadius: 20,
      backgroundColor:
        COLORS.surface,
      borderWidth: 1,
      borderColor:
        "#16435A",
      padding: 18,
      marginBottom: 14,
    },

    /* ========================================================
       ANALYSIS CARD
    ======================================================== */

    analysisCard: {
      borderRadius: 22,
      backgroundColor:
        COLORS.surface,
      borderWidth: 1.5,
      padding: 18,
      marginBottom: 14,
    },

    /* ========================================================
       RESULT HEADER
    ======================================================== */

    resultHeader: {
      flexDirection:
        "row",
      alignItems:
        "center",
      marginBottom: 8,
    },

    statusDot: {
      width: 9,
      height: 9,
      borderRadius: 5,
      marginRight: 8,
    },

    resultLabel: {
      fontSize: 14,
      fontWeight:
        "800",
      flex: 1,
    },

    confidenceText: {
      color:
        COLORS.muted,
      fontSize: 11,
      fontWeight:
        "600",
    },

    /* ========================================================
       SENDER
    ======================================================== */

    senderLarge: {
      color:
        COLORS.white,
      fontSize: 21,
      fontWeight:
        "700",
      marginTop: 5,
    },

    phoneText: {
      color:
        COLORS.muted,
      fontSize: 12,
      marginTop: 3,
    },

    senderText: {
      color:
        COLORS.white,
      fontSize: 14,
      fontWeight:
        "700",
    },

    metaText: {
      color:
        COLORS.teal,
      fontSize: 11,
      marginTop: 3,
    },

    smallMetaText: {
      color:
        COLORS.muted,
      fontSize: 9,
      marginTop: 3,
    },

    /* ========================================================
       SCORE
    ======================================================== */

    scoreContainer: {
      flexDirection:
        "row",
      alignItems:
        "center",
      marginVertical: 18,
      padding: 16,
      borderRadius: 18,
      backgroundColor:
        COLORS.background,
    },

    scoreCircle: {
      width: 72,
      height: 72,
      borderRadius: 36,
      alignItems:
        "center",
      justifyContent:
        "center",
      borderWidth: 3,
      borderColor:
        "#16435A",
    },

    scoreValue: {
      fontSize: 25,
      fontWeight:
        "900",
    },

    scoreTextContainer: {
      marginLeft: 14,
    },

    scoreTitle: {
      color:
        COLORS.white,
      fontSize: 15,
      fontWeight:
        "700",
      marginBottom: 4,
    },

    scoreDescription: {
      color:
        COLORS.muted,
      fontSize: 12,
    },

    /* ========================================================
       INFO ROW
    ======================================================== */

    infoRow: {
      flexDirection:
        "row",
      justifyContent:
        "space-between",
      alignItems:
        "center",
      paddingVertical: 11,
      borderTopWidth: 1,
      borderTopColor:
        "#16435A",
    },

    infoLabel: {
      color:
        COLORS.muted,
      fontSize: 10,
      fontWeight:
        "800",
      letterSpacing: 1,
    },

    infoValueContainer: {
      flexDirection:
        "row",
      alignItems:
        "center",
      gap: 5,
    },

    infoValue: {
      color:
        COLORS.white,
      fontSize: 13,
      fontWeight:
        "600",
      textTransform:
        "capitalize",
    },

    /* ========================================================
       MESSAGE PROBABILITY
    ======================================================== */

    probabilityBox: {
      marginTop: 16,
      padding: 14,
      borderRadius: 16,
      backgroundColor:
        COLORS.background,
    },

    probabilityRow: {
      flexDirection:
        "row",
      justifyContent:
        "space-around",
    },

    probabilityItem: {
      flex: 1,
      alignItems:
        "center",
    },

    probabilityValue: {
      color:
        COLORS.teal,
      fontSize: 18,
      fontWeight:
        "800",
    },

    probabilityLabel: {
      color:
        COLORS.muted,
      fontSize: 10,
      textAlign:
        "center",
      marginTop: 4,
    },

    /* ========================================================
       IMPERSONATION
    ======================================================== */

    warningBox: {
      flexDirection:
        "row",
      padding: 14,
      borderRadius: 16,
      backgroundColor:
        "#351F24",
      marginTop: 14,
    },

    warningContent: {
      flex: 1,
      marginLeft: 10,
    },

    warningTitle: {
      color:
        "#FF5C5C",
      fontSize: 13,
      fontWeight:
        "800",
      marginBottom: 5,
    },

    warningText: {
      color:
        COLORS.muted,
      fontSize: 12,
      lineHeight: 18,
      marginBottom: 3,
    },

    warningStrong: {
      color:
        COLORS.white,
      fontWeight:
        "700",
    },

    /* ========================================================
       REPUTATION
    ======================================================== */

    reputationBox: {
      marginTop: 16,
      padding: 14,
      borderRadius: 16,
      backgroundColor:
        COLORS.background,
    },

    reputationHeader: {
      flexDirection:
        "row",
      alignItems:
        "center",
      justifyContent:
        "space-between",
      marginBottom: 12,
    },

    reputationStatus: {
      color:
        COLORS.white,
      fontSize: 14,
      fontWeight:
        "800",
      textTransform:
        "capitalize",
    },

    reputationScore: {
      color:
        COLORS.muted,
      fontSize: 11,
    },

    reputationStats: {
      flexDirection:
        "row",
      justifyContent:
        "space-between",
    },

    reputationStat: {
      alignItems:
        "center",
      flex: 1,
    },

    reputationStatValue: {
      color:
        COLORS.white,
      fontSize: 18,
      fontWeight:
        "800",
    },

    reputationStatLabel: {
      color:
        COLORS.muted,
      fontSize: 10,
      marginTop: 3,
    },

    /* ========================================================
       MINI SECTION
    ======================================================== */

    sectionMiniTitle: {
      color:
        COLORS.teal,
      fontSize: 10,
      fontWeight:
        "800",
      letterSpacing: 1.2,
      marginBottom: 8,
    },

    /* ========================================================
       RISK REASONS
    ======================================================== */

    reasonsBox: {
      marginTop: 16,
    },

    reasonRow: {
      flexDirection:
        "row",
      alignItems:
        "flex-start",
      marginTop: 8,
    },

    reasonBulletContainer: {
      width: 22,
      paddingTop: 1,
    },

    reasonText: {
      flex: 1,
      color:
        COLORS.muted,
      fontSize: 12,
      lineHeight: 18,
    },

    /* ========================================================
       DETECTED SIGNALS
    ======================================================== */

    signalDetailsBox: {
      marginTop: 14,
      padding: 14,
      borderRadius: 16,
      backgroundColor:
        COLORS.background,
    },

    signalDetailRow: {
      flexDirection:
        "row",
      alignItems:
        "flex-start",
      marginTop: 8,
    },

    signalDetailText: {
      flex: 1,
      color:
        COLORS.muted,
      fontSize: 12,
      lineHeight: 18,
      marginLeft: 8,
    },

    /* ========================================================
       EXPLANATION
    ======================================================== */

    explanationBox: {
      marginTop: 16,
      paddingTop: 14,
      borderTopWidth: 1,
      borderTopColor:
        "#16435A",
    },

    explanationHeader: {
      flexDirection:
        "row",
      alignItems:
        "center",
      gap: 6,
    },

    explanationText: {
      color:
        COLORS.white,
      fontSize: 13,
      lineHeight: 20,
      marginTop: 5,
    },

    /* ========================================================
       EMPTY STATE
    ======================================================== */

    emptyIcon: {
      width: 56,
      height: 56,
      borderRadius: 18,
      backgroundColor:
        COLORS.background,
      alignItems:
        "center",
      justifyContent:
        "center",
      marginBottom: 12,
    },

    emptyTitle: {
      color:
        COLORS.white,
      fontSize: 16,
      fontWeight:
        "700",
      marginBottom: 6,
    },

    emptyText: {
      color:
        COLORS.muted,
      fontSize: 13,
      lineHeight: 19,
    },

    /* ========================================================
       LAST MESSAGE
    ======================================================== */

    messageCard: {
      borderRadius: 20,
      backgroundColor:
        COLORS.surface,
      borderWidth: 1,
      borderColor:
        "#16435A",
      padding: 16,
      marginBottom: 14,
    },

    messageHeader: {
      flexDirection:
        "row",
      alignItems:
        "center",
      justifyContent:
        "space-between",
      marginBottom: 10,
    },

    messageSenderContainer: {
      flex: 1,
    },

    messageBubble: {
      backgroundColor:
        COLORS.background,
      borderRadius: 14,
      padding: 12,
      marginBottom: 10,
    },

    bodyText: {
      color:
        COLORS.muted,
      fontSize: 12,
      lineHeight: 18,
    },

    /* ========================================================
       LOADING
    ======================================================== */

    spinner: {
      marginVertical: 12,
    },

    inlineLoading: {
      flexDirection:
        "row",
      alignItems:
        "center",
      paddingVertical: 5,
    },

    inlineLoadingText: {
      color:
        COLORS.muted,
      fontSize: 12,
      marginLeft: 8,
    },

    /* ========================================================
       ERROR
    ======================================================== */

    errorBox: {
      flexDirection:
        "row",
      alignItems:
        "center",
      padding: 10,
      borderRadius: 12,
      backgroundColor:
        "#351F24",
    },

    errorText: {
      color:
        "#FF9C9C",
      fontSize: 12,
      flex: 1,
      marginLeft: 7,
    },
  });
import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  FlatList,
  Pressable,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import * as Contacts from "expo-contacts/legacy";
import SmsAndroid from "react-native-get-sms-android";
import { COLORS } from "../constants/colors";

const normalizePhone = (value) => {
  if (!value) return "";
  return value
    .replace(/[^\d+]/g, "")
    .replace(/^\+/, "")
    .replace(/\s+/g, "");
};

export default function DeviceDataScreen({ onContinue }) {
  const [messages, setMessages] = useState([]);
  const [contacts, setContacts] = useState([]);
  const [contactLookup, setContactLookup] = useState({});
  const [loadingSms, setLoadingSms] = useState(true);
  const [loadingContacts, setLoadingContacts] = useState(true);

  useEffect(() => {
    // Load SMS inbox (Android only)
    SmsAndroid.list(
      JSON.stringify({ box: "inbox", maxCount: 50 }),
      (fail) => {
        console.log("SMS read failed:", fail);
        setLoadingSms(false);
      },
      (count, smsList) => {
        setMessages(JSON.parse(smsList));
        setLoadingSms(false);
      },
    );

    // Load contacts
    (async () => {
      const { data } = await Contacts.getContactsAsync({
        fields: [Contacts.Fields.PhoneNumbers],
      });

      const lookup = {};

      data.forEach((contact) => {
        const numbers = contact.phoneNumbers ?? [];
        numbers.forEach((phone) => {
          const normalized = normalizePhone(phone.number);
          if (normalized) {
            lookup[normalized] = contact.name || "Saved contact";
          }
        });
      });

      setContacts(data);
      setContactLookup(lookup);
      setLoadingContacts(false);
    })();
  }, []);

  return (
    <SafeAreaView style={styles.safeArea} edges={["top", "bottom"]}>
      <View style={styles.container}>
        <Text style={styles.pageTitle}>Device data</Text>
        <Text style={styles.pageSubtitle}>
          Read directly from this device. Nothing shown here leaves your phone.
        </Text>

        <Text style={styles.header}>Inbox ({messages.length})</Text>
        {loadingSms ? (
          <ActivityIndicator color={COLORS.cyan} style={styles.spinner} />
        ) : (
          <FlatList
            data={messages}
            keyExtractor={(item, index) =>
              item._id?.toString() ?? String(index)
            }
            renderItem={({ item }) => {
              const normalizedAddress = normalizePhone(item.address);
              const savedContactName = contactLookup[normalizedAddress];

              return (
                <View style={styles.row}>
                  <Text style={styles.rowTitle}>
                    {savedContactName || item.address}
                  </Text>
                  <Text style={styles.rowBody} numberOfLines={2}>
                    {savedContactName ? item.address : item.body}
                  </Text>
                </View>
              );
            }}
            ListEmptyComponent={
              <Text style={styles.emptyText}>No messages found.</Text>
            }
            style={styles.list}
          />
        )}

        <Text style={styles.header}>Contacts ({contacts.length})</Text>
        {loadingContacts ? (
          <ActivityIndicator color={COLORS.cyan} style={styles.spinner} />
        ) : (
          <FlatList
            data={contacts}
            keyExtractor={(item) => item.id}
            renderItem={({ item }) => (
              <View style={styles.row}>
                <Text style={styles.rowTitle}>{item.name}</Text>
                <Text style={styles.rowBody}>
                  {item.phoneNumbers?.[0]?.number || "No number"}
                </Text>
              </View>
            )}
            ListEmptyComponent={
              <Text style={styles.emptyText}>No contacts found.</Text>
            }
            style={styles.list}
          />
        )}

        <Pressable
          onPress={onContinue}
          accessibilityRole="button"
          accessibilityLabel="Continue to Security Center"
          style={({ pressed }) => [
            styles.continueButton,
            pressed && styles.buttonPressed,
          ]}
        >
          <Text style={styles.continueButtonText}>Continue</Text>
        </Pressable>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: COLORS.background },
  container: { flex: 1, paddingHorizontal: 20, paddingTop: 16 },
  pageTitle: {
    color: COLORS.white,
    fontSize: 26,
    fontWeight: "700",
    marginBottom: 4,
  },
  pageSubtitle: {
    color: COLORS.muted,
    fontSize: 13,
    marginBottom: 12,
  },
  header: {
    color: COLORS.white,
    fontSize: 17,
    fontWeight: "700",
    marginTop: 14,
    marginBottom: 10,
  },
  spinner: { marginVertical: 12 },
  list: { maxHeight: 200 },
  row: {
    backgroundColor: COLORS.surface,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: "#16435A",
    padding: 12,
    marginBottom: 8,
  },
  rowTitle: { color: COLORS.white, fontWeight: "600" },
  rowBody: { color: COLORS.muted, fontSize: 12, marginTop: 4 },
  emptyText: { color: COLORS.muted, fontSize: 13, paddingVertical: 8 },
  continueButton: {
    minHeight: 58,
    borderRadius: 30,
    backgroundColor: COLORS.cyan,
    alignItems: "center",
    justifyContent: "center",
    marginTop: 16,
    marginBottom: 12,
  },
  continueButtonText: {
    color: COLORS.darkIcon,
    fontSize: 16,
    fontWeight: "700",
  },
  buttonPressed: { opacity: 0.8 },
});

import React from "react";
import { Dimensions, StyleSheet, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { COLORS } from "../constants/colors";

const { width } = Dimensions.get("window");

export default function ShieldIcon({ iconName }) {
  return (
    <View style={styles.iconOuterRing}>
      <View style={styles.iconMiddleRing}>
        <View style={styles.iconBox}>
          <Ionicons
            name={iconName}
            size={width < 380 ? 58 : 66}
            color={COLORS.darkIcon}
          />
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  iconOuterRing: {
    width: width < 380 ? 184 : 208,
    height: width < 380 ? 184 : 208,
    borderRadius: 120,
    borderWidth: 1,
    borderColor: "#16435A",
    alignItems: "center",
    justifyContent: "center",
  },
  iconMiddleRing: {
    width: width < 380 ? 158 : 180,
    height: width < 380 ? 158 : 180,
    borderRadius: 100,
    borderWidth: 1,
    borderColor: "#16435A",
    alignItems: "center",
    justifyContent: "center",
  },
  iconBox: {
    width: width < 380 ? 128 : 142,
    height: width < 380 ? 128 : 142,
    borderRadius: 40,
    backgroundColor: COLORS.cyan,
    alignItems: "center",
    justifyContent: "center",
    shadowColor: COLORS.cyan,
    shadowOffset: { width: 0, height: 12 },
    shadowOpacity: 0.3,
    shadowRadius: 25,
    elevation: 12,
  },
});

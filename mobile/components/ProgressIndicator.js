import React from "react";
import { StyleSheet, View } from "react-native";
import { COLORS } from "../constants/colors";

export default function ProgressIndicator({ currentStep, totalSteps }) {
  return (
    <View style={styles.progressContainer}>
      {Array.from({ length: totalSteps }).map((_, index) => (
        <View
          key={index}
          style={[
            styles.progressDot,
            index === currentStep
              ? styles.activeProgressDot
              : styles.inactiveProgressDot,
          ]}
        />
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  progressContainer: {
    height: 18,
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
    marginBottom: 34,
  },
  progressDot: {
    height: 8,
    borderRadius: 8,
  },
  activeProgressDot: {
    width: 36,
    backgroundColor: COLORS.cyan,
  },
  inactiveProgressDot: {
    width: 8,
    backgroundColor: COLORS.inactive,
  },
});

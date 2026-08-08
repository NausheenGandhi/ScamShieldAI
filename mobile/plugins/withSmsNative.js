const {
  withDangerousMod,
  withMainApplication,
  withAndroidManifest,
} = require("@expo/config-plugins");

const fs = require("fs");
const path = require("path");

/*
 * Copies our custom Kotlin files into the generated
 * Android project.
 */
function withSmsKotlinFiles(config) {
  return withDangerousMod(config, [
    "android",
    async (config) => {
      const projectRoot = config.modRequest.projectRoot;

      const sourceDir = path.join(
        projectRoot,
        "native",
        "android",
        "com",
        "naush12",
        "mobile"
      );

      const destinationDir = path.join(
        projectRoot,
        "android",
        "app",
        "src",
        "main",
        "java",
        "com",
        "naush12",
        "mobile"
      );

      fs.mkdirSync(destinationDir, {
        recursive: true,
      });

      const files = [
        "SmsReceiver.kt",
        "SmsNativeModule.kt",
        "SmsNativePackage.kt",
      ];

      for (const file of files) {
        const sourceFile = path.join(
          sourceDir,
          file
        );

        const destinationFile = path.join(
          destinationDir,
          file
        );

        if (!fs.existsSync(sourceFile)) {
          throw new Error(
            `Missing native Kotlin file: ${sourceFile}`
          );
        }

        fs.copyFileSync(
          sourceFile,
          destinationFile
        );

        console.log(
          `✓ Copied ${file}`
        );
      }

      return config;
    },
  ]);
}

/*
 * Add our SmsNativePackage to MainApplication.
 */
function withSmsMainApplication(config) {
  return withMainApplication(config, (config) => {
    let contents = config.modResults.contents;

    const importLine =
      "import com.naush12.mobile.SmsNativePackage";

    if (!contents.includes(importLine)) {
      contents =
        contents.replace(
          /(\nimport .*\n)/,
          `$1${importLine}\n`
        );
    }

    /*
     * Expo/RN MainApplication contains PackageList(this).packages.
     *
     * We add SmsNativePackage to that list.
     */
    if (!contents.includes("SmsNativePackage()")) {
      contents = contents.replace(
        /PackageList\(this\)\.packages\.apply\s*\{/,
        `PackageList(this).packages.apply {
          add(SmsNativePackage())`
      );
    }

    config.modResults.contents = contents;

    return config;
  });
}

/*
 * Add SMS permissions and SMS_RECEIVED receiver.
 */
function withSmsManifest(config) {
  return withAndroidManifest(config, (config) => {
    const manifest =
      config.modResults.manifest;

    const permissions =
      manifest["uses-permission"] ||
      [];

    const requiredPermissions = [
      "android.permission.RECEIVE_SMS",
      "android.permission.READ_SMS",
      "android.permission.POST_NOTIFICATIONS",
      "android.permission.PACKAGE_USAGE_STATS",
    ];

    for (const permission of requiredPermissions) {
      const exists =
        permissions.some(
          (item) =>
            item.$?.["android:name"] ===
            permission
        );

      if (!exists) {
        permissions.push({
          $: {
            "android:name": permission,
          },
        });
      }
    }

    manifest["uses-permission"] =
      permissions;

    const application =
      manifest.application?.[0];

    if (!application) {
      throw new Error(
        "Android application node not found."
      );
    }

    application.receiver =
      application.receiver || [];

    const alreadyExists =
      application.receiver.some(
        (receiver) =>
          receiver.$?.[
            "android:name"
          ] ===
          ".SmsReceiver"
      );

    if (!alreadyExists) {
      application.receiver.push({
        $: {
          "android:name":
            ".SmsReceiver",
          "android:exported":
            "true",
          "android:permission":
            "android.permission.BROADCAST_SMS",
        },

        "intent-filter": [
          {
            action: [
              {
                $: {
                  "android:name":
                    "android.provider.Telephony.SMS_RECEIVED",
                },
              },
            ],
          },
        ],
      });
    }

    return config;
  });
}

module.exports = function withSmsNative(config) {
  config = withSmsKotlinFiles(config);
  config = withSmsMainApplication(config);
  config = withSmsManifest(config);

  return config;
};
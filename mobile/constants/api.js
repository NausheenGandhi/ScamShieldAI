// constants/api.js
//
// Central place for the backend URL so you don't have to hunt through
// every screen when it changes.
//
// IMPORTANT — pick the right value for how you're running the app:
//
//   iOS Simulator          -> http://127.0.0.1:8000
//   Android Emulator (AVD) -> http://10.0.2.2:8000   (special alias to your host machine)
//   Physical phone (Expo Go / dev build)
//                           -> http://<your-computer's-LAN-IP>:8000
//                              e.g. http://192.168.1.42:8000
//                              (find it with `ipconfig` on Windows / `ifconfig` on Mac-Linux;
//                               phone and computer must be on the same Wi-Fi network)
//
// Also make sure the backend is started with --host 0.0.0.0 so it accepts
// connections from other devices, not just localhost.

export const API_BASE_URL = "http://192.168.31.89:8000";
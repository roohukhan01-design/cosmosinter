#!/usr/bin/env python3
"""Adds what AirLink needs to the AndroidManifest.xml that `cap add android` generates.
Safe to run more than once."""
import re, sys

path = sys.argv[1] if len(sys.argv) > 1 else "android/app/src/main/AndroidManifest.xml"
xml = open(path, encoding="utf-8").read()

perms = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
    "android.permission.WAKE_LOCK",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
    "android.permission.POST_NOTIFICATIONS",
]
add = "".join('    <uses-permission android:name="%s" />\n' % p
              for p in perms if 'android:name="%s"' % p not in xml)
if add:
    xml = xml.replace("</manifest>", "\n" + add + "</manifest>", 1)

if "ShareService" not in xml:
    svc = ('        <service android:name=".ShareService" android:exported="false"\n'
           '            android:foregroundServiceType="dataSync" />\n')
    xml = xml.replace("</application>", svc + "    </application>", 1)

if "android.intent.action.SEND" not in xml:
    flt = ('            <intent-filter>\n'
           '                <action android:name="android.intent.action.SEND" />\n'
           '                <action android:name="android.intent.action.SEND_MULTIPLE" />\n'
           '                <category android:name="android.intent.category.DEFAULT" />\n'
           '                <data android:mimeType="*/*" />\n'
           '            </intent-filter>\n')
    m = re.search(r"</activity>", xml)
    if not m:
        sys.exit("MainActivity not found in manifest")
    xml = xml[:m.start()] + flt + "        " + xml[m.start():]

open(path, "w", encoding="utf-8").write(xml)
print("manifest patched")

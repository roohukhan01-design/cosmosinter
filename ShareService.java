package com.roohu.airlink;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import androidx.core.app.NotificationCompat;

/**
 * Keeps AirLink alive while sharing: foreground notification (with a Stop button),
 * a CPU wake lock and a Wi-Fi lock, so transfers do not die when the screen turns off.
 */
public class ShareService extends Service {

    public static final String ACTION_STOP = "com.roohu.airlink.STOP";
    private static final String CHANNEL = "airlink_share";
    private static final int NOTE_ID = 4711;

    private static volatile Runnable stopper;
    private static volatile String lastText = "Sharing is on";

    private PowerManager.WakeLock wake;
    private WifiManager.WifiLock wifi;

    public static void setStopper(Runnable r) {
        stopper = r;
    }

    public static void start(Context c, String text) {
        lastText = text;
        Intent i = new Intent(c, ShareService.class);
        try {
            if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i);
            else c.startService(i);
        } catch (Exception e) {
            // sharing still works while the app is open
        }
    }

    public static void update(Context c, String text) {
        lastText = text;
        try {
            NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) nm.notify(NOTE_ID, build(c, text));
        } catch (Exception e) {
            // ignore
        }
    }

    public static void stop(Context c) {
        try {
            c.stopService(new Intent(c, ShareService.class));
        } catch (Exception e) {
            // ignore
        }
    }

    private static void ensureChannel(Context c) {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null || nm.getNotificationChannel(CHANNEL) != null) return;
        NotificationChannel ch = new NotificationChannel(CHANNEL, "AirLink sharing", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Shows while AirLink is sharing files");
        ch.setShowBadge(false);
        nm.createNotificationChannel(ch);
    }

    private static Notification build(Context c, String text) {
        ensureChannel(c);
        int imm = Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0;
        NotificationCompat.Builder b = new NotificationCompat.Builder(c, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setContentTitle("AirLink")
                .setContentText(text)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setPriority(NotificationCompat.PRIORITY_LOW);
        Intent open = c.getPackageManager().getLaunchIntentForPackage(c.getPackageName());
        if (open != null) {
            b.setContentIntent(PendingIntent.getActivity(c, 0, open, imm | PendingIntent.FLAG_UPDATE_CURRENT));
        }
        Intent st = new Intent(c, ShareService.class).setAction(ACTION_STOP);
        b.addAction(0, "Stop", PendingIntent.getService(c, 1, st, imm | PendingIntent.FLAG_UPDATE_CURRENT));
        return b.build();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            Runnable r = stopper;
            if (r != null) {
                try {
                    r.run();
                } catch (Exception e) {
                    // ignore
                }
            }
            stopSelf();
            return START_NOT_STICKY;
        }
        Notification n = build(this, lastText);
        try {
            if (Build.VERSION.SDK_INT >= 29) startForeground(NOTE_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
            else startForeground(NOTE_ID, n);
        } catch (Exception e) {
            stopSelf();
            return START_NOT_STICKY;
        }
        acquireLocks();
        return START_NOT_STICKY;
    }

    @SuppressWarnings("deprecation")
    private void acquireLocks() {
        try {
            if (wake == null) {
                PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
                if (pm != null) {
                    wake = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "airlink:share");
                    wake.setReferenceCounted(false);
                    wake.acquire(6L * 60 * 60 * 1000);
                }
            }
            if (wifi == null) {
                WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                if (wm != null) {
                    wifi = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "airlink:wifi");
                    wifi.setReferenceCounted(false);
                    wifi.acquire();
                }
            }
        } catch (Exception e) {
            // not critical
        }
    }

    @Override
    public void onDestroy() {
        try {
            if (wake != null && wake.isHeld()) wake.release();
            if (wifi != null && wifi.isHeld()) wifi.release();
        } catch (Exception e) {
            // ignore
        }
        wake = null;
        wifi = null;
        super.onDestroy();
    }
}

package com.roohu.airlink;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import com.getcapacitor.BridgeActivity;
import com.getcapacitor.PluginHandle;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(LanSharePlugin.class);
        super.onCreate(savedInstanceState);
        askForNotifications();
        deliver(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        deliver(intent);
    }

    /** Files or text shared to AirLink from another app. */
    private void deliver(Intent intent) {
        try {
            PluginHandle h = getBridge().getPlugin("LanShare");
            if (h != null) ((LanSharePlugin) h.getInstance()).ingest(intent);
        } catch (Throwable e) {
            // the app still works without it
        }
    }

    private void askForNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 77);
        }
    }
}

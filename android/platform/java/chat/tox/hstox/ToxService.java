package chat.tox.hstox;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import me.jappie.hatter.HatterCallAudio;
import me.jappie.hatter.HatterNotifications;

/**
 * Keeps the process (and Tox) running without a screen, and the microphone
 * and camera during calls.
 */
public class ToxService extends Service {
    static {
        // Starts Tox when Android restarts only the service.
        System.loadLibrary("hatter");
    }

    private static final String CHANNEL = "connection";
    private static final int NOTIFICATION = 1;
    /** Whether call audio is running. */
    private volatile boolean calling;

    @Override
    public void onCreate() {
        super.onCreate();
        HatterCallAudio.setListener((context, running) -> {
            calling = running;
            foreground();
        });
        HatterNotifications.setOngoingListener(context -> foreground());
        // With stay online off, after hTox is closed. Tox stops with the
        // process, and starts again when hTox is opened.
        HatterNotifications.setStopListener(context -> new Handler(Looper.getMainLooper()).post(() -> {
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            System.exit(0);
        }));
    }

    @Override
    public void onDestroy() {
        HatterCallAudio.setListener(null);
        HatterNotifications.setOngoingListener(null);
        HatterNotifications.setStopListener(null);
        super.onDestroy();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        foreground();
        return START_STICKY;
    }

    private void foreground() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(
            CHANNEL, getString(R.string.connection_channel), NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(
            this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        // The ongoing call (Android only shows it for a foreground service),
        // or else that hTox is running.
        Notification call = HatterNotifications.ongoingCall(this, CHANNEL, R.drawable.ic_call, open);
        Notification notification = call != null ? call : new Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_chat_bubble_outline)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(HatterNotifications.status().isEmpty()
                ? getString(R.string.connection_running) : HatterNotifications.status())
            .setContentIntent(open)
            .setOngoing(true)
            // Own group, so Android doesn't bundle it with the messages.
            .setGroup(CHANNEL)
            .build();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            int types = ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING;
            if (calling) {
                types |= ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
                // Only allowed once the user gave us the camera.
                if (checkSelfPermission(android.Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                    types |= ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA;
                }
            }
            try {
                startForeground(NOTIFICATION, notification, types);
            } catch (SecurityException e) {
                // No microphone permission, so no call audio to keep going.
                startForeground(NOTIFICATION, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING);
            }
        } else {
            startForeground(NOTIFICATION, notification);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}

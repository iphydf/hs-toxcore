package chat.tox.hstox;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import me.jappie.hatter.HatterNotifications;

/** Starts Tox on boot, with stay online on. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())
                && HatterNotifications.runsInBackground(context)) {
            try {
                context.startForegroundService(new Intent(context, ToxService.class));
            } catch (IllegalStateException e) {
                // Android may refuse, e.g. for a boot broadcast it didn't send.
                android.util.Log.w("BootReceiver", "Tox not started: " + e.getMessage());
            }
        }
    }
}

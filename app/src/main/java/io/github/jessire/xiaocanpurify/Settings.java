package io.github.jessire.xiaocanpurify;

import android.content.Context;
import android.database.Cursor;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

/**
 * 功能开关管理。
 *
 * <p>模块 App（设置界面）运行在模块自身进程，直接读写 SharedPreferences；
 * hook 代码运行在目标 App（小蚕霸王餐）进程，通过 {@link SettingsProvider}
 * 跨进程读取开关状态。
 *
 * <p>所有开关默认开启；读取失败时也视为开启，保证老版本行为不受影响。
 * 修改开关后需要重启目标 App 才会生效。
 */
public final class Settings {
    public static final String PREFS_NAME = "xiaocan_purify_settings";

    public static final String KEY_AD_BLOCKER = "ad_blocker";
    public static final String KEY_POPUP_BLOCKER = "popup_blocker";
    public static final String KEY_BOTTOM_BAR = "bottom_bar";
    public static final String KEY_HOME_PAGE = "home_page";
    public static final String KEY_ORDER_PAGE = "order_page";
    public static final String KEY_USER_PAGE = "user_page";
    public static final String KEY_NETWORK = "network_interceptor";
    public static final String KEY_FLUTTER_GUARD = "flutter_guard";

    public static final String[] ALL_KEYS = {
            KEY_AD_BLOCKER, KEY_POPUP_BLOCKER, KEY_BOTTOM_BAR, KEY_HOME_PAGE,
            KEY_ORDER_PAGE, KEY_USER_PAGE, KEY_NETWORK, KEY_FLUTTER_GUARD
    };

    private static volatile Context sContext;
    private static volatile Map<String, Boolean> sCache;

    private Settings() {
    }

    /**
     * 在目标 App 进程的 hook 入口处调用，提供跨进程查询所需的 Context。
     * 传入 null 时会被忽略，开关查询将回退到默认值（全开）。
     */
    public static void init(Context context) {
        if (context != null) {
            sContext = context.getApplicationContext();
        }
    }

    /**
     * hook 侧调用：指定功能是否开启。
     * 结果会被缓存（hook 安装时只读一次），改开关后需重启目标 App。
     */
    public static boolean isEnabled(String key) {
        Map<String, Boolean> cache = sCache;
        if (cache == null) {
            cache = loadAll();
            sCache = cache;
        }
        Boolean v = cache.get(key);
        return v == null || v;
    }

    private static Map<String, Boolean> loadAll() {
        Map<String, Boolean> map = new HashMap<>();
        Context ctx = sContext;
        if (ctx == null) {
            return map;
        }
        Cursor c = null;
        try {
            c = ctx.getContentResolver().query(SettingsProvider.CONTENT_URI,
                    null, null, null, null);
            if (c != null) {
                int ki = c.getColumnIndex("key");
                int vi = c.getColumnIndex("value");
                while (c.moveToNext()) {
                    map.put(c.getString(ki), c.getInt(vi) == 1);
                }
            }
        } catch (Throwable t) {
            Log.w(MainHook.LOG_TAG, "Load purifier settings failed, using defaults: " + t);
        } finally {
            if (c != null) {
                c.close();
            }
        }
        return map;
    }

    /** 设置界面（模块自身进程）调用：读取本地开关，默认开启。 */
    public static boolean isEnabledLocal(Context context, String key) {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(key, true);
    }

    /** 设置界面（模块自身进程）调用：保存本地开关。 */
    public static void setEnabledLocal(Context context, String key, boolean enabled) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit().putBoolean(key, enabled).apply();
    }
}

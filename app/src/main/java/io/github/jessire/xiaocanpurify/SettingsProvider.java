package io.github.jessire.xiaocanpurify;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;

/**
 * 把模块的 SharedPreferences 通过 ContentProvider 暴露给目标 App 进程读取。
 *
 * <p>hook 代码运行在小蚕霸王餐进程，无法直接访问模块 App 的私有 SharedPreferences，
 * 因此通过本 Provider（exported）做一次只读的跨进程查询。
 */
public class SettingsProvider extends ContentProvider {
    public static final String AUTHORITY = "io.github.jessire.xiaocanpurify.settings";
    public static final Uri CONTENT_URI = Uri.parse("content://" + AUTHORITY + "/settings");
    private static final String[] COLUMNS = {"key", "value"};

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(COLUMNS);
        Context ctx = getContext();
        if (ctx != null) {
            SharedPreferences sp = ctx.getSharedPreferences(
                    Settings.PREFS_NAME, Context.MODE_PRIVATE);
            for (String key : Settings.ALL_KEYS) {
                cursor.addRow(new Object[]{key, sp.getBoolean(key, true) ? 1 : 0});
            }
        }
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.dir/vnd.xiaocanpurify.settings";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}

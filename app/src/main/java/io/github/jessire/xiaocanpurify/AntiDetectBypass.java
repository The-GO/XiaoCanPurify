package io.github.jessire.xiaocanpurify;

import android.app.Dialog;
import android.content.pm.PackageManager;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.TextView;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import io.github.libxposed.api.XposedInterface;

/**
 * 反 root / 反 Xposed(LSPosed) 检测。
 *
 * <p>覆盖 Java 层常见检测手段：
 * <ul>
 *   <li>RootBeer 检测库：isRooted / detect* / check* 直接返回 false</li>
 *   <li>Runtime.exec("su")：返回一个 exitCode 非 0 的假 Process</li>
 *   <li>File.exists()：常见 su / busybox 路径返回 false</li>
 *   <li>PackageManager：对 App 隐藏 Magisk / Xposed / LuckyPatcher 等包名</li>
 *   <li>Class.forName("...xposed...")：抛 ClassNotFoundException</li>
 *   <li>堆栈检测：过滤掉含 xposed / lsposed 的堆栈帧</li>
 *   <li>ro.build.tags=test-keys：伪装成 release-keys</li>
 *   <li>兜底：自动关闭文案含"root/外挂/环境异常"的检测弹窗</li>
 * </ul>
 *
 * <p>installEarly() 只依赖系统类，不需要目标 ClassLoader，可在加固解密前安装，
 * 用于对抗 Application.onCreate 中的检测；installLate() 需要目标 ClassLoader，
 * 用于 hook App 内自带的检测库（如 RootBeer）。
 *
 * <p>注意：Native 层检测（如加固壳自身的 so 检测）无法在 Java 层绕过，
 * 若 App 采用此类检测，需要配合 Shamiko 等方案。
 */
public final class AntiDetectBypass {

    private static final Set<String> SU_PATHS = new HashSet<>(Arrays.asList(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/su/bin/su", "/system/app/Superuser.apk", "/sbin/supersu",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu", "/system/bin/.ext/su",
            "/vendor/bin/su", "/odm/bin/su",
            "/system/bin/busybox", "/system/xbin/busybox"
    ));

    private static final Set<String> ROOT_PACKAGES = new HashSet<>(Arrays.asList(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "org.meowcat.edxposed.manager",
            "com.solohsu.android.edxp.manager",
            "com.tsng.hidemyapplist"
    ));

    /** 弹窗文案第一组关键词：命中其一即可疑 */
    private static final String[] KEYWORDS_A = {
            "root", "magisk", "xposed", "lsposed", "外挂", "环境异常"
    };
    /** 弹窗文案第二组关键词：需与第一组同时命中，避免误杀正常弹窗 */
    private static final String[] KEYWORDS_B = {
            "检测", "异常", "风险", "安全", "警告"
    };

    private AntiDetectBypass() {
    }

    /** 系统类 hook，不依赖目标 ClassLoader，可尽早安装。 */
    public static void installEarly(XposedInterface xposed) {
        hookRuntimeExec(xposed);
        hookFileExists(xposed);
        hookClassForName(xposed);
        hookStackTrace(xposed);
        hookSystemProperties(xposed);
        hookPackageManager(xposed);
        hookDialogShow(xposed);
        MainHook.log("AntiDetectBypass: early hooks installed");
    }

    /** App 内自带检测库（如 RootBeer）的 hook，需要目标 ClassLoader。 */
    public static void installLate(XposedInterface xposed, ClassLoader cl) {
        hookRootBeer(xposed, cl);
    }

    // ---------------- RootBeer ----------------

    private static void hookRootBeer(XposedInterface xposed, ClassLoader cl) {
        try {
            Class<?> rb = Class.forName("com.scottyab.rootbeer.RootBeer", false, cl);
            int hooked = 0;
            for (Method m : rb.getDeclaredMethods()) {
                if (m.getReturnType() != boolean.class) {
                    continue;
                }
                String n = m.getName();
                if (n.equals("isRooted") || n.startsWith("detect") || n.startsWith("check")) {
                    xposed.hook(m).intercept(chain -> Boolean.FALSE);
                    hooked++;
                }
            }
            MainHook.log("AntiDetectBypass: hooked RootBeer (" + hooked + " methods)");
        } catch (Throwable ignored) {
            // App 未集成 RootBeer，无需处理
        }
    }

    // ---------------- Runtime.exec("su") ----------------

    private static void hookRuntimeExec(XposedInterface xposed) {
        try {
            for (Method m : Runtime.class.getDeclaredMethods()) {
                if (!"exec".equals(m.getName())) {
                    continue;
                }
                xposed.hook(m).intercept(chain -> {
                    Object arg0 = chain.getArg(0);
                    String cmd = null;
                    if (arg0 instanceof String) {
                        cmd = (String) arg0;
                    } else if (arg0 instanceof String[]) {
                        StringBuilder sb = new StringBuilder();
                        for (String s : (String[]) arg0) {
                            sb.append(s).append(' ');
                        }
                        cmd = sb.toString();
                    }
                    if (cmd != null && isSuCommand(cmd)) {
                        MainHook.log("AntiDetectBypass: blocked su exec: " + cmd.trim());
                        return new DeniedProcess();
                    }
                    return chain.proceed();
                });
            }
        } catch (Throwable t) {
            MainHook.log("AntiDetectBypass: hook Runtime.exec failed: " + t);
        }
    }

    private static boolean isSuCommand(String cmd) {
        String lower = cmd.toLowerCase(Locale.ROOT).trim();
        return lower.equals("su")
                || lower.startsWith("su ")
                || lower.contains(" su ")
                || lower.endsWith(" su")
                || lower.contains("/su")
                || (lower.startsWith("which ") && lower.contains("su"));
    }

    /** exitCode 非 0 的假 Process，让 "su 是否可用" 的判断走失败分支。 */
    private static class DeniedProcess extends Process {
        @Override
        public OutputStream getOutputStream() {
            return new ByteArrayOutputStream();
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(new byte[0]);
        }

        @Override
        public InputStream getErrorStream() {
            return new ByteArrayInputStream(new byte[0]);
        }

        @Override
        public int waitFor() {
            return 1;
        }

        @Override
        public int exitValue() {
            return 1;
        }

        @Override
        public void destroy() {
        }
    }

    // ---------------- File.exists() su 路径 ----------------

    private static void hookFileExists(XposedInterface xposed) {
        try {
            Method exists = File.class.getDeclaredMethod("exists");
            xposed.hook(exists).intercept(chain -> {
                File f = (File) chain.getThisObject();
                if (f != null) {
                    String path = f.getPath();
                    if (SU_PATHS.contains(path) || SU_PATHS.contains(f.getAbsolutePath())) {
                        return Boolean.FALSE;
                    }
                }
                return chain.proceed();
            });
        } catch (Throwable t) {
            MainHook.log("AntiDetectBypass: hook File.exists failed: " + t);
        }
    }

    // ---------------- Class.forName xposed 检测 ----------------

    private static void hookClassForName(XposedInterface xposed) {
        try {
            for (Method m : Class.class.getDeclaredMethods()) {
                if (!"forName".equals(m.getName())) {
                    continue;
                }
                xposed.hook(m).intercept(chain -> {
                    Object arg0 = chain.getArg(0);
                    if (arg0 instanceof String) {
                        String name = (String) arg0;
                        if (name.toLowerCase(Locale.ROOT).contains("xposed")) {
                            throw new ClassNotFoundException(name);
                        }
                    }
                    return chain.proceed();
                });
            }
        } catch (Throwable t) {
            MainHook.log("AntiDetectBypass: hook Class.forName failed: " + t);
        }
    }

    // ---------------- 堆栈检测 ----------------

    private static void hookStackTrace(XposedInterface xposed) {
        try {
            Method threadST = Thread.class.getDeclaredMethod("getStackTrace");
            xposed.hook(threadST).intercept(chain ->
                    filterStack((StackTraceElement[]) chain.proceed()));
        } catch (Throwable t) {
            MainHook.log("AntiDetectBypass: hook Thread.getStackTrace failed: " + t);
        }
        try {
            Method throwableST = Throwable.class.getDeclaredMethod("getStackTrace");
            xposed.hook(throwableST).intercept(chain ->
                    filterStack((StackTraceElement[]) chain.proceed()));
        } catch (Throwable t) {
            MainHook.log("AntiDetectBypass: hook Throwable.getStackTrace failed: " + t);
        }
    }

    private static StackTraceElement[] filterStack(StackTraceElement[] orig) {
        if (orig == null) {
            return new StackTraceElement[0];
        }
        List<StackTraceElement> kept = new ArrayList<>(orig.length);
        for (StackTraceElement e : orig) {
            String cn = e.getClassName();
            if (cn == null) {
                continue;
            }
            String lower = cn.toLowerCase(Locale.ROOT);
            if (lower.contains("xposed") || lower.contains("lsposed") || lower.contains("edxposed")) {
                continue;
            }
            kept.add(e);
        }
        return kept.toArray(new StackTraceElement[0]);
    }

    // ---------------- ro.build.tags ----------------

    private static void hookSystemProperties(XposedInterface xposed) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            for (Method m : sp.getDeclaredMethods()) {
                if (!"get".equals(m.getName())) {
                    continue;
                }
                Class<?>[] ps = m.getParameterTypes();
                if (ps.length != 1 || ps[0] != String.class) {
                    continue;
                }
                xposed.hook(m).intercept(chain -> {
                    Object res = chain.proceed();
                    if ("ro.build.tags".equals(chain.getArg(0))
                            && res instanceof String
                            && ((String) res).contains("test-keys")) {
                        return "release-keys";
                    }
                    return res;
                });
            }
        } catch (Throwable t) {
            MainHook.log("AntiDetectBypass: hook SystemProperties failed: " + t);
        }
    }

    // ---------------- PackageManager 藏包 ----------------

    private static void hookPackageManager(XposedInterface xposed) {
        try {
            Class<?> apm = Class.forName("android.app.ApplicationPackageManager");
            for (Method m : apm.getDeclaredMethods()) {
                String n = m.getName();
                if ("getInstalledPackages".equals(n) || "getInstalledApplications".equals(n)) {
                    xposed.hook(m).intercept(chain -> filterPackageList(chain.proceed()));
                } else if ("getPackageInfo".equals(n)) {
                    xposed.hook(m).intercept(chain -> {
                        Object arg0 = chain.getArg(0);
                        if (arg0 instanceof String && ROOT_PACKAGES.contains(arg0)) {
                            throw new PackageManager.NameNotFoundException((String) arg0);
                        }
                        return chain.proceed();
                    });
                }
            }
        } catch (Throwable t) {
            MainHook.log("AntiDetectBypass: hook PackageManager failed: " + t);
        }
    }

    private static Object filterPackageList(Object res) {
        if (!(res instanceof List)) {
            return res;
        }
        List<?> src = (List<?>) res;
        List<Object> out = new ArrayList<>(src.size());
        for (Object item : src) {
            if (!isRootPackage(item)) {
                out.add(item);
            }
        }
        return out;
    }

    private static boolean isRootPackage(Object info) {
        try {
            Field f = info.getClass().getField("packageName");
            Object pn = f.get(info);
            return pn instanceof String && ROOT_PACKAGES.contains(pn);
        } catch (Throwable t) {
            return false;
        }
    }

    // ---------------- 检测弹窗兜底 ----------------

    private static void hookDialogShow(XposedInterface xposed) {
        try {
            Method show = Dialog.class.getDeclaredMethod("show");
            xposed.hook(show).intercept(chain -> {
                Object res = chain.proceed();
                Dialog dlg = (Dialog) chain.getThisObject();
                try {
                    if (dlg != null && mentionsDetection(dlg)) {
                        MainHook.log("AntiDetectBypass: dismissed root-detection dialog");
                        dlg.dismiss();
                    }
                } catch (Throwable t) {
                    MainHook.log("AntiDetectBypass: dialog check error: " + t);
                }
                return res;
            });
        } catch (Throwable t) {
            MainHook.log("AntiDetectBypass: hook Dialog.show failed: " + t);
        }
    }

    private static boolean mentionsDetection(Dialog dlg) {
        try {
            Window w = dlg.getWindow();
            if (w == null) {
                return false;
            }
            View decor = w.getDecorView();
            if (decor == null) {
                return false;
            }
            return scanText(decor);
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean scanText(View v) {
        if (v instanceof TextView) {
            CharSequence cs = ((TextView) v).getText();
            if (cs != null) {
                String s = cs.toString().toLowerCase(Locale.ROOT);
                boolean hitA = false;
                for (String kw : KEYWORDS_A) {
                    if (s.contains(kw)) {
                        hitA = true;
                        break;
                    }
                }
                if (hitA) {
                    for (String kw : KEYWORDS_B) {
                        if (s.contains(kw)) {
                            return true;
                        }
                    }
                }
            }
        }
        if (v instanceof ViewGroup) {
            ViewGroup g = (ViewGroup) v;
            for (int i = 0; i < g.getChildCount(); i++) {
                if (scanText(g.getChildAt(i))) {
                    return true;
                }
            }
        }
        return false;
    }
}

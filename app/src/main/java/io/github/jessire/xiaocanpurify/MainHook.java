package io.github.jessire.xiaocanpurify;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public final class MainHook extends XposedModule {
    public static final String TARGET_PACKAGE = "com.realtech.xiaocan";
    public static final String LOG_TAG = "XiaoCanPurify";
    private static final AtomicBoolean HOOKED = new AtomicBoolean(false);
    private static final AtomicBoolean EARLY_HOOKED = new AtomicBoolean(false);
    private static volatile MainHook instance;

    @Override
    public void onModuleLoaded(XposedModuleInterface.ModuleLoadedParam param) {
        instance = this;
        log("XiaoCanPurify API 102 module loaded.");
    }

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        if (!TARGET_PACKAGE.equals(param.getPackageName())) {
            return;
        }
        instance = this;
        log("Target package ready: " + param.getPackageName());

        Settings.init(currentAppContext());

        ClassLoader initialLoader = param.getClassLoader();
        if (canLoadTargetClasses(initialLoader)) {
            installAll(this, initialLoader);
            return;
        }

        // App uses ShellApplication / Aliyun Jiagu unpacker, hook Application & Activity lifecycle
        hookLifecycle(this);
    }

    private static boolean canLoadTargetClasses(ClassLoader cl) {
        if (cl == null) return false;
        try {
            Class.forName("com.realtech.xiaocan.MainActivity", false, cl);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    /**
     * Best-effort Application Context via ActivityThread.
     * May return null if called before the app is attached; callers must tolerate null.
     */
    private static Context currentAppContext() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Method m = at.getMethod("currentApplication");
            Object app = m.invoke(null);
            return (Context) app;
        } catch (Throwable t) {
            return null;
        }
    }

    private void hookLifecycle(XposedInterface xposed) {
        try {
            Method attachBaseContext = Application.class.getDeclaredMethod("attachBaseContext", Context.class);
            xposed.hook(attachBaseContext).intercept(chain -> {
                Context context = (Context) chain.getArg(0);
                if (context != null) {
                    Settings.init(context);
                    installEarlyHooks(xposed);
                }
                Object result = chain.proceed();
                if (context != null) {
                    ClassLoader cl = context.getClassLoader();
                    if (canLoadTargetClasses(cl)) {
                        installAll(xposed, cl);
                    }
                }
                return result;
            });
        } catch (Throwable t) {
            log("Hook Application.attachBaseContext failed: " + t);
        }

        try {
            Method onCreate = Application.class.getDeclaredMethod("onCreate");
            xposed.hook(onCreate).intercept(chain -> {
                Object result = chain.proceed();
                Application app = (Application) chain.getThisObject();
                if (app != null) {
                    Settings.init(app);
                    ClassLoader cl = app.getClassLoader();
                    if (canLoadTargetClasses(cl)) {
                        installAll(xposed, cl);
                    }
                }
                return result;
            });
        } catch (Throwable t) {
            log("Hook Application.onCreate failed: " + t);
        }

        try {
            Method actOnCreate = Activity.class.getDeclaredMethod("onCreate", Bundle.class);
            xposed.hook(actOnCreate).intercept(chain -> {
                Activity activity = (Activity) chain.getThisObject();
                if (activity != null) {
                    Settings.init(activity);
                    ClassLoader cl = activity.getClassLoader();
                    if (canLoadTargetClasses(cl)) {
                        installAll(xposed, cl);
                    }
                }
                return chain.proceed();
            });
        } catch (Throwable t) {
            log("Hook Activity.onCreate failed: " + t);
        }
    }

    /**
     * 安装不依赖目标 ClassLoader 的系统级 hook（反检测）。
     * 在 Application.attachBaseContext 之前执行，早于 App 自身的 onCreate，
     * 因此能对抗 App 启动期的 root/框架检测。只安装一次。
     */
    private static void installEarlyHooks(XposedInterface xposed) {
        if (!EARLY_HOOKED.compareAndSet(false, true)) {
            return;
        }
        if (!Settings.isEnabled(Settings.KEY_ANTI_DETECTION)) {
            log("AntiDetectBypass disabled by settings, skipped.");
            return;
        }
        try {
            AntiDetectBypass.installEarly(xposed);
            log("AntiDetectBypass early hooks installed.");
        } catch (Throwable t) {
            log("AntiDetectBypass early install error: " + t);
        }
    }

    public static synchronized void installAll(XposedInterface xposed, ClassLoader classLoader) {
        if (!HOOKED.compareAndSet(false, true)) {
            return;
        }
        log("Target classes available, installing purifier hooks with ClassLoader: " + classLoader);

        if (Settings.isEnabled(Settings.KEY_ANTI_DETECTION)) {
            try {
                AntiDetectBypass.installLate(xposed, classLoader);
                log("AntiDetectBypass late hooks installed.");
            } catch (Throwable t) {
                log("AntiDetectBypass late install error: " + t);
            }
        } else {
            log("AntiDetectBypass disabled by settings, skipped.");
        }

        if (Settings.isEnabled(Settings.KEY_AD_BLOCKER)) {
            try {
                AdBlocker.install(xposed, classLoader);
                log("AdBlocker installed successfully.");
            } catch (Throwable t) {
                log("AdBlocker install error: " + t);
            }
        } else {
            log("AdBlocker disabled by settings, skipped.");
        }

        if (Settings.isEnabled(Settings.KEY_POPUP_BLOCKER)) {
            try {
                PopupBlocker.install(xposed, classLoader);
                log("PopupBlocker installed successfully.");
            } catch (Throwable t) {
                log("PopupBlocker install error: " + t);
            }
        } else {
            log("PopupBlocker disabled by settings, skipped.");
        }

        if (Settings.isEnabled(Settings.KEY_BOTTOM_BAR)) {
            try {
                BottomBarPurifier.install(xposed, classLoader);
                log("BottomBarPurifier installed successfully.");
            } catch (Throwable t) {
                log("BottomBarPurifier install error: " + t);
            }
        } else {
            log("BottomBarPurifier disabled by settings, skipped.");
        }

        if (Settings.isEnabled(Settings.KEY_HOME_PAGE)) {
            try {
                HomePagePurifier.install(xposed, classLoader);
                log("HomePagePurifier installed successfully.");
            } catch (Throwable t) {
                log("HomePagePurifier install error: " + t);
            }
        } else {
            log("HomePagePurifier disabled by settings, skipped.");
        }

        if (Settings.isEnabled(Settings.KEY_ORDER_PAGE)) {
            try {
                OrderPagePurifier.install(xposed, classLoader);
                log("OrderPagePurifier installed successfully.");
            } catch (Throwable t) {
                log("OrderPagePurifier install error: " + t);
            }
        } else {
            log("OrderPagePurifier disabled by settings, skipped.");
        }

        if (Settings.isEnabled(Settings.KEY_USER_PAGE)) {
            try {
                UserPagePurifier.install(xposed, classLoader);
                log("UserPagePurifier installed successfully.");
            } catch (Throwable t) {
                log("UserPagePurifier install error: " + t);
            }
        } else {
            log("UserPagePurifier disabled by settings, skipped.");
        }

        if (Settings.isEnabled(Settings.KEY_NETWORK)) {
            try {
                NetworkAdInterceptor.install(xposed, classLoader);
                log("NetworkAdInterceptor installed successfully.");
            } catch (Throwable t) {
                log("NetworkAdInterceptor install error: " + t);
            }
        } else {
            log("NetworkAdInterceptor disabled by settings, skipped.");
        }


        if (Settings.isEnabled(Settings.KEY_FLUTTER_GUARD)) {
            try {
                FlutterPageGuard.install(xposed, classLoader);
                log("FlutterPageGuard installed successfully.");
            } catch (Throwable t) {
                log("FlutterPageGuard install error: " + t);
            }
        } else {
            log("FlutterPageGuard disabled by settings, skipped.");
        }

        log("All XiaoCanPurify hooks successfully initialized!");
    }

    public static void log(String message) {
        MainHook hook = instance;
        if (hook != null) {
            try {
                hook.log(Log.INFO, LOG_TAG, message);
                return;
            } catch (Throwable ignored) {
            }
        }
        Log.i(LOG_TAG, message);
    }
}

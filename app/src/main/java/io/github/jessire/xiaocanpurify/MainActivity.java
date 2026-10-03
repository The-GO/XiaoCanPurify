package io.github.jessire.xiaocanpurify;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final String[][] ITEMS = {
            {Settings.KEY_AD_BLOCKER, "广告拦截", "开屏/插屏/信息流/Flutter 广告、静默任务等"},
            {Settings.KEY_POPUP_BLOCKER, "弹窗拦截", "营销/红包/升级/元宝等各类弹窗"},
            {Settings.KEY_BOTTOM_BAR, "底部导航精简", "移除「会员」「福利」标签，只留首页/订单/我"},
            {Settings.KEY_HOME_PAGE, "首页净化", "红包悬浮球/新手引导/Banner/推广卡片"},
            {Settings.KEY_ORDER_PAGE, "订单页净化", "订单列表中的广告位清理"},
            {Settings.KEY_USER_PAGE, "我的页净化", "个人中心推广模块清理"},
            {Settings.KEY_NETWORK, "网络层过滤", "拦截广告配置与埋点上报请求"},
            {Settings.KEY_FLUTTER_GUARD, "Flutter 页面守卫", "拦截广告/营销类 Flutter 路由跳转"},
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scrollView = new ScrollView(this);
        scrollView.setBackgroundColor(Color.parseColor("#F6F7F9"));
        scrollView.setFitsSystemWindows(true);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = dp2px(20);
        layout.setPadding(pad, dp2px(24), pad, pad);

        // Header Title
        TextView title = new TextView(this);
        title.setText("小蚕净化");
        title.setTextSize(24);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(Color.parseColor("#1A1A1A"));
        layout.addView(title);

        TextView subTitle = new TextView(this);
        subTitle.setText("小蚕霸王餐 Xposed / LSPosed 净化模块");
        subTitle.setTextSize(13);
        subTitle.setTextColor(Color.parseColor("#888888"));
        subTitle.setPadding(0, dp2px(4), 0, dp2px(16));
        layout.addView(subTitle);

        // Status Card
        LinearLayout statusCard = createCard();
        TextView statusBadge = new TextView(this);
        statusBadge.setText("● 模块已就绪");
        statusBadge.setTextSize(15);
        statusBadge.setTypeface(Typeface.DEFAULT_BOLD);
        statusBadge.setTextColor(Color.parseColor("#07C160"));
        statusCard.addView(statusBadge);

        TextView statusDesc = new TextView(this);
        statusDesc.setText("目标应用: com.realtech.xiaocan (小蚕霸王餐)\n在 LSPosed 勾选小蚕霸王餐后重启小蚕即可生效。");
        statusDesc.setTextSize(13);
        statusDesc.setTextColor(Color.parseColor("#555555"));
        statusDesc.setPadding(0, dp2px(6), 0, 0);
        statusCard.addView(statusDesc);
        layout.addView(statusCard);

        // Section Title
        TextView sectionTitle = new TextView(this);
        sectionTitle.setText("功能开关");
        sectionTitle.setTextSize(16);
        sectionTitle.setTypeface(Typeface.DEFAULT_BOLD);
        sectionTitle.setTextColor(Color.parseColor("#333333"));
        sectionTitle.setPadding(0, dp2px(16), 0, dp2px(8));
        layout.addView(sectionTitle);

        for (String[] item : ITEMS) {
            layout.addView(createSwitchCard(item[0], item[1], item[2]));
        }

        // Footer note
        TextView footer = new TextView(this);
        footer.setText("修改开关后，需强制停止并重启「小蚕霸王餐」才会生效。");
        footer.setTextSize(12);
        footer.setTextColor(Color.parseColor("#999999"));
        footer.setPadding(0, dp2px(4), 0, 0);
        layout.addView(footer);

        scrollView.addView(layout);
        setContentView(scrollView);
    }

    private LinearLayout createCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundColor(Color.WHITE);
        int p = dp2px(14);
        card.setPadding(p, p, p, p);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, dp2px(12));
        card.setLayoutParams(lp);
        return card;
    }

    private LinearLayout createSwitchCard(final String key, String title, String desc) {
        LinearLayout card = createCard();
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setGravity(Gravity.CENTER_VERTICAL);

        LinearLayout textLayout = new LinearLayout(this);
        textLayout.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        textLayout.setLayoutParams(tlp);

        TextView t = new TextView(this);
        t.setText(title);
        t.setTextSize(14);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setTextColor(Color.parseColor("#222222"));
        textLayout.addView(t);

        TextView d = new TextView(this);
        d.setText(desc);
        d.setTextSize(12);
        d.setTextColor(Color.parseColor("#666666"));
        d.setPadding(0, dp2px(4), 0, 0);
        textLayout.addView(d);

        Switch sw = new Switch(this);
        sw.setChecked(Settings.isEnabledLocal(this, key));
        sw.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                Settings.setEnabledLocal(MainActivity.this, key, isChecked);
            }
        });

        card.addView(textLayout);
        card.addView(sw);
        return card;
    }

    private int dp2px(float dp) {
        float scale = getResources().getDisplayMetrics().density;
        return (int) (dp * scale + 0.5f);
    }
}

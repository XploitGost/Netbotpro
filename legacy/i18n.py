# i18n.py
# -*- coding: utf-8 -*-

STRINGS = {
    "en": {
        "app.title": "netbotpro - Kali Edition",

        "tab.dashboard": "Dashboard",
        "tab.sniffer": "Sniffer",
        "tab.alerts": "Alerts",
        "tab.stats": "Stats / Graph",
        "tab.traceroute": "TraceRoute",
        "tab.offline": "Offline Analyzer",
        "tab.logs": "Logs / History",
        "tab.rules": "IDS Rules",
        "tab.settings": "Settings",
        "tab.about": "About",

        "sniffer.heading": "SNIFFER // LIVE WIRED TRAFFIC",
        "sniffer.btn.start": "Start",
        "sniffer.btn.stop": "Stop",
        "sniffer.btn.clear": "Clear",
        "sniffer.btn.export_html": "Export HTML report",
        "sniffer.filter.label": "Filter expression:",
        "sniffer.filter.apply": "Apply",
        "sniffer.filter.reset": "Reset",
        "sniffer.details": "Packet details",
        "sniffer.log": "Live log",

        "alerts.heading": "ALERTS // IDS / ML / RULES",
        "alerts.btn.clear": "Clear alerts",

        "stats.heading": "STATISTICS / CHARTS",
        "stats.ml.panel": "ML IDS Status",

        "tr.heading": "TraceRoute (Linux / scapy based)",
        "tr.target": "Target:",
        "tr.run": "Run",

        "off.heading": "Offline PCAP Analyzer",
        "off.btn.browse": "Browse",
        "off.btn.analyze": "Analyze",
        "off.table": "Alerts from PCAP",

        "logs.heading": "Logs / History (SQLite)",
        "logs.btn.refresh": "Refresh",
        "logs.btn.open_folder": "Open logs folder",
        "logs.btn.exp_csv": "Export packets CSV",
        "logs.btn.exp_xlsx": "Export packets Excel",
        "logs.btn.exp_pdf": "Export alerts PDF",
        "logs.btn.exp_html": "Export full HTML report",
        "logs.table.packets": "Recent packets",
        "logs.table.alerts": "Recent alerts",

        "rules.heading": "IDS Rules (rules.json)",
        "rules.btn.load": "Reload from file",
        "rules.btn.save": "Save",
        "rules.info": "Edit rules.json here. Make sure it stays valid JSON.",

        "settings.heading": "Settings",
        "settings.general": "General",
        "settings.ids": "IDS / ML",
        "settings.ui": "UI / Logs",
        "settings.btn.save": "Save settings",

        "about.text": (
            "netbotpro – Kali Edition\n"
            "Advanced network sniffer + IDS + traceroute + offline analyzer\n"
            "Optimized UI for Kali / Linux."
        ),

        "msg.sniffer.failed": "Failed to start sniffer",
        "msg.sniffer.no_data": "No data to export yet.",
        "msg.filter.invalid": "Invalid filter expression",
        "msg.offline.no_file": "Please select a PCAP file.",
        "msg.offline.failed": "Failed to analyze PCAP",
        "msg.settings.saved": "Settings saved. Theme will apply on next restart.",
    },

    "fa": {
        "app.title": "netbotpro - نسخه کالی",

        "tab.dashboard": "داشبورد",
        "tab.sniffer": "شنود زنده",
        "tab.alerts": "هشدارها",
        "tab.stats": "آمار / نمودار",
        "tab.traceroute": "تریس‌رَوت",
        "tab.offline": "آنالیز آفلاین",
        "tab.logs": "لاگ‌ها / تاریخچه",
        "tab.rules": "قوانین IDS",
        "tab.settings": "تنظیمات",
        "tab.about": "درباره",

        "sniffer.heading": "شنود زنده ترافیک شبکه",
        "sniffer.btn.start": "شروع",
        "sniffer.btn.stop": "توقف",
        "sniffer.btn.clear": "پاک کردن جدول",
        "sniffer.btn.export_html": "خروجی گزارش HTML",
        "sniffer.filter.label": "عبارت فیلتر:",
        "sniffer.filter.apply": "اعمال",
        "sniffer.filter.reset": "حذف فیلتر",
        "sniffer.details": "جزئیات پکت",
        "sniffer.log": "لاگ زنده",

        "alerts.heading": "هشدارها (امضایی / Rule / ML)",
        "alerts.btn.clear": "پاک کردن هشدارها",

        "stats.heading": "آمار و نمودارها",
        "stats.ml.panel": "وضعیت IDS مبتنی بر ML",

        "tr.heading": "تریس‌رَوت (مبتنی بر لینوکس / scapy)",
        "tr.target": "مقصد:",
        "tr.run": "اجرا",

        "off.heading": "آنالیز فایل PCAP",
        "off.btn.browse": "انتخاب فایل",
        "off.btn.analyze": "آنالیز",
        "off.table": "هشدارهای استخراج‌شده از PCAP",

        "logs.heading": "لاگ‌ها / تاریخچه (SQLite)",
        "logs.btn.refresh": "به‌روزرسانی",
        "logs.btn.open_folder": "باز کردن پوشه لاگ",
        "logs.btn.exp_csv": "خروجی CSV پکت‌ها",
        "logs.btn.exp_xlsx": "خروجی Excel پکت‌ها",
        "logs.btn.exp_pdf": "خروجی PDF هشدارها",
        "logs.btn.exp_html": "گزارش کامل HTML",
        "logs.table.packets": "پکت‌های اخیر",
        "logs.table.alerts": "هشدارهای اخیر",

        "rules.heading": "قوانین IDS (فایل rules.json)",
        "rules.btn.load": "لود از فایل",
        "rules.btn.save": "ذخیره قوانین",
        "rules.info": "قوانین را اینجا به‌صورت JSON ویرایش کنید. ساختار JSON معتبر باشد.",

        "settings.heading": "تنظیمات",
        "settings.general": "عمومی",
        "settings.ids": "IDS / ML",
        "settings.ui": "رابط کاربری / لاگ",
        "settings.btn.save": "ذخیره تنظیمات",

        "about.text": (
            "netbotpro – نسخه کالی\n"
            "شنودگر شبکه + IDS + تریس‌رَوت + آنالیز آفلاین\n"
            "بهینه شده برای Kali / لینوکس."
        ),

        "msg.sniffer.failed": "اجرای Sniffer با خطا مواجه شد.",
        "msg.sniffer.no_data": "هنوز داده‌ای برای خروجی گرفتن وجود ندارد.",
        "msg.filter.invalid": "عبارت فیلتر نامعتبر است.",
        "msg.offline.no_file": "لطفاً فایل PCAP را انتخاب کنید.",
        "msg.offline.failed": "آنالیز PCAP با خطا مواجه شد.",
        "msg.settings.saved": "تنظیمات ذخیره شد. تم بعد از اجرای مجدد اعمال می‌شود.",
    },
}


def tr(key: str, lang: str = "en") -> str:
    lang_map = STRINGS.get(lang, STRINGS["en"])
    return lang_map.get(key, STRINGS["en"].get(key, key))

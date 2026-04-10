# themes.py
# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk

DARK_THEME = {
    "bg": "#050816",
    "fg": "#e5e7eb",
    "panel_bg": "#0b1120",
    "table_bg": "#020617",
    "table_alt": "#111827",
    "accent": "#22c55e",
    "danger": "#ef4444",
}

LIGHT_THEME = {
    "bg": "#f9fafb",
    "fg": "#111827",
    "panel_bg": "#ffffff",
    "table_bg": "#ffffff",
    "table_alt": "#e5e7eb",
    "accent": "#2563eb",
    "danger": "#ef4444",
}


def apply_theme(root: tk.Misc, theme_name: str = "dark") -> dict:
    theme = DARK_THEME if theme_name != "light" else LIGHT_THEME
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    try:
        root.configure(bg=theme["bg"])
    except Exception:
        pass

    style.configure("TFrame", background=theme["bg"])
    style.configure("Panel.TFrame", background=theme["panel_bg"])

    style.configure("TLabel", background=theme["panel_bg"], foreground=theme["fg"])
    style.configure("Header.TLabel", background=theme["bg"], foreground=theme["accent"])

    style.configure("TLabelframe", background=theme["panel_bg"], foreground=theme["fg"])
    style.configure(
        "TLabelframe.Label", background=theme["panel_bg"], foreground=theme["fg"]
    )

    style.configure("TButton", padding=4)

    style.configure("TNotebook", background=theme["bg"], borderwidth=0)
    style.configure(
        "TNotebook.Tab",
        background=theme["panel_bg"],
        foreground=theme["fg"],
        padding=(8, 4),
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", theme["bg"])],
        foreground=[("selected", theme["accent"])],
    )

    style.configure(
        "Treeview",
        background=theme["table_bg"],
        fieldbackground=theme["table_bg"],
        foreground=theme["fg"],
        rowheight=20,
    )
    style.configure(
        "Treeview.Heading",
        background=theme["panel_bg"],
        foreground=theme["fg"],
    )

    return theme

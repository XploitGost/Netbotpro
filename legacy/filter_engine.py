# filter_engine.py
# -*- coding: utf-8 -*-
"""
Engine ساده برای فیلتر روی meta پکت‌ها.

پشتیبانی از عبارت‌هایی مثل:
  ip=192.168.1.1
  src=10.0.0.5
  dst=8.8.8.8
  proto=TCP
  country=DE
  org=Google
  port=80
  sport=53
  dport=443
و ترکیب با AND:
  src=192.168.1.10 AND dport=443
"""

def _normalize(s):
    if s is None:
        return ""
    return str(s).strip().lower()


def make_packet_filter(expr: str):
    """
    expr → string فیلتر.
    خروجی: تابعی که meta را می‌گیرد و True/False برمی‌گرداند.
    اگر expr خالی یا نامعتبر باشد → همه‌چیز را قبول می‌کند.
    """

    if not expr:
        return lambda meta: True

    # ساده: به صورت "cond AND cond AND cond"
    parts = [p.strip() for p in expr.split("AND") if p.strip()]
    conditions = []

    for p in parts:
        if "=" not in p:
            continue
        key, val = p.split("=", 1)
        key = key.strip().lower()
        val = val.strip()

        if not key or not val:
            continue

        # هر condition خودش یک تابع است
        if key == "ip":
            v = val
            def cond(meta, v=v):
                s = _normalize(meta.get("src"))
                d = _normalize(meta.get("dst"))
                vv = _normalize(v)
                return vv == s or vv == d
        elif key == "src":
            v = val
            def cond(meta, v=v):
                return _normalize(meta.get("src")) == _normalize(v)
        elif key == "dst":
            v = val
            def cond(meta, v=v):
                return _normalize(meta.get("dst")) == _normalize(v)
        elif key in ("proto", "protocol"):
            v = val
            def cond(meta, v=v):
                return _normalize(meta.get("proto")) == _normalize(v)
        elif key == "country":
            v = val
            def cond(meta, v=v):
                return _normalize(meta.get("country")) == _normalize(v)
        elif key == "org":
            v = val
            def cond(meta, v=v):
                return _normalize(v) in _normalize(meta.get("org"))
        elif key == "port":
            try:
                v_int = int(val)
            except ValueError:
                continue
            def cond(meta, v_int=v_int):
                return int(meta.get("sport") or 0) == v_int or int(meta.get("dport") or 0) == v_int
        elif key == "sport":
            try:
                v_int = int(val)
            except ValueError:
                continue
            def cond(meta, v_int=v_int):
                return int(meta.get("sport") or 0) == v_int
        elif key == "dport":
            try:
                v_int = int(val)
            except ValueError:
                continue
            def cond(meta, v_int=v_int):
                return int(meta.get("dport") or 0) == v_int
        else:
            # فیلد ناشناخته → contains روی summary
            v = val
            def cond(meta, v=v):
                return _normalize(v) in _normalize(meta.get("summary"))

        conditions.append(cond)

    if not conditions:
        return lambda meta: True

    def _combined(meta):
        for c in conditions:
            if not c(meta):
                return False
        return True

    return _combined

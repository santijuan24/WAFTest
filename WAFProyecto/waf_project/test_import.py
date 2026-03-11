import traceback
import sys

try:
    import admin_api.routes.config
except Exception as e:
    with open("full_traceback.txt", "w", encoding="utf-8") as f:
        f.write(traceback.format_exc())

import os
import time
import asyncio
from zspace import process_zspace
from ugreen import process_ugreen
from fnos import process_fnos
import traceback
# 从环境变量获取间隔时间，单位：分钟
INTERVAL_MINUTES = float(os.getenv('INTERVAL_MINUTES', 5))

while True:
    try:
        process_zspace()
    except Exception as e:
        error_info = f"执行 process_zspace 时出错: {e}\n{traceback.format_exc()}"
        print(error_info)
    
    try:
        process_ugreen()
    except Exception as e:
        error_info = f"执行 process_ugreen 时出错: {e}\n{traceback.format_exc()}"
        print(error_info)

    try:
        asyncio.run(process_fnos())
    except Exception as e:
        error_info = f"执行 process_fnos 时出错: {e}\n{traceback.format_exc()}"
        print(error_info)  
    time.sleep(INTERVAL_MINUTES * 60)

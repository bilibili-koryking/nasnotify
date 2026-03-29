from func import *
# 从环境变量获取配置
# os.environ['ZSPACE_CONFIGS'] =  ''' [
#             {
#                 "ip_port": "192.168.44.55:5056", 
#                 "cookie": "xxxxxxxxxxxxxxxxxxx",
#                 "notify_type_name": "极空间z4pro",
#                 "use_ssl": true
#             }
#          ]'''
zspace_configs_str = os.getenv('ZSPACE_CONFIGS', '[]').strip()
ZSPACE_CONFIGS = json.loads(zspace_configs_str)
def process_zspace():
    if not ZSPACE_CONFIGS:
        return  print("无极空间配置") # 没有配置则不执行
    log_dir = "log"
    os.makedirs(log_dir, exist_ok=True)
    for config in ZSPACE_CONFIGS:
        cookie = config.get('cookie')
        ip_port = config.get('ip_port')
        notify_type_name = config.get('notify_type_name')
        use_ssl = config.get('use_ssl', False)
        ip, port = split_ip_port(ip_port, 5055)
        if not check_port_open(ip,port):
            print(f"IP: {ip}, 端口: {port} 不通，跳过此次循环")
            continue    
        file_path = os.path.join(log_dir, f"{ip}_{port}.log")
        try:
            response = zspace_notify(cookie, ip, port, use_ssl)
            notice_list = response.get('data', {}).get('list', [])
            last_timestamp = get_last_zspace_timestamp(file_path)
            new_notices = []
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                # 不存在文件或者文件为空，插入所有数据
                save_zspace_notifications(notice_list, file_path)
                log_content = read_zspace_notification_wx(file_path,notify_type_name)
                if log_content:
                    # 调用 wechatpush 发送内容
                    wechatpush(log_content, WXPUSH_SPT)
                    print("新增通知")
            else:
                for item in notice_list:
                    created_at_str = item.get('created_at', '')
                    try:
                        current_time = datetime.strptime(created_at_str, '%Y-%m-%d %H:%M:%S')
                        timestamp = current_time.timestamp()
                        if timestamp > last_timestamp:
                            new_notices.append(item)
                    except ValueError:
                        continue
                if new_notices:
                    # 有更新数据，清空文件并插入更新部分
                    save_zspace_notifications(new_notices, file_path)
                    log_content = read_zspace_notification_wx(file_path,notify_type_name)
                    if log_content:
                        # 调用 wechatpush 发送内容
                        wechatpush(log_content, WXPUSH_SPT)
                        print("清空文件，新增通知。")
                else:
                    print("没有新的通知。")
        except requests.RequestException as e:
            error_info = f"获取极空间通知时出错，IP: {ip}, 端口: {port}, 错误信息: {e}\n{traceback.format_exc()}"
            print(error_info)
if __name__ == "__main__":
    process_zspace()
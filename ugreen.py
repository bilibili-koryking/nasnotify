from func import *

# os.environ['UGREEN_CONFIGS'] =  ''' [
#             {
#                 "ip_port": "192.168.44.22:9999", 
#                 "username": "koryking", 
#                 "password": "xxxxxxxxxxx", 
#                 "notify_type_name": "绿联云4300P",
#             },
#             {
#                 "ip_port": "192.168.44.23:9999", 
#                 "username": "koryking", 
#                 "password": "xxxxxxxxxxx", 
#                 "notify_type_name": "绿联云4800",
#             },
#             {
#                 "ip_port": "192.168.44.45:9443", 
#                 "username": "koryking", 
#                 "password": "xxxxxxxxxxx", 
#                 "notify_type_name": "绿联云6800",
#                 "use_ssl": true
#             }
#          ]'''
#从环境变量获取配置
UGREEN_CONFIGS_STR = os.getenv('UGREEN_CONFIGS', '[]').strip()
UGREEN_CONFIGS = json.loads(UGREEN_CONFIGS_STR)

def process_ugreen():
    if not UGREEN_CONFIGS:
        return  print("无绿联配置")# 没有配置则不执行
    log_dir = "log"
    os.makedirs(log_dir, exist_ok=True)
    for config in UGREEN_CONFIGS:
        username = config.get('username')
        ip_port = config.get('ip_port')
        notify_type_name = config.get('notify_type_name')
        use_ssl = config.get('use_ssl', False)
        ip, port = split_ip_port(ip_port, 9999)
        if not check_port_open(ip, port):
            print(f"IP: {ip}, 端口: {port} 不通，跳过此次循环")
            continue        
        password = config.get('password')
        file_path = os.path.join(log_dir, f"{ip}_{port}.log")
        try:
            auth_info = load_auth_info(ip, port)
            token_id = None
            token = None
            if auth_info:
                token_id = auth_info['token_id']
                token = auth_info['token']
            else:
                # 没有保存的鉴权信息，进行首次鉴权
                token = get_token(username, ip, port, use_ssl)
                login_result = login(username, ip, port, jiami(token, password), use_ssl)
                public_key = login_result['data']['public_key']
                token = login_result['data']['token']
                token = jiami(public_key, token)
                token_id = login_result['data']['token_id']
                save_auth_info(ip, port, {'token_id': token_id, 'token': token})

            # 只调用一次 ugreen_notify
            response_data = ugreen_notify(token_id, token, ip, port, use_ssl)
            if response_data.get('code') != 200:
                # code 不为 200，重新鉴权
                token = get_token(username, ip, port, use_ssl)
                login_result = login(username, ip, port, jiami(token, password), use_ssl)
                public_key = login_result['data']['public_key']
                token = login_result['data']['token']
                token = jiami(public_key, token)
                token_id = login_result['data']['token_id']
                save_auth_info(ip, port, {'token_id': token_id, 'token': token})
                # 重新调用 ugreen_notify
                response_data = ugreen_notify(token_id, token, ip, port, use_ssl)

            notice_list = response_data.get('data', {}).get('List', [])
            last_timestamp = get_last_timestamp(file_path)
            new_notices = []

            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                # 不存在文件或者文件为空，插入所有数据
                save_notifications(notice_list, file_path)
                log_content = read_ugreen_notification_wx(file_path,notify_type_name)
                if log_content:
                    # 调用 wechatpush 发送内容
                    wechatpush(log_content, WXPUSH_SPT)
                    print("新增通知")
            else:
                for item in notice_list:
                    timestamp = item.get('time', 0)
                    if timestamp > last_timestamp:
                        new_notices.append(item)
                if new_notices:
                    # 有更新数据，清空文件并插入更新部分
                    save_notifications(new_notices, file_path)
                    log_content = read_ugreen_notification_wx(file_path,notify_type_name)
                    if log_content:
                        # 调用 wechatpush 发送内容
                        wechatpush(log_content, WXPUSH_SPT)
                        print("清空文件，新增通知。")
                else:
                    print("没有新的通知。")
        except requests.RequestException as e:
            error_info = f"获取绿联通知时出错，IP: {ip}, 错误信息: {e}\n{traceback.format_exc()}"
            print(error_info)
if __name__ == "__main__":
    process_ugreen()
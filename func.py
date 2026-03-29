import requests
import json
import warnings
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
from datetime import datetime, timedelta,timezone
import os
import re
import traceback
import socket

# 忽略InsecureRequestWarning警告
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# os.environ['WXPUSH_SPT'] = 'xxxxxxxxxxxxxxxxx'
WXPUSH_SPT = os.getenv('WXPUSH_SPT', '')
####拆分ip和端口
def split_ip_port(ip_port, default_port=None):
    """
    将 ip:port 格式的字符串拆分为 ip 和 port
    :param ip_port: ip:port 格式的字符串
    :param default_port: 默认端口号
    :return: ip 和 port
    """
    parts = ip_port.split(':')
    ip = parts[0]
    port = int(parts[1]) if len(parts) > 1 else default_port
    return ip, port

####保存鉴权信息
def save_auth_info(ip, port, auth_info):
    """
    保存鉴权信息到配置文件
    :param ip: IP 地址
    :param port: 端口号
    :param auth_info: 鉴权信息
    """
    os.makedirs("token", exist_ok=True)
    config_file = os.path.join("token", f"{ip}_{port}.config")
    with open(config_file, 'w') as f:
        json.dump(auth_info, f)

####加载鉴权信息
def load_auth_info(ip, port):
    """
    从配置文件加载鉴权信息
    :param ip: IP 地址
    :param port: 端口号
    :return: 鉴权信息，如果文件不存在则返回 None
    """
    os.makedirs("token", exist_ok=True)
    config_file = os.path.join("token", f"{ip}_{port}.config")
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    return None
####ip有效性检测
def check_port_open(ip, port, timeout=2):
    """
    检查设备指定 IP 和端口是否开放
    :param ip_port: 目标 IP 和端口，格式为 ip:port
    :param timeout: 超时时间，单位秒
    :return: 如果端口开放返回 True，否则返回 False
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception as e:
        print(f"检查端口 {port} 时出错，IP: {ip}, 错误信息: {e}")
        return False

####绿联获取鉴权
def get_token(username, ip, port, use_ssl):
    """
    获取绿联设备 token
    :param username: 用户名
    :param ip_port: 目标 IP 和端口，格式为 ip:port
    :param use_ssl: 是否使用 HTTPS
    :return: token 或 None
    """
    headers = {
        "User-Agent": "MyApp/1.0",
        "Authorization": "Bearer YOUR_TOKEN"
    }
    data = {"username": username}
    headers = {"Content-Type": "application/json"}
    protocol = "https" if use_ssl else "http"
    try:
        response = requests.post(
            f"{protocol}://{ip}:{port}/ugreen/v1/verify/check?token=",
            json=data,
            timeout=10,
            verify=False
        )
        response.raise_for_status()
        return response.headers.get("X-Rsa-Token")
    except Exception  as e:
        error_info = f"获取 token 时出错，IP: {ip}, 端口: {port}, 错误信息: {e}\n{traceback.format_exc()}"
        print(error_info)
        return None

def jiami(encoded_str,text_to_encrypt):
    encoded_str = encoded_str
    decoded_bytes = base64.b64decode(encoded_str)  # 返回 bytes
    decoded_str = decoded_bytes.decode('utf-8')  # 转为字符串（如果是文本）

    def encrypt_with_public_key(decoded_str, plaintext) -> str:
        """
        使用已有的公钥加密字符串，返回 Base64 结果（兼容 JSEncrypt）
        :param decoded_str: PEM 格式的公钥（字符串）
        :param plaintext: 要加密的文本
        :return: Base64 编码的加密结果
        """
        # 1. 加载公钥
        key = RSA.import_key(decoded_str)
        
        # 2. 使用 PKCS#1 v1.5 填充加密
        cipher = PKCS1_v1_5.new(key)
        encrypted_bytes = cipher.encrypt(plaintext.encode('utf-8'))
        
        # 3. 转为 Base64 字符串（与 JSEncrypt 一致）
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    # Remove the test block and directly call the encryption function
    encrypted_result = encrypt_with_public_key(decoded_str, text_to_encrypt)
    return encrypted_result
def login(username,  ip, port, password, use_ssl):
    """
    登录绿联设备
    :param username: 用户名
    :param ip_port: 目标 IP 和端口，格式为 ip:port
    :param password: 密码
    :param use_ssl: 是否使用 HTTPS
    :return: 登录响应的 JSON 数据
    """
    headers = {
        "x-specify-language": "zh-CN"
    }
    data = {"username": username, "password": password, "keepalive": True, "is_simple": True}
    protocol = "https" if use_ssl else "http"
    try:
        response = requests.post(
            f"{protocol}://{ip}:{port}/ugreen/v1/verify/login",
            json=data,
            timeout=10,
            verify=False
        )
        response.raise_for_status()
        return response.json()
    except Exception  as e:
        error_info = f"登录时出错，IP: {ip}, 端口: {port}, 错误信息: {e}\n{traceback.format_exc()}"
        print(error_info)
        return {}

####绿联通知
def ugreen_notify(token_id, token,  ip, port, use_ssl):
    """
    获取绿联设备通知
    :param token_id: token ID
    :param token: token
    :param ip_port: 目标 IP 和端口，格式为 ip:port
    :param use_ssl: 是否使用 HTTPS
    :return: 通知响应的 JSON 数据
    """
    headers = {
        "x-specify-language": "zh-CN",
        "x-ugreen-security-key": token_id,
        "x-ugreen-token": token
    }
    data = {"level": ["info", "important", "warning"], "page": 1, "size": 10}
    protocol = "https" if use_ssl else "http"
    try:
        response = requests.post(
            f"{protocol}://{ip}:{port}/ugreen/v1/desktop/message/list",
            json=data,
            headers=headers,
            timeout=10,
            verify=False
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        error_info = f"获取绿联通知时出错，IP: {ip}, 端口: {port}, 错误信息: {e}\n{traceback.format_exc()}"
        print(error_info)
        return {}

def read_notification(FILE_PATH,notify_type_name):
    try:
        with open(FILE_PATH, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            line_count = len(lines)
            # 标题显示消息总数
            html_content = f"<h2>{notify_type_name}消息通知（共{line_count}条）</h2>"  
            for index, line in enumerate(lines, start=1):
                # 每条消息前加上序号
                html_content += f"<p><strong>{index}.</strong> {line.strip()}</p>"  
            return html_content, line_count
    except FileNotFoundError:
        return "<p>无通知记录。</p>", 0

def save_notifications(notice_list,FILE_PATH):
    with open(FILE_PATH, 'w', encoding='utf-8') as f:
        for item in notice_list:
            body = item.get('body', '')
            timestamp = item.get('time', 0)
            utc_time = datetime.fromtimestamp(timestamp, timezone.utc)
            beijing_time = utc_time + timedelta(hours=8)
            formatted_time = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
            # 同时写入 timestamp
            f.write(f"{formatted_time}：{body}\n")

def get_last_timestamp(FILE_PATH):
    if not os.path.exists(FILE_PATH):
        return 0
    # Initialize the maximum time to the minimum possible time
    max_time = datetime.min
    with open(FILE_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                # Extract the time string, assuming the format is 'YYYY-MM-DD HH:MM:SS'
                time_str = line.split('：')[0].strip()
                # Convert the time string to a datetime object
                current_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                if current_time > max_time:
                    max_time = current_time
            except (ValueError, IndexError):
                # If the conversion fails or there is an index out of bounds, skip the current line
                continue
    # Check if max_time is still the initial value
    if max_time == datetime.min:
        return 0
    # Convert the maximum time to a timestamp
    return max_time.timestamp()

####极空间通知

def read_zspace_notification(FILE_PATH,notify_type_name):
    try:
        with open(FILE_PATH, 'r', encoding='utf-8') as file:
            content = file.read()
            # 使用正则表达式按时间戳分割通知
            notices = re.split(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}：)', content)
            notices = [n for n in notices if n]  # 移除空字符串

            notice_list = []
            for i in range(0, len(notices), 2):
                if i + 1 < len(notices):
                    notice = notices[i] + notices[i + 1]
                    notice_list.append(notice.strip())

            line_count = len(notice_list)
            # 标题显示消息总数
            html_content = f"<h2>{notify_type_name}消息通知（共{line_count}条）</h2>"  
            for index, notice in enumerate(notice_list, start=1):
                # 先将 \n 替换为 <br>，再添加到 HTML 内容中
                formatted_notice = notice.replace('\n', '<br>')
                html_content += f"<p><strong>{index}.</strong> {formatted_notice}</p>"  
            return html_content, line_count
    except FileNotFoundError:
        return "<p>无通知记录。</p>", 0

def save_zspace_notifications(notice_list, FILE_PATH):
    with open(FILE_PATH, 'w', encoding='utf-8') as f:
        for item in notice_list:
            content = item.get('content', '')
            # 直接获取 created_at 字段
            created_at = item.get('created_at', '')
            # 同时写入 created_at
            f.write(f"{created_at}：{content}\n")

def get_last_zspace_timestamp(FILE_PATH):
    if not os.path.exists(FILE_PATH):
        return 0
    # 初始化最大时间为最小可能时间
    max_time = datetime.min
    with open(FILE_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                # 提取时间字符串，假设格式为 'YYYY-MM-DD HH:MM:SS'
                time_str = line.split('：')[0].strip()
                # 将时间字符串转换为 datetime 对象
                current_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                if current_time > max_time:
                    max_time = current_time
            except (ValueError, IndexError):
                # 如果转换失败或出现索引越界，跳过当前行
                continue
    # 检查 max_time 是否仍为初始值
    if max_time == datetime.min:
        return 0
    # 将最大时间转换为时间戳
    return max_time.timestamp()

def zspace_notify(cookie,  ip, port, use_ssl):
    """
    获取极空间设备通知
    :param cookie: 认证 cookie
    :param ip_port: 目标 IP 和端口，格式为 ip:port
    :param use_ssl: 是否使用 HTTPS
    :return: 通知响应的 JSON 数据
    """
    headers = {
        "cookie": cookie,
        "content-type": "application/x-www-form-urlencoded",
    }
    data = {
        "type": "notify",
        "num": 10
    }
    protocol = "https" if use_ssl else "http"
    try:
        response = requests.post(
            f"{protocol}://{ip}:{port}/action/list",
            data=data, headers=headers, timeout=10,
            verify=False
        )
        return response.json()
    except Exception as e:
        error_info = f"获取极空间通知时出错，IP: {ip}, 端口: {port}, 错误信息: {e}\n{traceback.format_exc()}"
        print(error_info)
        return {}
####wxpush通知
def lly_wxpush(body, line_count, notify_type_name, wxpush_spt):
    """
    发送微信通知
    :param body: 通知内容
    :param line_count: 内容行数
    :param notify_type_name: 通知类型名称
    :param wxpush_spt: 微信推送凭证
    :return: 响应的 JSON 数据
    """
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "content": body,
        "summary": f"{notify_type_name}消息通知（共{line_count}条）",
        "contentType": 2,
        "spt": wxpush_spt,
    }
    try:
        response = requests.post(
            "https://wxpusher.zjiecode.com/api/send/message/simple-push",
            json=data, headers=headers  
        )
        return response.json()
    except Exception as e:
        error_info = f"发送微信通知时出错，错误信息: {e}\n{traceback.format_exc()}"
        print(error_info)
        return {}

def read_zspace_notification_wx(FILE_PATH,notify_type_name):
    try:
        with open(FILE_PATH, 'r', encoding='utf-8') as file:
            content = file.read()
            # 使用正则表达式按时间戳分割通知
            notices = re.split(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}：)', content)
            notices = [n for n in notices if n]  
            notice_list = []
            for i in range(0, len(notices), 2):
                if i + 1 < len(notices):
                    notice = notices[i] + notices[i + 1]
                    notice_list.append(notice.strip())
            line_count = len(notice_list)
            # 标题显示消息总数
            push_content = f"{notify_type_name}消息通知（共{line_count}条）"   
            for index, notice in enumerate(notice_list, start=1):
                # 先将 \n 替换为 <br>，再添加到 HTML 内容中
                push_content += f"\n\n{index}.{notice}"  
            return push_content
    except FileNotFoundError:
        return "无通知记录。", 0
  
def read_ugreen_notification_wx(FILE_PATH,notify_type_name):
    try:
        with open(FILE_PATH, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            line_count = len(lines)
            # 标题显示消息总数
            html_content = f"{notify_type_name}消息通知（共{line_count}条）"  
            for index, line in enumerate(lines, start=1):
                # 每条消息前加上序号
                html_content += f"\n\n{index}. {line.strip()}"  
            return html_content
    except FileNotFoundError:
        return "<p>无通知记录。</p>", 0

def wechatpush(body, wxpush_spt):
    """
    发送微信通知
    :param body: 通知内容
    :param wxpush_spt: 微信推送凭证
    :return: 响应的 JSON 数据
    """
    headers = {
        "Content-Type": "application/json;charset=utf-8"
    }
    data = {
    "msgtype": "text",
    "text": {
        "content":body
    }
}
    try:
        response = requests.post(
            f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={wxpush_spt}",
            json=data, headers=headers  
        )
        return response.json()
    except Exception as e:
        error_info = f"发送微信通知时出错，错误信息: {e}\n{traceback.format_exc()}"
        print(error_info)
        return {}
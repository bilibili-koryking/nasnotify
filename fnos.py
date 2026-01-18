#!/usr/bin/env python3

import asyncio
import json
import logging
import time
import base64
import secrets
import hmac
import hashlib
import os
import ssl
from typing import Optional
import websockets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta, timezone
from func import *

# os.environ['FNOS_CONFIGS'] =  ''' [
#     {
#       "server": "192.168.44.33:5667",
#       "username": "koryking",
#       "password": "xxxxxxxxxxx",
#       "use_ssl": true,
#       "notify_type_name": "飞牛Evo 2"
#     }
#   ]'''
# 从环境变量获取配置
FNOS_CONFIGS_STR = os.getenv('FNOS_CONFIGS', '[]').strip()
FNOS_CONFIGS = json.loads(FNOS_CONFIGS_STR)
# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("fnos-notify-demo")

# 直接从配置文件读取最新的配置

# ==================== 加密功能 ====================

def generate_random_string(length: int = 32) -> str:
    """生成指定长度的密码学安全随机字符串"""
    chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(secrets.choice(chars) for _ in range(length))


def generate_iv() -> bytes:
    """生成 16 字节的 IV"""
    return os.urandom(16)


def rsa_encrypt(public_key_pem: str, plaintext: str) -> str:
    """
    RSA 加密（使用 PKCS1_v1_5）
    
    :param public_key_pem: PEM 格式的公钥
    :param plaintext: 要加密的明文
    :return: Base64 编码的密文
    """
    key = RSA.import_key(public_key_pem)
    cipher = PKCS1_v1_5.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()


def aes_encrypt(data: str, key: str, iv: bytes) -> str:
    """
    AES-CBC 加密
    
    :param data: 要加密的数据
    :param key: 32 字符的密钥字符串
    :param iv: 16 字节的 IV
    :return: Base64 编码的密文
    """
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
    return base64.b64encode(ciphertext).decode("utf-8")


def aes_decrypt(ciphertext: str, key: str, iv: bytes) -> str:
    """
    AES-CBC 解密
    
    :param ciphertext: Base64 编码的密文
    :param key: 32 字符的密钥字符串
    :param iv: 16 字节的 IV
    :return: 解密后的明文（Base64 编码，用于签名密钥）
    """
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return base64.b64encode(decrypted).decode("utf-8")


def encrypt_login_request(data: str, public_key: str, aes_key: str, iv: bytes) -> dict:
    """
    加密登录请求
    
    :param data: JSON 字符串格式的登录数据
    :param public_key: RSA 公钥
    :param aes_key: AES 密钥（32字符）
    :param iv: IV（16字节）
    :return: 加密后的请求数据
    """
    # RSA 加密 AES 密钥
    rsa_encrypted = rsa_encrypt(public_key, aes_key)
    
    # AES 加密请求数据
    aes_encrypted = aes_encrypt(data, aes_key, iv)
    
    return {
        "req": "encrypted",
        "iv": base64.b64encode(iv).decode("utf-8"),
        "rsa": rsa_encrypted,
        "aes": aes_encrypted
    }


def get_signature(data: str, key: str) -> str:
    """
    使用 HMAC-SHA256 计算签名
    
    :param data: 要签名的数据
    :param key: Base64 编码的密钥
    :return: Base64 编码的签名
    """
    key_bytes = base64.b64decode(key)
    hmac_obj = hmac.new(key_bytes, data.encode("utf-8"), hashlib.sha256)
    return base64.b64encode(hmac_obj.digest()).decode("utf-8")

# 不需要签名的请求列表
NO_SIGN_REQUESTS = ["encrypted", "util.getSI", "util.crypto.getRSAPub", "ping"]


def sign_request(data: dict, sign_key: Optional[str]) -> str:
    """
    对请求数据签名（如果需要）
    
    :param data: 请求数据字典
    :param sign_key: 签名密钥（Base64 编码），None 表示不签名
    :return: 签名后的 JSON 字符串（签名+JSON）
    """
    req = data.get("req", "")
    json_str = json.dumps(data, separators=(",", ":"))
    
    if req not in NO_SIGN_REQUESTS and sign_key:
        signature = get_signature(json_str, sign_key)
        return signature + json_str
    
    return json_str

# ==================== 请求 ID 生成器 ====================

class ReqIdGenerator:
    """请求 ID 生成器"""
    
    def __init__(self):
        self._index = 0
    
    def generate(self, back_id: str = "0000000000000000") -> str:
        """生成请求 ID: {timestamp_hex}{back_id}{index_hex}"""
        self._index += 1
        timestamp = format(int(time.time()), "x").zfill(8)
        index = format(self._index, "x").zfill(4)
        return f"{timestamp}{back_id}{index}"


_reqid_generator = ReqIdGenerator()

# ==================== WebSocket 客户端 ====================

class IndependentFnOsClient:
    """独立的 fnOS WebSocket 客户端"""
    
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # WebSocket 连接
        self._ws: Optional[any] = None
        self._listen_task: Optional[asyncio.Task] = None
        self._url: Optional[str] = None
        
        # 请求管理
        self._pending: dict[str, asyncio.Future] = {}
        
        # 加密相关（每次连接重新生成）
        self._aes_key: str = ""
        self._iv: bytes = b""
        
        # 服务器信息
        self.si: Optional[str] = None
        self.pub: Optional[str] = None
        
        # 登录信息
        self.back_id: str = "0000000000000000"
        self.token: Optional[str] = None
        self.secret: Optional[str] = None
        self.sign_key: Optional[str] = None
        self.uid: Optional[int] = None
        self.admin: Optional[bool] = None
    
    @property
    def is_connected(self) -> bool:
        """是否已连接"""
        if self._ws is None:
            return False
        try:
            from websockets.protocol import State
            return self._ws.state == State.OPEN
        except (ImportError, AttributeError):
            return getattr(self._ws, 'open', True)

    
    async def connect(self, server: str, use_ssl: bool = True, cookie: Optional[str] = None) -> None:
        """
        连接到 fnOS 服务器
        
        :param server: 服务器地址（如 your-server.fnos.net 或 192.168.1.4:5666）
        :param use_ssl: 是否使用 SSL
        :param cookie: 可选的 Cookie
        """
        # 判断协议
        protocol = "wss" if use_ssl else "ws"
        self._url = f"{protocol}://{server}/websocket?type=main"
        
        # 重新生成加密密钥
        self._aes_key = generate_random_string(32)
        self._iv = generate_iv()
        
        # 额外头信息
        extra_headers = {}
        if cookie:
            extra_headers["Cookie"] = cookie
        elif use_ssl:
            extra_headers["Cookie"] = "mode=relay; language=zh"
        
        try:
            # 创建SSL上下文并禁用证书验证
            ssl_context = None
            if use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            
            self._ws = await asyncio.wait_for(
                websockets.connect(
                    self._url,
                    ping_interval=None,
                    additional_headers=extra_headers,
                    ssl=ssl_context
                ),
                timeout=self.timeout
            )
            # 启动消息监听
            self._listen_task = asyncio.create_task(self._listen())
            self.logger.debug(f"已连接到 {server}")
        except Exception as e:
            raise ConnectionError(f"连接失败: {e}")
    
    async def close(self) -> None:
        """关闭连接"""
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        
        if self._ws:
            await self._ws.close()
            self._ws = None
        
        self.logger.debug("连接已关闭")

    
    async def _listen(self) -> None:
        """监听 WebSocket 消息"""
        try:
            async for message in self._ws:
                try:
                    data = json.loads(message)
                    self.logger.debug(f"收到: {message[:200]}...")
                    
                    reqid = data.get("reqid")
                    if reqid and reqid in self._pending:
                        future = self._pending.pop(reqid)
                        if not future.done():
                            future.set_result(data)
                except json.JSONDecodeError:
                    self.logger.warning(f"无效的 JSON: {message}")
        except websockets.ConnectionClosed:
            self.logger.debug("WebSocket 连接已关闭")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.exception(f"监听异常: {e}")
    
    async def request(self, req: str, **kwargs) -> dict:
        """
        发送请求并等待响应
        
        :param req: 请求类型
        :param kwargs: 请求参数
        :return: 响应数据
        """
        if not self.is_connected:
            raise RuntimeError("未连接到服务器")
        
        # 生成请求 ID
        reqid = _reqid_generator.generate(self.back_id)
        data = {"req": req, "reqid": reqid, **kwargs}

        # 需要加密的请求
        if req in ["user.login", "user.add"]:
            json_data = json.dumps(data, separators=(",", ":"))
            data = encrypt_login_request(json_data, self.pub, self._aes_key, self._iv)
        
        # 签名请求
        message = sign_request(data, self.sign_key)
        
        # 发送请求
        await self._ws.send(message)
        self.logger.debug(f"发送: {req}")
        
        # 等待响应
        future: asyncio.Future = asyncio.Future()
        self._pending[reqid] = future
        
        try:
            result = await asyncio.wait_for(future, timeout=self.timeout)
            return result
        except asyncio.TimeoutError:
            self._pending.pop(reqid, None)
            raise TimeoutError(f"请求超时: {req}")
    
    # ========== 公共 API ==========
    
    async def get_rsa_pub(self) -> dict:
        """获取 RSA 公钥"""
        response = await self.request("util.crypto.getRSAPub")
        if "errno" in response:
            raise RuntimeError(f"获取公钥失败: {response}")
        self.pub = response.get("pub")
        self.si = response.get("si")
        return response

    
    async def login(
        self, 
        username: str, 
        password: str, 
        stay: bool = True,
        device_type: str = "Browser",
        device_name: str = "fnos-git-auth"
    ) -> dict:
        """
        登录到 fnOS
        
        :param username: 用户名
        :param password: 密码
        :param stay: 是否保持登录
        :param device_type: 设备类型
        :param device_name: 设备名称
        :return: 登录响应
        """
        # 确保已获取公钥
        if not self.pub:
            await self.get_rsa_pub()
        
        response = await self.request(
            "user.login",
            user=username,
            password=password,
            stay=stay,
            deviceType=device_type,
            deviceName=device_name,
            si=self.si
        )
        
        # 检查错误
        if "errno" in response:
            error_msg = response.get("msg") or response.get("error") or f"错误码: {response['errno']}"
            raise RuntimeError(f"登录失败: {error_msg}")
        
        # 保存登录信息
        self.back_id = response.get("backId", self.back_id)
        self.token = response.get("token")
        self.secret = response.get("secret")
        self.uid = response.get("uid")
        self.admin = response.get("admin")
        
        # 解密签名密钥
        if self.secret:
            self.sign_key = aes_decrypt(self.secret, self._aes_key, self._iv)
        
        return response

# ==================== 通知获取功能 ====================

async def fnos_get_notifications(client: IndependentFnOsClient, page: int = 1, last_id: int = 0) -> dict:
    """
    获取通知列表
    
    :param client: 已登录的 IndependentFnOsClient 实例
    :param page: 页码（默认第1页）
    :param last_id: 最后一条通知的ID（用于分页，默认0表示从最新的开始）
    :return: 通知列表响应
    """
    logger.info(f"获取通知列表，第 {page} 页，lastId={last_id}")
    
    # 使用 client.request 方法发送请求
    response = await client.request(
        "notify.list",
        page=page,
        lastId=last_id
    )
    
    return response


def convert_datetime_to_timestamp(datetime_val):
    """
    将 fnOS 通知的时间值转换为时间戳
    
    :param datetime_val: fnOS 通知的时间值，可以是字符串（格式如 "2024-05-20T14:30:00Z"）或整数时间戳
    :return: 时间戳（秒）
    """
    try:
        # 检查是否已经是整数或浮点数
        if isinstance(datetime_val, (int, float)):
            return datetime_val
        
        # 解析 datetime 字符串
        dt = datetime.strptime(datetime_val, "%Y-%m-%dT%H:%M:%SZ")
        # 转换为 UTC 时间戳
        return dt.timestamp()
    except (ValueError, TypeError) as e:
        logger.error(f"无法解析时间值: {datetime_val}, 错误: {e}")
        return 0


def save_fnos_notifications(notice_list, FILE_PATH):
    """
    保存 fnOS 通知到文件
    
    :param notice_list: 通知列表
    :param FILE_PATH: 文件路径
    """
    with open(FILE_PATH, 'w', encoding='utf-8') as f:
        for item in notice_list:
            content = item.get('content', '')
            datetime_str = item.get('datetime', '')
            timestamp = convert_datetime_to_timestamp(datetime_str)
            
            if timestamp > 0:
                utc_time = datetime.fromtimestamp(timestamp, timezone.utc)
                beijing_time = utc_time + timedelta(hours=8)
                formatted_time = beijing_time.strftime('%Y-%m-%d %H:%M:%S')
                # 同时写入 timestamp
                f.write(f"{formatted_time}：{content}\n")


async def fnos_notify(client: IndependentFnOsClient, file_path: str, notify_type_name: str):
    """
    处理通知列表并保存到文件（采用 ugreen.py 风格）
    
    :param client: 已登录的 IndependentFnOsClient 实例
    :param file_path: 保存通知的文件路径
    :param notify_type_name: 通知类型名称
    :return: 是否有新通知
    """
    # 检查文件是否存在或为空
    is_first_run = not os.path.exists(file_path) or os.path.getsize(file_path) == 0
    
    # 获取最后保存的时间戳
    last_timestamp = get_last_timestamp(file_path)
    
    # 获取通知
    response = await fnos_get_notifications(client, page=1, last_id=0)
    notify_list = response.get("notifyList", [])
    
    if is_first_run:
        # 首次启动：只保存最近的10条通知
        # 按时间倒序排序（最新的在前）
        notify_list.sort(key=lambda x: convert_datetime_to_timestamp(x.get('datetime', '')), reverse=True)
        # 只保留最新的10条
        recent_notices = notify_list[:10]
        
        # 保存到文件
        save_fnos_notifications(recent_notices, file_path)
        
        # 构造微信推送内容
        push_content = f"{notify_type_name}消息通知（共{len(recent_notices)}条）"
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f, start=1):
                push_content += f"\n\n{i}. {line.strip()}"
        
        return True, push_content
    else:
        # 后续运行：只推送新增的通知
        # 过滤新通知
        new_notices = []
        for notice in notify_list:
            datetime_str = notice.get('datetime', '')
            timestamp = convert_datetime_to_timestamp(datetime_str)
            
            # 确保能正确比较整数和浮点数的时间戳
            if float(timestamp) > float(last_timestamp):
                new_notices.append(notice)
        
        if new_notices:
            # 按时间倒序排序（最新的在前）
            new_notices.sort(key=lambda x: convert_datetime_to_timestamp(x.get('datetime', '')), reverse=True)
            
            # 保存新通知到文件
            save_fnos_notifications(new_notices, file_path)
            
            # 构造微信推送内容
            push_content = f"{notify_type_name}消息通知（共{len(new_notices)}条）"
            with open(file_path, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f, start=1):
                    push_content += f"\n\n{i}. {line.strip()}"
            
            return True, push_content
        else:
            return False, ""


async def process_fnos_config(config):
    """
    处理单个 fnOS 配置
    
    :param config: fnOS 配置字典
    """
    username = config.get('username')
    server = config.get('server')
    notify_type_name = config.get('notify_type_name', 'fnOS')
    use_ssl = config.get('use_ssl', True)
    cookie = config.get('cookie', 'language=zh')
    password = config.get('password')
    
    # 拆分服务器地址获取 IP 和端口
    ip, port = split_ip_port(server, 5666)
    if not check_port_open(ip, port):
        print(f"IP: {ip}, 端口: {port} 不通，跳过此次循环")
        return
    
    file_path = os.path.join("log", f"{ip}_{port}.log")
    
    # 调试：强制删除文件，模拟首次运行
    # os.remove(file_path) if os.path.exists(file_path) else None
    
    try:
        # 创建客户端实例
        client = IndependentFnOsClient()
        
        # 连接到服务器
        logger.info(f"连接到服务器: {server}")
        await client.connect(server, use_ssl=use_ssl, cookie=cookie)
        
        # 获取公钥
        logger.info("获取服务器公钥...")
        await client.get_rsa_pub()
        
        # 登录
        logger.info(f"登录用户: {username}")
        await client.login(username, password, stay=True)
        logger.info(f"登录成功! UID: {client.uid}")
        
        # 处理通知
        has_new_notice, push_content = await fnos_notify(client, file_path, notify_type_name)
        
        if has_new_notice:
            # 发送微信通知
            result = wechatpush(push_content, WXPUSH_SPT)
            print(f"发送了 {notify_type_name} 的新通知")
        else:
            print(f"{notify_type_name} 没有新的通知。")
        
    except KeyboardInterrupt:
        logger.info("用户中断程序")
    except Exception as e:
        logger.error(f"处理 {notify_type_name} 时出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理资源
        if 'client' in locals() and client:
            logger.info("关闭连接...")
            await client.close()
 

async def process_fnos():
    """
    处理所有 fnOS 配置
    """
    if not FNOS_CONFIGS:
        return print("无 fnOS 配置")
    
    # 创建日志目录
    log_dir = "log"
    os.makedirs(log_dir, exist_ok=True)
    
    # 处理每个配置
    for config in FNOS_CONFIGS:
        await process_fnos_config(config)

if __name__ == "__main__":
    asyncio.run(process_fnos())




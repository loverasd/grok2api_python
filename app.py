import os
import json
import uuid
import time
import base64
import sys
import inspect
import secrets
from loguru import logger
from pathlib import Path

import requests
from flask import (
    Flask,
    request,
    Response,
    jsonify,
    stream_with_context,
    render_template,
    redirect,
    session,
)
from curl_cffi import requests as curl_requests
from werkzeug.middleware.proxy_fix import ProxyFix


class Logger:
    def __init__(self, level="DEBUG", colorize=True, format=None):
        logger.remove()

        if format is None:
            format = (
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{extra[filename]}</cyan>:<cyan>{extra[function]}</cyan>:<cyan>{extra[lineno]}</cyan> | "
                "<level>{message}</level>"
            )

        logger.add(
            sys.stderr,
            level=level,
            format=format,
            colorize=colorize,
            backtrace=True,
            diagnose=True,
        )

        self.logger = logger

    def _get_caller_info(self):
        frame = inspect.currentframe()
        try:
            caller_frame = frame.f_back.f_back
            full_path = caller_frame.f_code.co_filename
            function = caller_frame.f_code.co_name
            lineno = caller_frame.f_lineno

            filename = os.path.basename(full_path)

            return {"filename": filename, "function": function, "lineno": lineno}
        finally:
            del frame

    def info(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).info(f"[{source}] {message}")

    def error(self, message, source="API"):
        caller_info = self._get_caller_info()

        if isinstance(message, Exception):
            self.logger.bind(**caller_info).exception(f"[{source}] {str(message)}")
        else:
            self.logger.bind(**caller_info).error(f"[{source}] {message}")

    def warning(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).warning(f"[{source}] {message}")

    def debug(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).debug(f"[{source}] {message}")

    async def request_logger(self, request):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).info(
            f"请求: {request.method} {request.path}", "Request"
        )


logger = Logger(level="DEBUG")
DATA_DIR = Path("/data")

if not DATA_DIR.exists():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG = {
    "MODELS": {
        "grok-3": "grok-3",
        "grok-3-search": "grok-3",
        "grok-3-imageGen": "grok-3",
        "grok-3-deepsearch": "grok-3",
        "grok-3-deepersearch": "grok-3",
        "grok-3-reasoning": "grok-3",
        "grok-4": "grok-4",
        "grok-4-reasoning": "grok-4",
        "grok-4-imageGen": "grok-4",
        "grok-4-deepsearch": "grok-4",
    },
    "API": {
        "IS_TEMP_CONVERSATION": os.environ.get("IS_TEMP_CONVERSATION", "true").lower()
        == "true",
        "IS_CUSTOM_SSO": os.environ.get("IS_CUSTOM_SSO", "false").lower() == "true",
        "BASE_URL": "https://grok.com",
        "API_KEY": os.environ.get("API_KEY", "sk-123456"),
        "SIGNATURE_COOKIE": None,
        "PICGO_KEY": os.environ.get("PICGO_KEY") or None,
        "TUMY_KEY": os.environ.get("TUMY_KEY") or None,
        "RETRY_TIME": 1000,
        "PROXY": os.environ.get("PROXY") or None,
    },
    "ADMIN": {
        "MANAGER_SWITCH": os.environ.get("MANAGER_SWITCH") or None,
        "PASSWORD": os.environ.get("ADMINPASSWORD") or None,
    },
    "SERVER": {
        "COOKIE": None,
        "CF_CLEARANCE": os.environ.get("CF_CLEARANCE") or None,
        "PORT": int(os.environ.get("PORT", 5200)),
    },
    "RETRY": {"RETRYSWITCH": False, "MAX_ATTEMPTS": 2},
    "TOKEN_STATUS_FILE": str(DATA_DIR / "token_status.json"),
    "SHOW_THINKING": os.environ.get("SHOW_THINKING").lower() == "true",
    "IS_THINKING": False,
    "IS_IMG_GEN": False,
    "IS_IMG_GEN2": False,
    "ISSHOW_SEARCH_RESULTS": os.environ.get("ISSHOW_SEARCH_RESULTS", "true").lower()
    == "true",
    "IS_SUPER_GROK": os.environ.get("IS_SUPER_GROK", "false").lower() == "true",
}


DEFAULT_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "text/plain;charset=UTF-8",
    "Connection": "keep-alive",
    "Origin": "https://grok.com",
    "Priority": "u=1, i",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Sec-Ch-Ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Baggage": "sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c",
    "x-statsig-id": "ZTpUeXBlRXJyb3I6IENhbm5vdCByZWFkIHByb3BlcnRpZXMgb2YgdW5kZWZpbmVkIChyZWFkaW5nICdjaGlsZE5vZGVzJyk=",
}


class AuthTokenManager:
    def __init__(self):
        self.token_model_map = {}
        self.expired_tokens = set()
        self.token_status_map = {}
        self.model_super_config = {
            "grok-3": {
                "RequestFrequency": 100,
                "ExpirationTime": 3 * 60 * 60 * 1000,  # 3小时
            },
            "grok-3-deepsearch": {
                "RequestFrequency": 30,
                "ExpirationTime": 24 * 60 * 60 * 1000,  # 3小时
            },
            "grok-3-deepersearch": {
                "RequestFrequency": 10,
                "ExpirationTime": 3 * 60 * 60 * 1000,  # 23小时
            },
            "grok-3-reasoning": {
                "RequestFrequency": 30,
                "ExpirationTime": 3 * 60 * 60 * 1000,  # 3小时
            },
            "grok-4": {
                "RequestFrequency": 20,
                "ExpirationTime": 3 * 60 * 60 * 1000,  # 3小时
            },
        }
        self.model_normal_config = {
            "grok-3": {
                "RequestFrequency": 20,
                "ExpirationTime": 3 * 60 * 60 * 1000,  # 3小时
            },
            "grok-3-deepsearch": {
                "RequestFrequency": 10,
                "ExpirationTime": 24 * 60 * 60 * 1000,  # 24小时
            },
            "grok-3-deepersearch": {
                "RequestFrequency": 3,
                "ExpirationTime": 24 * 60 * 60 * 1000,  # 24小时
            },
            "grok-3-reasoning": {
                "RequestFrequency": 8,
                "ExpirationTime": 24 * 60 * 60 * 1000,  # 24小时
            },
        }
        self.model_config = self.model_normal_config
        self.token_reset_switch = False
        self.token_reset_timer = None

    @staticmethod
    def _cookie_has_value(cookie: str) -> bool:
        if not isinstance(cookie, str):
            return False
        if "sso=" not in cookie or "sso-rw=" not in cookie:
            return False
        import re

        m1 = re.search(r"sso=([^;]+)", cookie)
        m2 = re.search(r"sso-rw=([^;]+)", cookie)
        return bool(m1 and m1.group(1).strip() and m2 and m2.group(1).strip())

    def prune_invalid_tokens(self):
        """移除 token_model_map 中任何无效/空 cookie"""
        for model in list(self.token_model_map.keys()):
            before = len(self.token_model_map[model])
            self.token_model_map[model] = [
                e
                for e in self.token_model_map[model]
                if self._cookie_has_value(e.get("token", ""))
            ]
            after = len(self.token_model_map[model])
            if before != after:
                logger.info(
                    f"模型 {model} 清理无效 token: {before}->{after}", "TokenManager"
                )

    def save_token_status(self):
        try:
            with open(CONFIG["TOKEN_STATUS_FILE"], "w", encoding="utf-8") as f:
                json.dump(self.token_status_map, f, indent=2, ensure_ascii=False)
            logger.info("令牌状态已保存到配置文件", "TokenManager")
        except Exception as error:
            logger.error(f"保存令牌状态失败: {str(error)}", "TokenManager")

    def load_token_status(self):
        try:
            token_status_file = Path(CONFIG["TOKEN_STATUS_FILE"])
            if token_status_file.exists():
                with open(token_status_file, "r", encoding="utf-8") as f:
                    self.token_status_map = json.load(f)
                logger.info("已从配置文件加载令牌状态", "TokenManager")
        except Exception as error:
            logger.error(f"加载令牌状态失败: {str(error)}", "TokenManager")

    def add_token(self, tokens, isinitialization=False):
        tokenType = tokens.get("type")
        tokenSso = tokens.get("token")
        if tokenType == "normal":
            self.model_config = self.model_normal_config
        else:
            self.model_config = self.model_super_config
        sso = tokenSso.split("sso=")[1].split(";")[0]

        for model in self.model_config.keys():
            if model not in self.token_model_map:
                self.token_model_map[model] = []
            if sso not in self.token_status_map:
                self.token_status_map[sso] = {}

            existing_token_entry = next(
                (
                    entry
                    for entry in self.token_model_map[model]
                    if entry["token"] == tokenSso
                ),
                None,
            )

            if not existing_token_entry:
                self.token_model_map[model].append(
                    {
                        "token": tokenSso,
                        "MaxRequestCount": self.model_config[model]["RequestFrequency"],
                        "RequestCount": 0,
                        "AddedTime": int(time.time() * 1000),
                        "StartCallTime": None,
                        "type": tokenType,
                    }
                )

                if model not in self.token_status_map[sso]:
                    self.token_status_map[sso][model] = {
                        "isValid": True,
                        "invalidatedTime": None,
                        "totalRequestCount": 0,
                        "isSuper": tokenType == "super",
                    }
        if not isinitialization:
            self.save_token_status()

    def set_token(self, tokens):
        tokenType = tokens.get("type")
        tokenSso = tokens.get("token")
        if tokenType == "normal":
            self.model_config = self.model_normal_config
        else:
            self.model_config = self.model_super_config

        models = list(self.model_config.keys())
        self.token_model_map = {
            model: [
                {
                    "token": tokenSso,
                    "MaxRequestCount": self.model_config[model]["RequestFrequency"],
                    "RequestCount": 0,
                    "AddedTime": int(time.time() * 1000),
                    "StartCallTime": None,
                    "type": tokenType,
                }
            ]
            for model in models
        }

        sso = tokenSso.split("sso=")[1].split(";")[0]
        self.token_status_map[sso] = {
            model: {
                "isValid": True,
                "invalidatedTime": None,
                "totalRequestCount": 0,
                "isSuper": tokenType == "super",
            }
            for model in models
        }

    def delete_token(self, token):
        try:
            sso = token.split("sso=")[1].split(";")[0]
            for model in self.token_model_map:
                self.token_model_map[model] = [
                    entry
                    for entry in self.token_model_map[model]
                    if entry["token"] != token
                ]

            if sso in self.token_status_map:
                del self.token_status_map[sso]

            self.save_token_status()

            logger.info(f"令牌已成功移除: {token}", "TokenManager")
            return True
        except Exception as error:
            logger.error(f"令牌删除失败: {str(error)}")
            return False

    def reduce_token_request_count(self, model_id, count):
        try:
            normalized_model = self.normalize_model_name(model_id)

            if normalized_model not in self.token_model_map:
                logger.error(f"模型 {normalized_model} 不存在", "TokenManager")
                return False

            if not self.token_model_map[normalized_model]:
                logger.error(f"模型 {normalized_model} 没有可用的token", "TokenManager")
                return False

            token_entry = self.token_model_map[normalized_model][0]

            # 确保RequestCount不会小于0
            new_count = max(0, token_entry["RequestCount"] - count)
            reduction = token_entry["RequestCount"] - new_count

            token_entry["RequestCount"] = new_count

            # 更新token状态
            if token_entry["token"]:
                sso = token_entry["token"].split("sso=")[1].split(";")[0]
                if (
                    sso in self.token_status_map
                    and normalized_model in self.token_status_map[sso]
                ):
                    self.token_status_map[sso][normalized_model][
                        "totalRequestCount"
                    ] = max(
                        0,
                        self.token_status_map[sso][normalized_model][
                            "totalRequestCount"
                        ]
                        - reduction,
                    )
            return True

        except Exception as error:
            logger.error(
                f"重置校对token请求次数时发生错误: {str(error)}", "TokenManager"
            )
            return False

    def get_next_token_for_model(self, model_id, is_return=False):
        normalized_model = self.normalize_model_name(model_id)

        if (
            normalized_model not in self.token_model_map
            or not self.token_model_map[normalized_model]
        ):
            return None

        token_entry = self.token_model_map[normalized_model][0]
        logger.info(f"token_entry: {token_entry}", "TokenManager")
        if is_return:
            return token_entry["token"]

        if token_entry:
            if token_entry["type"] == "super":
                self.model_config = self.model_super_config
            else:
                self.model_config = self.model_normal_config
            if token_entry["StartCallTime"] is None:
                token_entry["StartCallTime"] = int(time.time() * 1000)

            if not self.token_reset_switch:
                self.start_token_reset_process()
                self.token_reset_switch = True

            token_entry["RequestCount"] += 1

            if token_entry["RequestCount"] > token_entry["MaxRequestCount"]:
                self.remove_token_from_model(normalized_model, token_entry["token"])
                next_token_entry = (
                    self.token_model_map[normalized_model][0]
                    if self.token_model_map[normalized_model]
                    else None
                )
                return next_token_entry["token"] if next_token_entry else None

            sso = token_entry["token"].split("sso=")[1].split(";")[0]

            if (
                sso in self.token_status_map
                and normalized_model in self.token_status_map[sso]
            ):
                if (
                    token_entry["RequestCount"]
                    == self.model_config[normalized_model]["RequestFrequency"]
                ):
                    self.token_status_map[sso][normalized_model]["isValid"] = False
                    self.token_status_map[sso][normalized_model]["invalidatedTime"] = (
                        int(time.time() * 1000)
                    )
                self.token_status_map[sso][normalized_model]["totalRequestCount"] += 1

                self.save_token_status()

            return token_entry["token"]

        return None

    def remove_token_from_model(self, model_id, token):
        normalized_model = self.normalize_model_name(model_id)

        if normalized_model not in self.token_model_map:
            logger.error(f"模型 {normalized_model} 不存在", "TokenManager")
            return False

        model_tokens = self.token_model_map[normalized_model]
        token_index = next(
            (i for i, entry in enumerate(model_tokens) if entry["token"] == token), -1
        )

        if token_index != -1:
            removed_token_entry = model_tokens.pop(token_index)
            self.expired_tokens.add(
                (
                    removed_token_entry["token"],
                    normalized_model,
                    int(time.time() * 1000),
                    removed_token_entry["type"],
                )
            )

            if not self.token_reset_switch:
                self.start_token_reset_process()
                self.token_reset_switch = True

            logger.info(
                f"模型{model_id}的令牌已失效，已成功移除令牌: {token}", "TokenManager"
            )
            return True

        logger.error(
            f"在模型 {normalized_model} 中未找到 token: {token}", "TokenManager"
        )
        return False

    def get_expired_tokens(self):
        return list(self.expired_tokens)

    def normalize_model_name(self, model):
        if model.startswith("grok-") and not any(
            keyword in model for keyword in ["deepsearch", "deepersearch", "reasoning"]
        ):
            return "-".join(model.split("-")[:2])
        return model

    def get_token_count_for_model(self, model_id):
        normalized_model = self.normalize_model_name(model_id)
        return len(self.token_model_map.get(normalized_model, []))

    def get_remaining_token_request_capacity(self):
        remaining_capacity_map = {}

        for model in self.model_config.keys():
            model_tokens = self.token_model_map.get(model, [])

            model_request_frequency = sum(
                token_entry.get("MaxRequestCount", 0) for token_entry in model_tokens
            )
            total_used_requests = sum(
                token_entry.get("RequestCount", 0) for token_entry in model_tokens
            )

            remaining_capacity = (
                len(model_tokens) * model_request_frequency
            ) - total_used_requests
            remaining_capacity_map[model] = max(0, remaining_capacity)

        return remaining_capacity_map

    def get_token_array_for_model(self, model_id):
        normalized_model = self.normalize_model_name(model_id)
        return self.token_model_map.get(normalized_model, [])

    def start_token_reset_process(self):
        def reset_expired_tokens():
            now = int(time.time() * 1000)

            model_config = self.model_normal_config
            tokens_to_remove = set()
            for token_info in self.expired_tokens:
                token, model, expired_time, type = token_info
                if type == "super":
                    model_config = self.model_super_config
                expiration_time = model_config[model]["ExpirationTime"]

                if now - expired_time >= expiration_time:
                    if not any(
                        entry["token"] == token
                        for entry in self.token_model_map.get(model, [])
                    ):
                        if model not in self.token_model_map:
                            self.token_model_map[model] = []

                        self.token_model_map[model].append(
                            {
                                "token": token,
                                "MaxRequestCount": model_config[model][
                                    "RequestFrequency"
                                ],
                                "RequestCount": 0,
                                "AddedTime": now,
                                "StartCallTime": None,
                                "type": type,
                            }
                        )

                    sso = token.split("sso=")[1].split(";")[0]
                    if (
                        sso in self.token_status_map
                        and model in self.token_status_map[sso]
                    ):
                        self.token_status_map[sso][model]["isValid"] = True
                        self.token_status_map[sso][model]["invalidatedTime"] = None
                        self.token_status_map[sso][model]["totalRequestCount"] = 0
                        self.token_status_map[sso][model]["isSuper"] = type == "super"

                    tokens_to_remove.add(token_info)

            self.expired_tokens -= tokens_to_remove

            for model in model_config.keys():
                if model not in self.token_model_map:
                    continue

                for token_entry in self.token_model_map[model]:
                    if not token_entry.get("StartCallTime"):
                        continue

                    expiration_time = model_config[model]["ExpirationTime"]
                    if now - token_entry["StartCallTime"] >= expiration_time:
                        sso = token_entry["token"].split("sso=")[1].split(";")[0]
                        if (
                            sso in self.token_status_map
                            and model in self.token_status_map[sso]
                        ):
                            self.token_status_map[sso][model]["isValid"] = True
                            self.token_status_map[sso][model]["invalidatedTime"] = None
                            self.token_status_map[sso][model]["totalRequestCount"] = 0
                            self.token_status_map[sso][model]["isSuper"] = (
                                token_entry["type"] == "super"
                            )

                        token_entry["RequestCount"] = 0
                        token_entry["StartCallTime"] = None

        import threading

        # 启动一个线程执行定时任务，每小时执行一次
        def run_timer():
            while True:
                reset_expired_tokens()
                time.sleep(3600)

        timer_thread = threading.Thread(target=run_timer)
        timer_thread.daemon = True
        timer_thread.start()

    def get_all_tokens(self):
        all_tokens = set()
        for model_tokens in self.token_model_map.values():
            for entry in model_tokens:
                all_tokens.add(entry["token"])
        return list(all_tokens)

    def get_current_token(self, model_id):
        normalized_model = self.normalize_model_name(model_id)

        if (
            normalized_model not in self.token_model_map
            or not self.token_model_map[normalized_model]
        ):
            return None

        token_entry = self.token_model_map[normalized_model][0]
        return token_entry["token"]

    def get_token_status_map(self):
        return self.token_status_map


class Utils:
    @staticmethod
    def organize_search_results(search_results):
        if not search_results or "results" not in search_results:
            return ""

        results = search_results["results"]
        formatted_results = []

        for index, result in enumerate(results):
            title = result.get("title", "未知标题")
            url = result.get("url", "#")
            preview = result.get("preview", "无预览内容")

            formatted_result = f"\r\n<details><summary>资料[{index}]: {title}</summary>\r\n{preview}\r\n\n[Link]({url})\r\n</details>"
            formatted_results.append(formatted_result)

        return "\n\n".join(formatted_results)

    @staticmethod
    def create_auth_headers(model, is_return=False):
        return token_manager.get_next_token_for_model(model, is_return)

    @staticmethod
    def get_proxy_options():
        proxy = CONFIG["API"]["PROXY"]
        proxy_options = {}

        if proxy:
            logger.info(f"使用代理: {proxy}", "Server")

            if proxy.startswith("socks5://"):
                proxy_options["proxy"] = proxy

                if "@" in proxy:
                    auth_part = proxy.split("@")[0].split("://")[1]
                    if ":" in auth_part:
                        username, password = auth_part.split(":")
                        proxy_options["proxy_auth"] = (username, password)
            else:
                proxy_options["proxies"] = {"https": proxy, "http": proxy}
        return proxy_options


class GrokApiClient:
    def __init__(self, model_id):
        if model_id not in CONFIG["MODELS"]:
            raise ValueError(f"不支持的模型: {model_id}")
        self.model_id = CONFIG["MODELS"][model_id]

    def process_message_content(self, content):
        if isinstance(content, str):
            return content
        return None

    def get_image_type(self, base64_string):
        mime_type = "image/jpeg"
        if "data:image" in base64_string:
            import re

            matches = re.search(
                r"data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,", base64_string
            )
            if matches:
                mime_type = matches.group(1)

        extension = mime_type.split("/")[1]
        file_name = f"image.{extension}"

        return {"mimeType": mime_type, "fileName": file_name}

    def upload_base64_file(self, message, model):
        try:
            message_base64 = base64.b64encode(message.encode("utf-8")).decode("utf-8")
            upload_data = {
                "fileName": "message.txt",
                "fileMimeType": "text/plain",
                "content": message_base64,
            }

            logger.info("发送文字文件请求", "Server")
            cookie = f"{Utils.create_auth_headers(model, True)};{CONFIG['SERVER']['CF_CLEARANCE']}"
            proxy_options = Utils.get_proxy_options()
            response = curl_requests.post(
                f"{CONFIG['API']['BASE_URL']}/rest/app-chat/upload-file",
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie": cookie,  # 由当前模型的有效 cookie + 可选 cf_clearance 拼出来
                    "Content-Type": "application/json;charset=UTF-8",
                },
                json=upload_data,
                impersonate="chrome133a",
                **proxy_options,
            )

            if response.status_code != 200:
                logger.error(f"上传文件失败,状态码:{response.status_code}", "Server")
                raise Exception(f"上传文件失败,状态码:{response.status_code}")

            result = response.json()
            logger.info(f"上传文件成功: {result}", "Server")
            return result.get("fileMetadataId", "")

        except Exception as error:
            logger.error(str(error), "Server")
            raise Exception(f"上传文件失败,状态码:{response.status_code}")

    def upload_base64_image(self, base64_or_url: str) -> str:
        """
        上传图片到 /rest/app-chat/upload-file
        - 支持 dataURL (data:image/*;base64,xxx)
        - 支持纯 base64
        - 支持 http/https 远程图片（会先拉取字节再转 base64）
        返回 fileMetadataId；失败返回 ''
        """
        try:
            proxy_options = Utils.get_proxy_options()

            # 1) 准备图片字节的 base64、MIME、文件名
            image_buffer_b64 = None
            mime_type = "image/jpeg"
            file_name = "image.jpg"

            if isinstance(base64_or_url, str) and base64_or_url.startswith("http"):
                # 远程 URL：拉取后转 base64
                resp = curl_requests.get(
                    base64_or_url,
                    headers={**DEFAULT_HEADERS},
                    impersonate="chrome133a",
                    **proxy_options,
                )
                if resp.status_code != 200:
                    logger.error(
                        f"拉取远程图片失败, 状态码:{resp.status_code}", "Server"
                    )
                    return ""
                mime_type = resp.headers.get("content-type", "image/jpeg")
                try:
                    ext = mime_type.split("/")[1].split(";")[0]
                except Exception:
                    ext = "jpg"
                file_name = f"image.{ext}"
                image_buffer_b64 = base64.b64encode(resp.content).decode("utf-8")
            else:
                # dataURL 或 纯 base64
                if "data:image" in base64_or_url:
                    # dataURL
                    image_buffer_b64 = base64_or_url.split(",", 1)[1]
                    info = self.get_image_type(base64_or_url)
                    mime_type = info["mimeType"]
                    file_name = info["fileName"]
                else:
                    # 纯 base64
                    image_buffer_b64 = base64_or_url
                    # 尝试从内容里无法判断，就用默认 jpeg
                    mime_type = "image/jpeg"
                    file_name = "image.jpg"

            upload_data = {
                "fileName": file_name,
                "fileMimeType": mime_type,
                "content": image_buffer_b64,
            }

            # 2) 组装 Cookie（独立于主对话的 CONFIG["SERVER"]["COOKIE"]）
            cookie = Utils.create_auth_headers(
                self.model_id, True
            )  # 取到当前模型的 sso cookie（不计数）
            if not cookie:
                logger.error("上传图片时无可用 token", "Server")
                return ""
            if CONFIG["SERVER"]["CF_CLEARANCE"]:
                cookie = f"{cookie};{CONFIG['SERVER']['CF_CLEARANCE']}"

            logger.info("发送图片文件请求 (/rest/app-chat/upload-file)", "Server")

            resp = curl_requests.post(
                f"{CONFIG['API']['BASE_URL']}/rest/app-chat/upload-file",
                headers={
                    **DEFAULT_HEADERS,
                    # 很关键：覆盖默认的 text/plain
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                },
                json=upload_data,
                impersonate="chrome133a",
                **proxy_options,
            )

            if resp.status_code != 200:
                logger.error(
                    f"上传图片失败, 状态码:{resp.status_code} 响应:{resp.text}",
                    "Server",
                )
                return ""

            result = resp.json()
            logger.info(f"上传图片成功: {result}", "Server")
            return result.get("fileMetadataId", "")

        except Exception as error:
            logger.error(str(error), "Server")
            return ""

    # def convert_system_messages(self, messages):
    #     try:
    #         system_prompt = []
    #         i = 0
    #         while i < len(messages):
    #             if messages[i].get('role') != 'system':
    #                 break

    #             system_prompt.append(self.process_message_content(messages[i].get('content')))
    #             i += 1

    #         messages = messages[i:]
    #         system_prompt = '\n'.join(system_prompt)

    #         if not messages:
    #             raise ValueError("没有找到用户或者AI消息")
    #         return {"system_prompt":system_prompt,"messages":messages}
    #     except Exception as error:
    #         logger.error(str(error), "Server")
    #         raise ValueError(error)
    def prepare_chat_request(self, request):
        """
        只取“最后一条用户消息”的文本作为 message，
        将本轮用户消息里的 base64 图片先上传拿到 fileMetadataId，放入 fileAttachments。
        请求体字段对齐 Web 端。
        """
        # 只保留最后一条用户消息
        todo_messages = request["messages"]
        if not todo_messages:
            raise ValueError("消息内容为空!")

        last = todo_messages[-1]
        if last["role"] != "user":
            raise ValueError("最后一条必须是用户消息!")

        # 从用户消息的 content 提取纯文本（不插入 [图片] 占位）
        def extract_text(content):
            if isinstance(content, list):
                out = []
                for it in content:
                    if it.get("type") == "text":
                        out.append(it.get("text", ""))
                return "\n".join([s for s in out if s])
            elif isinstance(content, dict) and content.get("type") == "text":
                return content.get("text", "")
            elif isinstance(content, str):
                return content
            return ""

        message_text = extract_text(last.get("content", "")) or "请分析图片内容"

        # 本轮图片：上传换 fileMetadataId -> fileAttachments
        file_attachments = []
        if isinstance(last.get("content"), list):
            for it in last["content"]:
                if it.get("type") == "image_url" and it.get("image_url", {}).get("url"):
                    fid = self.upload_base64_image(it["image_url"]["url"])
                    if fid:
                        file_attachments.append(fid)
        elif isinstance(last.get("content"), dict):
            it = last["content"]
            if it.get("type") == "image_url" and it.get("image_url", {}).get("url"):
                fid = self.upload_base64_image(it["image_url"]["url"])
                if fid:
                    file_attachments.append(fid)

        # 搜索/推理/图生图等开关
        model = request["model"]
        search = model in [
            "grok-4-deepsearch",
            "grok-3-search",
            "grok-3-deepsearch",
            "grok-3-deepersearch",
        ]
        is_reasoning = model in ["grok-3-reasoning", "grok-4-reasoning"]

        # 允许外部透传（与你贴的 Web 请求保持相同字段）
        conversation_id = request.get(
            "conversationId"
        )  # 若提供，会在 chat_completions 中选择 /responses
        parent_response_id = request.get("parentResponseId")  # 同上
        custom_personality = request.get("customPersonality", "")
        image_generation_count = request.get("imageGenerationCount", 1)
        enable_image_streaming = bool(request.get("stream", False))

        payload = {
            "message": message_text,
            "modelName": self.model_id,
            # 可选：续聊时才带
            "parentResponseId": parent_response_id,
            "disableSearch": False if not search else False,  # Web 示例是 false
            "enableImageGeneration": True,
            "imageAttachments": [],  # 对齐 Web：图片用 fileAttachments
            "returnImageBytes": False,
            "returnRawGrokInXaiRequest": False,
            "fileAttachments": file_attachments[:4],  # 最多 4 张
            "enableImageStreaming": enable_image_streaming,
            "imageGenerationCount": image_generation_count,
            "forceConcise": False,
            "toolOverrides": {},  # Web 示例是空对象
            "enableSideBySide": True,
            "sendFinalMetadata": True,
            "customPersonality": custom_personality,
            "isReasoning": is_reasoning,
            "webpageUrls": request.get("webpageUrls", []),
            "metadata": {"requestModelDetails": {"modelId": self.model_id}},
            "disableTextFollowUps": True,
            # 下面这几个也与 Web 示例对齐（不是必需，但保持一致）
            "isFromGrokFiles": False,
            "disableMemory": False,
            "forceSideBySide": False,
            "modelMode": "MODEL_MODE_EXPERT",
            "isAsyncChat": False,
            "isRegenRequest": False,
        }

        # 清理 None 字段
        payload = {k: v for k, v in payload.items() if v is not None}
        return payload


class MessageProcessor:
    @staticmethod
    def create_chat_response(message, model, is_stream=False, conversation_id=None, parent_response_id=None):
        base_response = {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "created": int(time.time()),
            "model": model,
        }

        # 可选: 回传会话相关标识，便于客户端保存并续聊
        if conversation_id:
            base_response["conversation_id"] = conversation_id
        if parent_response_id:
            base_response["parent_response_id"] = parent_response_id

        if is_stream:
            return {
                **base_response,
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": message}}],
            }

        return {
            **base_response,
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": message},
                    "finish_reason": "stop",
                }
            ],
            "usage": None,
        }


def process_model_response(response, model):
    result = {"token": None, "imageUrl": None}

    if CONFIG["IS_IMG_GEN"]:
        if response.get("cachedImageGenerationResponse") and not CONFIG["IS_IMG_GEN2"]:
            result["imageUrl"] = response["cachedImageGenerationResponse"]["imageUrl"]
        return result
    if model == "grok-3":
        result["token"] = response.get("token")
    elif model in ["grok-3-search"]:
        if response.get("webSearchResults") and CONFIG["ISSHOW_SEARCH_RESULTS"]:
            result["token"] = (
                f"\r\n<think>{Utils.organize_search_results(response['webSearchResults'])}</think>\r\n"
            )
        else:
            result["token"] = response.get("token")
    elif model in ["grok-3-deepsearch", "grok-3-deepersearch", "grok-4-deepsearch"]:
        if response.get("messageStepId") and not CONFIG["SHOW_THINKING"]:
            return result
        if response.get("messageStepId") and not CONFIG["IS_THINKING"]:
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif (
            not response.get("messageStepId")
            and CONFIG["IS_THINKING"]
            and response.get("messageTag") == "final"
        ):
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        elif (
            response.get("messageStepId")
            and CONFIG["IS_THINKING"]
            and response.get("messageTag") == "assistant"
        ) or response.get("messageTag") == "final":
            result["token"] = response.get("token", "")
        elif (
            CONFIG["IS_THINKING"]
            and response.get("token", "").get("action", "") == "webSearch"
        ):
            result["token"] = (
                response.get("token", "").get("action_input", "").get("query", "")
            )
        elif CONFIG["IS_THINKING"] and response.get("webSearchResults"):
            result["token"] = Utils.organize_search_results(
                response["webSearchResults"]
            )
    elif model == "grok-3-reasoning":
        if response.get("isThinking") and not CONFIG["SHOW_THINKING"]:
            return result

        if response.get("isThinking") and not CONFIG["IS_THINKING"]:
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif not response.get("isThinking") and CONFIG["IS_THINKING"]:
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        else:
            result["token"] = response.get("token")

    elif model == "grok-4":
        if response.get("isThinking"):
            return result
        result["token"] = response.get("token")
    elif model == "grok-4-reasoning":
        if response.get("isThinking") and not CONFIG["SHOW_THINKING"]:
            return result
        if (
            response.get("isThinking")
            and not CONFIG["IS_THINKING"]
            and response.get("messageTag") == "assistant"
        ):
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif (
            not response.get("isThinking")
            and CONFIG["IS_THINKING"]
            and response.get("messageTag") == "final"
        ):
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        else:
            result["token"] = response.get("token")
    elif model in ["grok-4-deepsearch"]:
        if response.get("messageStepId") and not CONFIG["SHOW_THINKING"]:
            return result
        if (
            response.get("messageStepId")
            and not CONFIG["IS_THINKING"]
            and response.get("messageTag") == "assistant"
        ):
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif (
            not response.get("messageStepId")
            and CONFIG["IS_THINKING"]
            and response.get("messageTag") == "final"
        ):
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        elif (
            response.get("messageStepId")
            and CONFIG["IS_THINKING"]
            and response.get("messageTag") == "assistant"
        ) or response.get("messageTag") == "final":
            result["token"] = response.get("token", "")
        elif (
            CONFIG["IS_THINKING"]
            and response.get("token", "").get("action", "") == "webSearch"
        ):
            result["token"] = (
                response.get("token", "").get("action_input", "").get("query", "")
            )
        elif CONFIG["IS_THINKING"] and response.get("webSearchResults"):
            result["token"] = Utils.organize_search_results(
                response["webSearchResults"]
            )

    return result


def handle_image_response(image_url):
    max_retries = 2
    retry_count = 0
    image_base64_response = None

    while retry_count < max_retries:
        try:
            proxy_options = Utils.get_proxy_options()
            image_base64_response = curl_requests.get(
                f"https://assets.grok.com/{image_url}",
                headers={**DEFAULT_HEADERS, "Cookie": CONFIG["SERVER"]["COOKIE"]},
                impersonate="chrome133a",
                **proxy_options,
            )

            if image_base64_response.status_code == 200:
                break

            retry_count += 1
            if retry_count == max_retries:
                raise Exception(
                    f"上游服务请求失败! status: {image_base64_response.status_code}"
                )

            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * retry_count)

        except Exception as error:
            logger.error(str(error), "Server")
            retry_count += 1
            if retry_count == max_retries:
                raise

            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * retry_count)

    image_buffer = image_base64_response.content

    if not CONFIG["API"]["PICGO_KEY"] and not CONFIG["API"]["TUMY_KEY"]:
        base64_image = base64.b64encode(image_buffer).decode("utf-8")
        image_content_type = image_base64_response.headers.get(
            "content-type", "image/jpeg"
        )
        return f"![image](data:{image_content_type};base64,{base64_image})"

    logger.info("开始上传图床", "Server")

    if CONFIG["API"]["PICGO_KEY"]:
        files = {"source": ("image.jpg", image_buffer, "image/jpeg")}
        headers = {"X-API-Key": CONFIG["API"]["PICGO_KEY"]}

        response_url = requests.post(
            "https://www.picgo.net/api/1/upload", files=files, headers=headers
        )

        if response_url.status_code != 200:
            return "生图失败，请查看PICGO图床密钥是否设置正确"
        else:
            logger.info("生图成功", "Server")
            result = response_url.json()
            return f"![image]({result['image']['url']})"

    elif CONFIG["API"]["TUMY_KEY"]:
        files = {"file": ("image.jpg", image_buffer, "image/jpeg")}
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {CONFIG['API']['TUMY_KEY']}",
        }

        response_url = requests.post(
            "https://tu.my/api/v1/upload", files=files, headers=headers
        )

        if response_url.status_code != 200:
            return "生图失败，请查看TUMY图床密钥是否设置正确"
        else:
            try:
                result = response_url.json()
                logger.info("生图成功", "Server")
                return f"![image]({result['data']['links']['url']})"
            except Exception as error:
                logger.error(str(error), "Server")
                return "生图失败，请查看TUMY图床密钥是否设置正确"


def handle_non_stream_response(response, model):
    try:
        logger.info("开始处理非流式响应", "Server")

        stream = response.iter_lines()
        full_response = ""
        conversation_id = None
        parent_response_id = None

        CONFIG["IS_THINKING"] = False
        CONFIG["IS_IMG_GEN"] = False
        CONFIG["IS_IMG_GEN2"] = False

        for chunk in stream:
            if not chunk:
                continue
            try:
                line_json = json.loads(chunk.decode("utf-8").strip())
                if line_json.get("error"):
                    logger.error(json.dumps(line_json, indent=2), "Server")
                    return json.dumps({"error": "RateLimitError"}) + "\n\n"

                # 提取会话与回复ID（尽量兼容多种字段名）
                result_obj = line_json.get("result", {}) if isinstance(line_json, dict) else {}
                resp_obj = result_obj.get("response", {}) if isinstance(result_obj, dict) else {}

                conversation_id = (
                    result_obj.get("conversationId")
                    or line_json.get("conversationId")
                    or resp_obj.get("conversationId")
                    or conversation_id
                )
                parent_response_id = (
                    result_obj.get("responseId")
                    or result_obj.get("messageId")
                    or resp_obj.get("responseId")
                    or resp_obj.get("messageId")
                    or line_json.get("responseId")
                    or line_json.get("messageId")
                    or parent_response_id
                )

                response_data = result_obj.get("response")
                if not response_data:
                    continue

                if response_data.get("doImgGen") or response_data.get(
                    "imageAttachmentInfo"
                ):
                    CONFIG["IS_IMG_GEN"] = True

                result = process_model_response(response_data, model)

                if result["token"]:
                    full_response += result["token"]

                if result["imageUrl"]:
                    CONFIG["IS_IMG_GEN2"] = True
                    return handle_image_response(result["imageUrl"])

            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.error(f"处理流式响应行时出错: {str(e)}", "Server")
                continue

        return full_response, conversation_id, parent_response_id
    except Exception as error:
        logger.error(str(error), "Server")
        raise


def handle_stream_response(response, model):
    def generate():
        logger.info("开始处理流式响应", "Server")

        stream = response.iter_lines()
        CONFIG["IS_THINKING"] = False
        CONFIG["IS_IMG_GEN"] = False
        CONFIG["IS_IMG_GEN2"] = False
        conversation_id = None
        parent_response_id = None

        for chunk in stream:
            if not chunk:
                continue
            try:
                line_json = json.loads(chunk.decode("utf-8").strip())
                print(line_json)
                if line_json.get("error"):
                    logger.error(json.dumps(line_json, indent=2), "Server")
                    yield json.dumps({"error": "RateLimitError"}) + "\n\n"
                    return

                # 提取会话与回复ID（尽量兼容多种字段名）
                result_obj = line_json.get("result", {}) if isinstance(line_json, dict) else {}
                resp_obj = result_obj.get("response", {}) if isinstance(result_obj, dict) else {}
                conversation_id = (
                    result_obj.get("conversationId")
                    or line_json.get("conversationId")
                    or resp_obj.get("conversationId")
                    or conversation_id
                )
                parent_response_id = (
                    result_obj.get("responseId")
                    or result_obj.get("messageId")
                    or resp_obj.get("responseId")
                    or resp_obj.get("messageId")
                    or line_json.get("responseId")
                    or line_json.get("messageId")
                    or parent_response_id
                )

                response_data = result_obj.get("response")
                if not response_data:
                    continue

                if response_data.get("doImgGen") or response_data.get(
                    "imageAttachmentInfo"
                ):
                    CONFIG["IS_IMG_GEN"] = True

                result = process_model_response(response_data, model)

                if result["token"]:
                    yield (
                        "data: "
                        + json.dumps(
                            MessageProcessor.create_chat_response(
                                result["token"],
                                model,
                                True,
                                conversation_id,
                                parent_response_id,
                            )
                        )
                        + "\n\n"
                    )

                if result["imageUrl"]:
                    CONFIG["IS_IMG_GEN2"] = True
                    image_data = handle_image_response(result["imageUrl"])
                    yield (
                        "data: "
                        + json.dumps(
                            MessageProcessor.create_chat_response(
                                image_data,
                                model,
                                True,
                                conversation_id,
                                parent_response_id,
                            )
                        )
                        + "\n\n"
                    )

            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.error(f"处理流式响应行时出错: {str(e)}", "Server")
                continue

        yield "data: [DONE]\n\n"

    return generate()


def initialization():
    sso_array = os.environ.get("SSO", "").split(",")
    sso_array_super = os.environ.get("SSO_SUPER", "").split(",")

    combined_dict = []
    for value in sso_array_super:
        combined_dict.append({"token": f"sso-rw={value};sso={value}", "type": "super"})
    for value in sso_array:
        combined_dict.append({"token": f"sso-rw={value};sso={value}", "type": "normal"})

    logger.info("开始加载令牌", "Server")
    token_manager.load_token_status()
    for tokens in combined_dict:
        if tokens:
            token_manager.add_token(tokens, True)
    # 清理已有的无效条目（见第 3 步实现）
    token_manager.prune_invalid_tokens()
    token_manager.save_token_status()

    token_manager.save_token_status()

    logger.info(
        f"成功加载令牌: {json.dumps(token_manager.get_all_tokens(), indent=2)}",
        "Server",
    )
    logger.info(
        f"令牌加载完成，共加载: {len(sso_array)+len(sso_array_super)}个令牌", "Server"
    )
    logger.info(f"其中共加载: {len(sso_array_super)}个super会员令牌", "Server")

    if CONFIG["API"]["PROXY"]:
        logger.info(f"代理已设置: {CONFIG['API']['PROXY']}", "Server")

    logger.info("初始化完成", "Server")


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(16)
app.json.sort_keys = False


@app.route("/manager/login", methods=["GET", "POST"])
def manager_login():
    if CONFIG["ADMIN"]["MANAGER_SWITCH"]:
        if request.method == "POST":
            password = request.form.get("password")
            if password == CONFIG["ADMIN"]["PASSWORD"]:
                session["is_logged_in"] = True
                return redirect("/manager")
            return render_template("login.html", error=True)
        return render_template("login.html", error=False)
    else:
        return redirect("/")


def check_auth():
    return session.get("is_logged_in", False)


@app.route("/manager")
def manager():
    if not check_auth():
        return redirect("/manager/login")
    return render_template("manager.html")


@app.route("/manager/api/get")
def get_manager_tokens():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(token_manager.get_token_status_map())


@app.route("/manager/api/add", methods=["POST"])
def add_manager_token():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        sso = request.json.get("sso")
        if not sso:
            return jsonify({"error": "SSO token is required"}), 400
        token_manager.add_token({"token": f"sso-rw={sso};sso={sso}", "type": "normal"})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/manager/api/delete", methods=["POST"])
def delete_manager_token():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        sso = request.json.get("sso")
        if not sso:
            return jsonify({"error": "SSO token is required"}), 400
        token_manager.delete_token(f"sso-rw={sso};sso={sso}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/manager/api/cf_clearance", methods=["POST"])
def setCf_Manager_clearance():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        cf_clearance = request.json.get("cf_clearance")
        if not cf_clearance:
            return jsonify({"error": "cf_clearance is required"}), 400
        CONFIG["SERVER"]["CF_CLEARANCE"] = cf_clearance
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get/tokens", methods=["GET"])
def get_tokens():
    auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": "自定义的SSO令牌模式无法获取轮询sso令牌状态"}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(token_manager.get_token_status_map())


@app.route("/add/token", methods=["POST"])
def add_token():
    auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": "自定义的SSO令牌模式无法添加sso令牌"}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        sso = request.json.get("sso")
        token_manager.add_token({"token": f"sso-rw={sso};sso={sso}", "type": "normal"})
        return jsonify(token_manager.get_token_status_map().get(sso, {})), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": "添加sso令牌失败"}), 500


@app.route("/set/cf_clearance", methods=["POST"])
def setCf_clearance():
    auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        cf_clearance = request.json.get("cf_clearance")
        CONFIG["SERVER"]["CF_CLEARANCE"] = cf_clearance
        return jsonify({"message": "设置cf_clearance成功"}), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": "设置cf_clearance失败"}), 500


@app.route("/delete/token", methods=["POST"])
def delete_token():
    auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": "自定义的SSO令牌模式无法删除sso令牌"}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        sso = request.json.get("sso")
        token_manager.delete_token(f"sso-rw={sso};sso={sso}")
        return jsonify({"message": "删除sso令牌成功"}), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": "删除sso令牌失败"}), 500


@app.route("/v1/models", methods=["GET"])
def get_models():
    return jsonify(
        {
            "object": "list",
            "data": [
                {
                    "id": model,
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "grok",
                }
                for model in CONFIG["MODELS"].keys()
            ],
        }
    )


@app.route("/v1/chat/completions", methods=["POST"])
def chat_completions():
    response_status_code = 500
    try:
        auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if auth_token:
            if CONFIG["API"]["IS_CUSTOM_SSO"]:
                result = f"sso={auth_token};sso-rw={auth_token}"
                token_manager.set_token(result)
            elif auth_token != CONFIG["API"]["API_KEY"]:
                return jsonify({"error": "Unauthorized"}), 401
        else:
            return jsonify({"error": "API_KEY缺失"}), 401

        data = request.json
        model = data.get("model")
        # 如果客户端传入 conversationId，则继续同一会话
        conversation_id = data.get("conversationId")
        stream = data.get("stream", False)

        retry_count = 0
        grok_client = GrokApiClient(model)
        # 先准备 Cookie
        CONFIG["API"]["SIGNATURE_COOKIE"] = Utils.create_auth_headers(model)
        if not CONFIG["API"]["SIGNATURE_COOKIE"]:
            raise ValueError("该模型无可用令牌")
        CONFIG["SERVER"]["COOKIE"] = (
            f"{CONFIG['API']['SIGNATURE_COOKIE']};{CONFIG['SERVER']['CF_CLEARANCE']}"
            if CONFIG["SERVER"]["CF_CLEARANCE"]
            else CONFIG["API"]["SIGNATURE_COOKIE"]
        )
        request_payload = grok_client.prepare_chat_request(data)

        logger.info(json.dumps(request_payload, indent=2))

        while retry_count < CONFIG["RETRY"]["MAX_ATTEMPTS"]:
            retry_count += 1
            CONFIG["API"]["SIGNATURE_COOKIE"] = Utils.create_auth_headers(model)

            if not CONFIG["API"]["SIGNATURE_COOKIE"]:
                raise ValueError("该模型无可用令牌")

            logger.info(
                f"当前令牌: {json.dumps(CONFIG['API']['SIGNATURE_COOKIE'], indent=2)}",
                "Server",
            )
            logger.info(
                f"当前可用模型的全部可用数量: {json.dumps(token_manager.get_remaining_token_request_capacity(), indent=2)}",
                "Server",
            )

            if CONFIG["SERVER"]["CF_CLEARANCE"]:
                CONFIG["SERVER"][
                    "COOKIE"
                ] = f"{CONFIG['API']['SIGNATURE_COOKIE']};{CONFIG['SERVER']['CF_CLEARANCE']}"
            else:
                CONFIG["SERVER"]["COOKIE"] = CONFIG["API"]["SIGNATURE_COOKIE"]
            logger.info(json.dumps(request_payload, indent=2), "Server")
            try:
                proxy_options = Utils.get_proxy_options()
                # 根据是否包含 conversationId 选择创建新会话或在已有会话中追加回复
                upstream_path = (
                    f"/rest/app-chat/conversations/{conversation_id}/responses"
                    if conversation_id
                    else "/rest/app-chat/conversations/new"
                )
                response = curl_requests.post(
                    f"{CONFIG['API']['BASE_URL']}{upstream_path}",
                    headers={
                        **DEFAULT_HEADERS,
                        "Cookie": CONFIG["SERVER"]["COOKIE"],
                        "Content-Type": "application/json;charset=UTF-8",
                    },
                    json=request_payload,  # ✅ 让库自己序列化，并配合上面的 JSON 头
                    impersonate="chrome133a",
                    stream=True,
                    **proxy_options,
                )
                logger.info(CONFIG["SERVER"]["COOKIE"], "Server")
                if response.status_code == 200:
                    response_status_code = 200
                    logger.info("请求成功", "Server")
                    logger.info(
                        f"当前{model}剩余可用令牌数: {token_manager.get_token_count_for_model(model)}",
                        "Server",
                    )

                    try:
                        if stream:
                            return Response(
                                stream_with_context(
                                    handle_stream_response(response, model)
                                ),
                                content_type="text/event-stream",
                            )
                        else:
                            content, conv_id, parent_id = handle_non_stream_response(
                                response, model
                            )
                            return jsonify(
                                MessageProcessor.create_chat_response(
                                    content, model, False, conv_id, parent_id
                                )
                            )

                    except Exception as error:
                        logger.error(str(error), "Server")
                        if CONFIG["API"]["IS_CUSTOM_SSO"]:
                            raise ValueError(
                                f"自定义SSO令牌当前模型{model}的请求次数已失效"
                            )
                        token_manager.remove_token_from_model(
                            model, CONFIG["API"]["SIGNATURE_COOKIE"]
                        )
                        if token_manager.get_token_count_for_model(model) == 0:
                            raise ValueError(
                                f"{model} 次数已达上限，请切换其他模型或者重新对话"
                            )
                elif response.status_code == 403:
                    response_status_code = 403
                    token_manager.reduce_token_request_count(
                        model, 1
                    )  # 重置去除当前因为错误未成功请求的次数，确保不会因为错误未成功请求的次数导致次数上限
                    if token_manager.get_token_count_for_model(model) == 0:
                        raise ValueError(
                            f"{model} 次数已达上限，请切换其他模型或者重新对话"
                        )
                    print("状态码:", response.status_code)
                    print("响应头:", response.headers)
                    print("响应内容:", response.text)
                    raise ValueError(f"IP暂时被封无法破盾，请稍后重试或者更换ip")
                elif response.status_code == 429:
                    response_status_code = 429
                    token_manager.reduce_token_request_count(model, 1)
                    if CONFIG["API"]["IS_CUSTOM_SSO"]:
                        raise ValueError(
                            f"自定义SSO令牌当前模型{model}的请求次数已失效"
                        )

                    token_manager.remove_token_from_model(
                        model, CONFIG["API"]["SIGNATURE_COOKIE"]
                    )
                    if token_manager.get_token_count_for_model(model) == 0:
                        raise ValueError(
                            f"{model} 次数已达上限，请切换其他模型或者重新对话"
                        )

                else:
                    if CONFIG["API"]["IS_CUSTOM_SSO"]:
                        raise ValueError(
                            f"自定义SSO令牌当前模型{model}的请求次数已失效"
                        )

                    logger.error(
                        f"令牌异常错误状态!status: {response.status_code}", "Server"
                    )
                    token_manager.remove_token_from_model(
                        model, CONFIG["API"]["SIGNATURE_COOKIE"]
                    )
                    logger.info(
                        f"当前{model}剩余可用令牌数: {token_manager.get_token_count_for_model(model)}",
                        "Server",
                    )

            except Exception as e:
                logger.error(f"请求处理异常: {str(e)}", "Server")
                if CONFIG["API"]["IS_CUSTOM_SSO"]:
                    raise
                continue
        if response_status_code == 403:
            raise ValueError("IP暂时被封无法破盾，请稍后重试或者更换ip")
        elif response_status_code == 500:
            raise ValueError("当前模型所有令牌暂无可用，请稍后重试")

    except Exception as error:
        logger.error(str(error), "ChatAPI")
        return (
            jsonify({"error": {"message": str(error), "type": "server_error"}}),
            response_status_code,
        )


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    return "api运行正常", 200


if __name__ == "__main__":
    token_manager = AuthTokenManager()
    initialization()

    app.run(host="0.0.0.0", port=CONFIG["SERVER"]["PORT"], debug=False)

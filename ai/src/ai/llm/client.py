# from __future__ import annotations

# from dataclasses import dataclass
# from typing import Any, Optional

# import httpx

# from .config import OllamaSettings, get_ollama_settings
# from ..contracts import AIAssessment
# from ..prompting import PromptRequest


# class OllamaClientError(Exception):
#     def __init__(self, message: str, status_code: Optional[int] = None):
#         super().__init__(message)
#         self.status_code = status_code


# class OllamaConnectionError(OllamaClientError):
#     pass


# class OllamaTimeoutError(OllamaClientError):
#     pass


# class OllamaHTTPError(OllamaClientError):
#     pass


# class OllamaInvalidResponseError(OllamaClientError):
#     pass


# class OllamaModelNotFoundError(OllamaClientError):
#     pass


# @dataclass(frozen=True)
# class LLMResponse:
#     content: str
#     model: str
#     raw_response: Optional[dict[str, Any]] = None
#     done: bool = True


# class OllamaClient:
#     def __init__(
#         self,
#         base_url: Optional[str] = None,
#         model: Optional[str] = None,
#         timeout_seconds: Optional[int] = None,
#         settings: Optional[OllamaSettings] = None,
#     ):
#         self._settings = settings or get_ollama_settings()
#         self._base_url = (base_url or self._settings.base_url).rstrip("/")
#         self._model = model or self._settings.model
#         self._timeout = timeout_seconds or self._settings.timeout_seconds
#         self._generate_endpoint = self._settings.generate_endpoint
#         self._client = httpx.Client(timeout=self._timeout)

#     def generate(self, prompt_request: PromptRequest) -> LLMResponse:
#         payload = {
#             "model": self._model,
#             "prompt": prompt_request.user_prompt,
#             "system": prompt_request.system_prompt,
#             "stream": False,
#             "format": AIAssessment.model_json_schema(),
#         }

#         url = f"{self._base_url}{self._generate_endpoint}"

#         try:
#             response = self._client.post(url, json=payload)
#         except httpx.ConnectError as e:
#             raise OllamaConnectionError(
#                 f"Failed to connect to Ollama at {self._base_url}: {e}"
#             ) from e
#         except httpx.TimeoutException as e:
#             raise OllamaTimeoutError(
#                 f"Request to Ollama timed out after {self._timeout} seconds"
#             ) from e

#         if response.status_code == 404:
#             raise OllamaModelNotFoundError(
#                 f"Model '{self._model}' not found or endpoint not available"
#             )

#         if response.status_code >= 400:
#             raise OllamaHTTPError(
#                 f"Ollama returned HTTP {response.status_code}: {response.text}"
#             )

#         try:
#             data = response.json()
#         except ValueError as e:
#             raise OllamaInvalidResponseError(
#                 f"Failed to parse Ollama response as JSON: {e}"
#             ) from e

#         content = data.get("response", "")
#         if not content and not data.get("done", True):
#             raise OllamaInvalidResponseError(
#                 "Ollama response missing content and not marked as done"
#             )

#         return LLMResponse(
#             content=content,
#             model=data.get("model", self._model),
#             raw_response=data,
#             done=data.get("done", True),
#         )

#     def close(self):
#         self._client.close()

#     def __enter__(self):
#         return self

#     def __exit__(self, exc_type, exc_val, exc_tb):
#         self.close()


# def create_ollama_client(
#     base_url: Optional[str] = None,
#     model: Optional[str] = None,
#     timeout_seconds: Optional[int] = None,
#     settings: Optional[OllamaSettings] = None,
# ) -> OllamaClient:
#     return OllamaClient(
#         base_url=base_url,
#         model=model,
#         timeout_seconds=timeout_seconds,
#         settings=settings,
#     )

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .config import OllamaSettings, get_ollama_settings
from ..contracts import AIAssessment
from ..prompting import PromptRequest


class OllamaClientError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class OllamaConnectionError(OllamaClientError):
    pass


class OllamaTimeoutError(OllamaClientError):
    pass


class OllamaHTTPError(OllamaClientError):
    pass


class OllamaInvalidResponseError(OllamaClientError):
    pass


class OllamaModelNotFoundError(OllamaClientError):
    pass


@dataclass(frozen=True)
class LLMResponse:
    content: str
    model: str
    raw_response: Optional[dict[str, Any]] = None
    done: bool = True


class OllamaClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        settings: Optional[OllamaSettings] = None,
    ):
        self._settings = settings or get_ollama_settings()
        self._base_url = (base_url or self._settings.base_url).rstrip("/")
        self._model = model or self._settings.model
        self._timeout = timeout_seconds or self._settings.timeout_seconds
        self._generate_endpoint = self._settings.generate_endpoint
        self._client = httpx.Client(timeout=self._timeout)

    def generate(self, prompt_request: PromptRequest) -> LLMResponse:
        options: dict[str, Any] = {
            "temperature": self._settings.temperature,
        }
        if self._settings.seed is not None:
            options["seed"] = self._settings.seed

        # Build request-specific JSON schema: constrain evidence_path to the
        # exact allowed provenance paths for this case. This is per-request
        # and never mutates the global AIAssessment schema.
        try:
            allowed = getattr(prompt_request, "allowed_evidence_paths", None)
            if allowed:
                from src.ai.provenance import build_dynamic_assessment_schema
                fmt = build_dynamic_assessment_schema(list(allowed))
            else:
                fmt = AIAssessment.model_json_schema()
        except Exception:
            fmt = AIAssessment.model_json_schema()

        payload = {
            "model": self._model,
            "prompt": prompt_request.user_prompt,
            "system": prompt_request.system_prompt,
            "stream": False,
            "format": fmt,
            "options": options,
        }

        url = f"{self._base_url}{self._generate_endpoint}"

        try:
            response = self._client.post(url, json=payload)
        except httpx.ConnectError as e:
            raise OllamaConnectionError(
                f"Failed to connect to Ollama at {self._base_url}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise OllamaTimeoutError(
                f"Request to Ollama timed out after {self._timeout} seconds"
            ) from e

        if response.status_code == 404:
            raise OllamaModelNotFoundError(
                f"Model '{self._model}' not found or endpoint not available"
            )

        if response.status_code >= 400:
            raise OllamaHTTPError(
                f"Ollama returned HTTP {response.status_code}: {response.text}"
            )

        try:
            data = response.json()
        except ValueError as e:
            raise OllamaInvalidResponseError(
                f"Failed to parse Ollama response as JSON: {e}"
            ) from e

        content = data.get("response", "")
        if not content and not data.get("done", True):
            raise OllamaInvalidResponseError(
                "Ollama response missing content and not marked as done"
            )

        return LLMResponse(
            content=content,
            model=data.get("model", self._model),
            raw_response=data,
            done=data.get("done", True),
        )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_ollama_client(
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    settings: Optional[OllamaSettings] = None,
) -> OllamaClient:
    return OllamaClient(
        base_url=base_url,
        model=model,
        timeout_seconds=timeout_seconds,
        settings=settings,
    )
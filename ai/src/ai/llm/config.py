# from __future__ import annotations

# from pydantic_settings import BaseSettings
# from pydantic import Field


# class OllamaSettings(BaseSettings):
#     model_config = {
#         "env_prefix": "OLLAMA_",
#         "case_sensitive": False,
#     }

#     base_url: str = Field(
#         default="http://localhost:11434",
#         description="Ollama server base URL",
#     )
#     model: str = Field(
#         default="qwen3:8b",
#         description="Model name to use for inference",
#     )
#     timeout_seconds: int = Field(
#         default=600,
#         description="Request timeout in seconds",
#     )
#     generate_endpoint: str = Field(
#         default="/api/generate",
#         description="Ollama generate API endpoint",
#     )


# def get_ollama_settings() -> OllamaSettings:
#     return OllamaSettings()

from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import Field


class OllamaSettings(BaseSettings):
    model_config = {
        "env_prefix": "OLLAMA_",
        "case_sensitive": False,
    }

    base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama server base URL",
    )
    model: str = Field(
        default="qwen2.5:7b-instruct",
        description="Model name to use for inference",
    )
    timeout_seconds: int = Field(
        default=600,
        description="Request timeout in seconds",
    )
    generate_endpoint: str = Field(
        default="/api/generate",
        description="Ollama generate API endpoint",
    )
    temperature: float = Field(
        default=0.2,
        description=(
            "Sampling temperature for generation. Kept low and explicit "
            "because an unset temperature falls back to Ollama's default "
            "(~0.8), which is high enough to make a probability field like "
            "phishing_probability swing wildly between runs on the same "
            "email."
        ),
    )
    seed: int | None = Field(
        default=None,
        description=(
            "Optional fixed seed for deterministic sampling. Leave unset "
            "for normal operation; set OLLAMA_SEED when you need the exact "
            "same output across repeated runs of the same input, e.g. while "
            "debugging calibration."
        ),
    )
    max_concurrency: int = Field(
        default=2,
        ge=1,
        le=32,
        description=(
            "Maximum number of concurrent AI analysis jobs (Ollama workers). "
            "Default 2 is conservative for a local single-GPU Ollama deployment: "
            "Ollama model inference is GPU/VRAM bound, and two concurrent large prompts "
            "already saturate a typical 8-16GB VRAM card with qwen2.5:7b-instruct. "
            "Higher values increase throughput only if the hardware has spare GPU/CPU "
            "and Ollama is configured with sufficient parallel context slots. "
            "Configure via OLLAMA_MAX_CONCURRENCY."
        ),
    )
    queue_maxsize: int = Field(
        default=50,
        ge=1,
        le=1000,
        description=(
            "Maximum number of pending backend requests queued before backpressure. "
            "Default 50 bounds memory (each evidence prompt can be tens of KB) and "
            "prevents unbounded task/thread growth under burst load (e.g. 200 simultaneous "
            "emails). Queue holds validated request payloads only; no duplicate evidence "
            "copies or global caches are created. Configure via OLLAMA_QUEUE_MAXSIZE."
        ),
    )
    shutdown_timeout_seconds: float = Field(
        default=10.0,
        ge=0.0,
        le=300.0,
        description=(
            "Graceful shutdown timeout in seconds for workers to finish active jobs "
            "after stop accepting new work. Configure via OLLAMA_SHUTDOWN_TIMEOUT_SECONDS."
        ),
    )


def get_ollama_settings() -> OllamaSettings:
    return OllamaSettings()
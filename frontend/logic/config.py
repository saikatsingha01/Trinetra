from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import yaml


@dataclass
class VerdictThresholdsConfig:
    low_max: int = 25
    medium_max: int = 49
    high_max: int = 79
    critical_max: int = 100


@dataclass
class RuleWeightsConfig:
    spf_fail: int = 10
    dkim_fail: int = 10
    dmarc_fail: int = 15
    sender_domain_mismatch: int = 15
    reply_to_mismatch: int = 10
    header_anomaly: int = 10
    spoofing_indicator: int = 10
    bad_ip_reputation: int = 15
    bad_domain_reputation: int = 15
    bad_url_reputation: int = 15
    malicious_hash_reputation: int = 20
    high_phishing_probability: int = 10
    high_bec_probability: int = 8
    high_social_engineering_probability: int = 8
    urgency_detected: int = 5
    credential_request_detected: int = 8
    financial_request_detected: int = 8


@dataclass
class ThresholdsConfig:
    reputation: int = 70
    reputation_high: int = 80
    reputation_medium: int = 50
    phishing: float = 0.7
    phishing_high: float = 0.8
    phishing_medium: float = 0.6
    bec: float = 0.6
    bec_high: float = 0.7
    social_eng: float = 0.7
    social_eng_high: float = 0.8
    auth_fail_count: int = 2


@dataclass
class ScoringConfig:
    method: str = "capped"
    max_possible_override: Optional[int] = None


@dataclass
class LoggingConfig:
    level: str = "INFO"
    json_format: bool = False
    include_timestamp: bool = True


@dataclass
class LogicConfig:
    verdict_thresholds: VerdictThresholdsConfig = field(default_factory=VerdictThresholdsConfig)
    rule_weights: RuleWeightsConfig = field(default_factory=RuleWeightsConfig)
    thresholds: ThresholdsConfig = field(default_factory=ThresholdsConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


_config: Optional[LogicConfig] = None


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def _apply_env_overrides(config: LogicConfig) -> LogicConfig:
    # Verdict thresholds
    if v := os.getenv("TRINETRA_VERDICT_LOW_MAX"):
        config.verdict_thresholds.low_max = int(v)
    if v := os.getenv("TRINETRA_VERDICT_MEDIUM_MAX"):
        config.verdict_thresholds.medium_max = int(v)
    if v := os.getenv("TRINETRA_VERDICT_HIGH_MAX"):
        config.verdict_thresholds.high_max = int(v)
    if v := os.getenv("TRINETRA_VERDICT_CRITICAL_MAX"):
        config.verdict_thresholds.critical_max = int(v)

    # Rule weights (prefix: TRINETRA_WEIGHT_)
    for field_name in config.rule_weights.__dataclass_fields__:
        env_key = f"TRINETRA_WEIGHT_{field_name.upper()}"
        if v := os.getenv(env_key):
            setattr(config.rule_weights, field_name, int(v))

    # Thresholds (prefix: TRINETRA_THRESHOLD_)
    for field_name in config.thresholds.__dataclass_fields__:
        env_key = f"TRINETRA_THRESHOLD_{field_name.upper()}"
        if v := os.getenv(env_key):
            current = getattr(config.thresholds, field_name)
            if isinstance(current, float):
                setattr(config.thresholds, field_name, float(v))
            else:
                setattr(config.thresholds, field_name, int(v))

    # Scoring
    if v := os.getenv("TRINETRA_SCORING_METHOD"):
        config.scoring.method = v
    if v := os.getenv("TRINETRA_MAX_POSSIBLE_SCORE"):
        config.scoring.max_possible_override = int(v)

    # Logging
    if v := os.getenv("TRINETRA_LOG_LEVEL"):
        config.logging.level = v
    if v := os.getenv("TRINETRA_LOG_JSON"):
        config.logging.json_format = v.lower() in ("true", "1", "yes")
    if v := os.getenv("TRINETRA_LOG_TIMESTAMP"):
        config.logging.include_timestamp = v.lower() not in ("false", "0", "no")

    return config


def load_config(config_path: Optional[str] = None) -> LogicConfig:
    global _config
    if _config is not None:
        return _config

    config = LogicConfig()

    # Load from YAML if provided
    if config_path:
        yaml_path = Path(config_path)
    else:
        yaml_path = Path(__file__).parent.parent / "config.yaml"

    yaml_data = _load_yaml(yaml_path)

    if yaml_data:
        if vt := yaml_data.get("verdict_thresholds"):
            config.verdict_thresholds = VerdictThresholdsConfig(**vt)
        if rw := yaml_data.get("rule_weights"):
            config.rule_weights = RuleWeightsConfig(**rw)
        if th := yaml_data.get("thresholds"):
            config.thresholds = ThresholdsConfig(**th)
        if sc := yaml_data.get("scoring"):
            config.scoring = ScoringConfig(**sc)
        if lg := yaml_data.get("logging"):
            config.logging = LoggingConfig(**lg)

    # Apply environment variable overrides
    config = _apply_env_overrides(config)

    _config = config
    return config


def get_config() -> LogicConfig:
    if _config is None:
        return load_config()
    return _config


def reset_config() -> None:
    global _config
    _config = None
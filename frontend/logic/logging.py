from __future__ import annotations

import json
import logging
import sys
from typing import Any, Optional
from logic.config import get_config


class JsonFormatter(logging.Formatter):
    def __init__(self, include_timestamp: bool = True):
        super().__init__()
        self.include_timestamp = include_timestamp

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if self.include_timestamp:
            log_obj["timestamp"] = self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ")
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "lineno", "funcName", "created",
                "msecs", "relativeCreated", "thread", "threadName",
                "processName", "process", "message", "exc_info", "exc_text",
                "stack_info", "getMessage"
            ):
                log_obj[key] = value
        
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_obj, ensure_ascii=False)


def setup_logging(config: Optional[Any] = None) -> None:
    if config is None:
        config = get_config()
    
    log_config = config.logging
    
    level = getattr(logging, log_config.level.upper(), logging.INFO)
    
    # Clear existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create new handler
    handler = logging.StreamHandler(sys.stdout)
    
    if log_config.json_format:
        formatter = JsonFormatter(include_timestamp=log_config.include_timestamp)
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)
    root_logger.setLevel(level)
    
    # Set specific loggers
    logging.getLogger("logic").setLevel(level)
    logging.getLogger("uvicorn").setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


# Context manager for adding context to logs
class LogContext:
    def __init__(self, logger: logging.Logger, **context):
        self.logger = logger
        self.context = context
        self.old_factory = logging.getLogRecordFactory()
    
    def __enter__(self):
        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, *args):
        logging.setLogRecordFactory(self.old_factory)


# Convenience function for structured logging
def log_structured(logger: logging.Logger, level: int, message: str, **kwargs) -> None:
    extra = {k: v for k, v in kwargs.items() if not k.startswith("_")}
    logger.log(level, message, extra=extra)
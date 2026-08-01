#!/usr/bin/env python3
# lfuzzer/logger/__init__.py
# Melkor의 logger.c 대응. '어떤 메타데이터를 어떤 규칙으로 어떻게 변형했는지'를
# 런당 리포트(json + 사람이 읽는 txt)로 남긴다.
from .logger import FuzzLogger, Mutation

__all__ = ["FuzzLogger", "Mutation"]

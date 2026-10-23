"""Testable import surface; single-file downloaded agents retain the same tools."""
from companion.device_agent import MACOS_POSTURE_TOOLS as TOOLS
from companion.device_agent import macos_posture_command as command
from companion.device_agent import collect_macos_posture as collect
# Shared module objects allow deterministic command-provider tests.
from companion.device_agent import platform,subprocess

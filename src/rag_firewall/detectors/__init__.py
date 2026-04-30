"""Detector package: input, tool, and output defense layers."""
from .injection import ScanResult, scan_input, score_heuristic
from .output import OutputScanResult, scan_output
from .tools import ToolScanResult, scan_tools

__all__ = [
    "ScanResult",
    "OutputScanResult",
    "ToolScanResult",
    "scan_input",
    "score_heuristic",
    "scan_output",
    "scan_tools",
]

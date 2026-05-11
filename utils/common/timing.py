"""耗时统计工具。"""

import time


class MeasureTime:
    def __init__(self):
        self.start = None
        self.time_ms = 0.0

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *_):
        self.time_ms = (time.perf_counter() - self.start) * 1000


def measure_time():
    return MeasureTime()

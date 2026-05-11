"""TraceCollector：统一记录算法执行中间步骤。"""


class TraceCollector:
    def __init__(self, enabled: bool = True, level: int = 1):
        self.enabled = enabled
        self.level = level
        self.steps = []

    def add_step(self, name: str, data: dict = None):
        if not self.enabled:
            return
        step = {"name": name}
        if data:
            step.update(data)
        self.steps.append(step)

    def set_meta(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def to_dict(self) -> dict:
        if not self.enabled:
            return None
        result = {"steps": self.steps}
        for attr in ("algorithm", "operation", "input_summary", "output_summary", "params"):
            v = getattr(self, attr, None)
            if v is not None:
                result[attr] = v
        return result if result["steps"] or result.get("algorithm") else None

    @staticmethod
    def summarize_bytes(data: bytes, max_show: int = 16) -> dict:
        return {
            "len": len(data),
            "head_hex": data[:max_show].hex() if data else "",
        }

    @staticmethod
    def summarize_key(data: bytes, show: int = 8) -> dict:
        if len(data) <= show * 2:
            return {"len": len(data), "hex": data.hex()}
        return {
            "len": len(data),
            "head_hex": data[:show].hex(),
            "tail_hex": data[-show:].hex(),
        }

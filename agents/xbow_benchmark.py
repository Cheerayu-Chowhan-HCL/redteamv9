"""
XBow Benchmark — Phase 5.
Tracks per-engagement efficiency metrics for comparison against
the xbow.ai autonomous pentesting benchmark:
  - tool calls to first finding (target: <50)
  - total cost USD (target: <$0.50)
  - time to first finding
  - false positive rate
"""
import time


# GPT-4o pricing (per 1M tokens, as of 2026-06)
_COST_PER_1M_INPUT = 5.00
_COST_PER_1M_OUTPUT = 15.00

# Passing thresholds
THRESHOLD_TOOL_CALLS = 50
THRESHOLD_COST_USD = 0.50
THRESHOLD_TTFF_S = 600  # 10 minutes


class XBOWBenchmark:
    """Lightweight engagement profiler wired to xbow metrics."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time = time.time()
        self._tool_calls = 0
        self._first_finding_at: int | None = None
        self._first_finding_time: float | None = None
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._api_calls: list[dict] = []
        self._findings: list[dict] = []
        self._false_positives = 0

    # ── recording helpers ─────────────────────────────────────────────────────

    def record_tool_call(self):
        """Increment tool-call counter. Call once per MCP tool invocation."""
        self._tool_calls += 1

    def record_first_finding(self, severity: str = "medium",
                              title: str = ""):
        """Mark the point at which the first real finding was confirmed."""
        if self._first_finding_at is None:
            self._first_finding_at = self._tool_calls
            self._first_finding_time = time.time() - self.start_time
        self._findings.append({"severity": severity, "title": title,
                                "tool_call_index": self._tool_calls,
                                "elapsed_s": time.time() - self.start_time})

    def record_finding(self, severity: str = "medium", title: str = ""):
        """Record any finding (including post-first)."""
        if self._first_finding_at is None:
            self.record_first_finding(severity, title)
        else:
            self._findings.append({"severity": severity, "title": title,
                                    "tool_call_index": self._tool_calls,
                                    "elapsed_s": time.time() - self.start_time})

    def record_false_positive(self):
        self._false_positives += 1

    def record_api_call(self, input_tokens: int,
                        output_tokens_or_status: int = 0):
        """
        Record an OpenAI API call.
        record_api_call(input_tokens, output_tokens)  — standard
        record_api_call(input_tokens, 200)            — output_tokens treated
                                                        as 0 when value looks
                                                        like an HTTP status code
        """
        # If second arg looks like an HTTP status (100-599), treat output as 0
        if 100 <= output_tokens_or_status <= 599:
            output_tokens = 0
        else:
            output_tokens = output_tokens_or_status

        self._total_input_tokens += input_tokens
        self._total_output_tokens += output_tokens
        cost = (input_tokens / 1_000_000 * _COST_PER_1M_INPUT +
                output_tokens / 1_000_000 * _COST_PER_1M_OUTPUT)
        self._api_calls.append({
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost,
        })

    # ── metrics ───────────────────────────────────────────────────────────────

    def get_metrics(self) -> dict:
        """Return current benchmark metrics dict."""
        elapsed = time.time() - self.start_time
        total_cost = sum(a["cost_usd"] for a in self._api_calls)
        ttff = self._first_finding_time

        passing = {
            "tool_calls": self._tool_calls < THRESHOLD_TOOL_CALLS,
            "cost": total_cost < THRESHOLD_COST_USD,
            "ttff": (ttff is not None and ttff < THRESHOLD_TTFF_S)
                    if ttff is not None else False,
        }

        fp_rate = (self._false_positives / max(len(self._findings), 1)
                   if self._findings else 0.0)

        return {
            "session_id": self.session_id,
            "total_tool_calls": self._tool_calls,
            "tool_calls_to_first_finding": self._first_finding_at,
            "time_to_first_finding_s": round(ttff, 2) if ttff else None,
            "total_elapsed_s": round(elapsed, 2),
            "total_findings": len(self._findings),
            "false_positive_rate": round(fp_rate, 3),
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
            "estimated_cost_usd": round(total_cost, 6),
            "passing": passing,
            "thresholds": {
                "tool_calls": THRESHOLD_TOOL_CALLS,
                "cost_usd": THRESHOLD_COST_USD,
                "ttff_s": THRESHOLD_TTFF_S,
            },
        }

    def summary(self) -> str:
        m = self.get_metrics()
        p = m["passing"]
        lines = [
            f"Session: {m['session_id']}",
            f"Tool calls: {m['total_tool_calls']} "
            f"({'PASS' if p['tool_calls'] else 'FAIL'} <{THRESHOLD_TOOL_CALLS})",
            f"First finding at call #{m['tool_calls_to_first_finding']}",
            f"Cost: ${m['estimated_cost_usd']:.4f} "
            f"({'PASS' if p['cost'] else 'FAIL'} <${THRESHOLD_COST_USD})",
            f"Findings: {m['total_findings']} "
            f"(FP rate {m['false_positive_rate']:.1%})",
        ]
        return "\n".join(lines)

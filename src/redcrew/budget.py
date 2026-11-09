"""Conservative request budgeting for low-throughput provider accounts."""
import json
import sys
import math
import time
from contextlib import contextmanager
from crewai.hooks.dispatch import HookAborted


def compact_json_fragments(text):
    """Remove JSON formatting whitespace, preserving all decoded field values."""
    decoder = json.JSONDecoder()
    output = []
    cursor = 0
    while cursor < len(text):
        if text[cursor] in '{[':
            try:
                value, end = decoder.raw_decode(text, cursor)
            except ValueError:
                pass
            else:
                if isinstance(value, (dict, list)):
                    compact = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
                    original = text[cursor:end]
                    output.append(compact if len(compact) < len(original) else original)
                    cursor = end
                    continue
        output.append(text[cursor])
        cursor += 1
    return ''.join(output)


class RequestBudgetError(HookAborted):
    pass


class RequestBudget:
    def __init__(self, llm, *, tokens=7000, output_tokens=1200, interval=61, clock=time.monotonic, sleep=time.sleep, source_packets=None):
        if tokens <= output_tokens or output_tokens < 1 or interval < 0:
            raise ValueError('Invalid LLM budget settings')
        self.llm = llm
        self.tokens = tokens
        self.output_tokens = output_tokens
        self.interval = interval
        self.clock = clock
        self.sleep = sleep
        self.last_call = None
        self.source_packets = list(source_packets or [])
        self.adjustments = []

    def estimate(self, messages):
        return math.ceil(len(json.dumps(messages, ensure_ascii=True)) / 3) + 1800 + self.output_tokens

    def fit_sources(self, messages):
        """Shorten only registered research excerpts; never trim engagement evidence."""
        for length in (180, 80, 0):
            if self.estimate(messages) <= self.tokens - 200:
                return
            for index, original in enumerate(self.source_packets):
                rows = json.loads(original)
                shortened = []
                for row in rows:
                    item = dict(row)
                    if isinstance(item.get('excerpt'), str):
                        item['excerpt'] = item['excerpt'][:length]
                    shortened.append(item)
                replacement = json.dumps(shortened)
                if len(replacement) >= len(original):
                    continue
                variants = [original]
                for earlier in (180, 80):
                    variants.append(json.dumps([{**row, 'excerpt': row.get('excerpt', '')[:earlier]} for row in rows]))
                for message in messages:
                    content = message.get('content')
                    if isinstance(content, str):
                        for variant in variants:
                            if len(variant) > len(replacement):
                                content = content.replace(variant, replacement)
                        message['content'] = content

    def __call__(self, context):
        if context.llm is not self.llm:
            return None
        # Reserve space for tool definitions and the structured report schema.
        # This is a conservative heuristic, not a provider-exact tokenizer.
        estimate = self.estimate(context.messages)
        if estimate > self.tokens - 200 and self.source_packets:
            before = estimate
            self.fit_sources(context.messages)
            estimate = self.estimate(context.messages)
            if estimate < before:
                self.adjustments.append({'before': before, 'after': estimate, 'agent': getattr(getattr(context, 'agent', None), 'role', None)})
                print(f'Shortened ATT&CK excerpts to fit request budget ({before} -> {estimate}). Original evidence and source IDs retained.', file=sys.stderr)
        if estimate > self.tokens - 200:
            before = estimate
            for message in context.messages:
                if isinstance(message.get('content'), str):
                    message['content'] = compact_json_fragments(message['content'])
            estimate = self.estimate(context.messages)
            if estimate < before:
                self.adjustments.append({'before': before, 'after': estimate, 'method': 'lossless_json_compaction', 'agent': getattr(getattr(context, 'agent', None), 'role', None)})
                print(f'Compacted JSON formatting ({before} -> {estimate}); evidence values unchanged.', file=sys.stderr)
        if estimate > self.tokens:
            raise RequestBudgetError(
                f'Request estimate {estimate} exceeds local budget {self.tokens}. '
                'Reduce engagement/evidence size or task context. No evidence was silently truncated.'
            )
        if self.last_call is not None:
            remaining = self.interval - (self.clock() - self.last_call)
            if remaining > 0:
                print(f'Waiting {remaining:.0f}s for the provider token window...', file=sys.stderr)
                self.sleep(remaining)
        self.last_call = self.clock()
        return None


@contextmanager
def request_budget(llm, *, source_packets=None):
    import os
    from crewai.hooks.llm_hooks import register_before_llm_call_hook, unregister_before_llm_call_hook
    guard = RequestBudget(llm, tokens=int(os.getenv('LLM_REQUEST_TOKEN_BUDGET', '7000')),
                          output_tokens=int(os.getenv('LLM_MAX_TOKENS', '1200')),
                          interval=float(os.getenv('LLM_MIN_CALL_INTERVAL', '61')), source_packets=source_packets)
    register_before_llm_call_hook(guard)
    try:
        yield guard
    finally:
        unregister_before_llm_call_hook(guard)

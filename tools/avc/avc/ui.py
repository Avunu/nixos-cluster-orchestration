"""Every prompt and every line of output goes through here.

Flows never import questionary or rich directly, so the interaction style can
change in one place, and tests can script the answers (`scripted`) the way
clan's MOCK_PROMPT_RESPONSE does.
"""

from __future__ import annotations

import contextlib
import sys
from collections.abc import Iterator, Sequence
from typing import Any

from rich.console import Console
from rich.table import Table

from avc.errors import Aborted, AvcError

console = Console(stderr=True, highlight=False)

# Set by --yes: confirmations are taken as given; anything that needs a real
# answer (a choice, a value) must then come from the command line.
assume_yes = False

_script: list[Any] | None = None


@contextlib.contextmanager
def scripted(answers: Sequence[Any]) -> Iterator[None]:
    """Answer the next prompts from `answers`, in order (tests)."""
    global _script
    saved, _script = _script, list(answers)
    try:
        yield
        if _script:
            raise AssertionError(f"unused scripted answers: {_script}")
    finally:
        _script = saved


def _scripted_answer(question: str) -> Any:
    assert _script is not None
    if not _script:
        raise AssertionError(f"no scripted answer for: {question}")
    return _script.pop(0)


def _interactive(question: str) -> None:
    if not sys.stdin.isatty():
        raise AvcError(f"needs an answer but there is no terminal: {question}")


def _ask(q: Any) -> Any:
    answer = q.ask()
    if answer is None:
        raise Aborted
    return answer


# ── output ───────────────────────────────────────────────────────────────────


def header(text: str) -> None:
    console.rule(f"[bold]{text}")


def info(text: str) -> None:
    console.print(f"[cyan]→[/] {text}")


def ok(text: str) -> None:
    console.print(f"[green]✓[/] {text}")


def warn(text: str) -> None:
    console.print(f"[yellow]![/] {text}")


def err(text: str) -> None:
    console.print(f"[red]✗[/] {text}")


def say(text: str) -> None:
    console.print(f"  [dim]{text}[/]")


def out(text: str) -> None:
    """Command output proper (stdout, unstyled), e.g. a log tail."""
    print(text)


def table(title: str | None, columns: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    t = Table(title=title, title_justify="left", show_edge=False, pad_edge=False)
    for c in columns:
        t.add_column(c)
    for r in rows:
        t.add_row(*r)
    console.print(t)


@contextlib.contextmanager
def spin(text: str) -> Iterator[None]:
    if _script is not None or not console.is_terminal:
        info(text)
        yield
        return
    with console.status(text):
        yield


# ── input ────────────────────────────────────────────────────────────────────


def confirm(question: str, default: bool = False) -> bool:
    if _script is not None:
        return bool(_scripted_answer(question))
    if assume_yes:
        return True
    _interactive(question)
    import questionary

    return bool(_ask(questionary.confirm(question, default=default)))


def choose(question: str, choices: Sequence[str | tuple[str, Any]], default: Any = None) -> Any:
    """Pick one. A choice is a label, or (label, value)."""
    if _script is not None:
        return _scripted_answer(question)
    _interactive(question)
    import questionary

    opts = [questionary.Choice(c[0], value=c[1]) if isinstance(c, tuple) else c for c in choices]
    return _ask(questionary.select(question, choices=opts, default=default, use_shortcuts=len(opts) <= 9))


def checkbox(question: str, choices: Sequence[tuple[str, Any, bool]]) -> list[Any]:
    """Pick several. A choice is (label, value, checked)."""
    if _script is not None:
        return list(_scripted_answer(question))
    _interactive(question)
    import questionary

    opts = [questionary.Choice(label, value=value, checked=checked) for label, value, checked in choices]
    return list(_ask(questionary.checkbox(question, choices=opts)))


def text(question: str, default: str = "", validate: Any = None) -> str:
    if _script is not None:
        return str(_scripted_answer(question))
    _interactive(question)
    import questionary

    return str(_ask(questionary.text(question, default=default, validate=validate)))


def secret(question: str) -> str:
    """Hidden input, asked twice."""
    if _script is not None:
        return str(_scripted_answer(question))
    _interactive(question)
    import questionary

    while True:
        first = str(_ask(questionary.password(question)))
        if first == str(_ask(questionary.password("Again, to confirm"))):
            return first
        warn("the two entries differ; try again")


def type_to_confirm(what: str, word: str) -> None:
    """Destructive actions: the operator types the name back."""
    if _script is not None:
        answer = _scripted_answer(what)
    elif assume_yes:
        return
    else:
        _interactive(what)
        import questionary

        answer = _ask(questionary.text(f"{what} — type '{word}' to continue"))
    if answer != word:
        raise Aborted

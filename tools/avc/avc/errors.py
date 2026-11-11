class AvcError(Exception):
    """An expected failure: printed as a message, without a traceback."""


class Aborted(AvcError):
    """The operator backed out of a prompt (Ctrl-C or Esc)."""

    def __init__(self) -> None:
        super().__init__("aborted")

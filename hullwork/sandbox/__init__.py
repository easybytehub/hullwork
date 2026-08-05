"""The container the agent runs in, and how it comes to exist.

Split from the dispatcher because building an image and driving an attempt fail in different ways
and at different times: a build that cannot finish is a project problem the operator has to fix,
and it must be discovered *before* an attempt is spent rather than during one.
"""

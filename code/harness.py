# ============================================================================
# ExtPoCGen — harness.py
#
# The differential oracle: loads an extension in an isolated, instrumented
# headless Chrome (CDP), serves a local attacker page with a canary, probes the
# dangerous sinks, and concludes CONFIRMED only when the sink fires WITH the
# attacker AND not without it. This is the soundness core of the system.
#
# ----------------------------------------------------------------------------
# The full implementation of this module is intentionally withheld from the
# public release while the study is in progress.
#
#     Available on request: gnintezemo.m.rosly@aims-senegal.org
# ----------------------------------------------------------------------------

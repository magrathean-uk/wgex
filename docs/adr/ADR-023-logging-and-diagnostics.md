# ADR-023 Logging and diagnostics

Status: Accepted 2026-10-25

As revision 1, plus: exact-match redaction from the store before pattern redaction; base64url and unpadded key patterns; WS paths and SNIs treated as secrets; DNS configuration read via SCDynamicStore for bundles; per-uid filtering of daemon diagnostics and logs; long ring-buffer lines split with continuation markers so the redactor sees whole secrets.


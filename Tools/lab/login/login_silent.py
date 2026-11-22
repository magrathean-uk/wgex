# SPDX-License-Identifier: MIT
"""LOGIN-SILENT (DEC-021): the checks of the silent login launch row. Pure functions; no VM or network.

The observation is what the driver collected (verdict-live.Session.login_silent_row): the profile's Connect at login choice and
the Hide Dock icon preference read back from the app's own files (guest `gap-actions.sh login-item-state`), the loginwindow
reopen-state prevention applied before the first logout (so only the login item can start the app at login), and presentation
samples of the console session (guest `gap-actions.sh presentation`: whether WGEX runs, its standard and other windows from
System Events, its menu bar item, a running WGEX item in the Dock's list and the `lsappinfo` application type).

A sample is silent when WGEX runs with no window of any kind (standard, non-standard or unclassified), no running Dock item, an
application type other than Foreground and its menu bar item present. A window sample shows exactly one standard window with the menu bar item, and the Dock item and a
Foreground type exactly when the Dock icon is expected. Every check needs at least MIN_SAMPLES readable samples where it
judges a state, so a single lucky sample is never a pass; an unreadable or malformed sample is kept in the series and fails it,
never a pass and never dropped.
"""

MIN_SAMPLES = 2
VARIANTS = (("hideDockOff", False), ("hideDockOn", True))
APP_TYPES = ("Foreground", "UIElement", "BackgroundOnly")
INTEGER_KEYS = ("standardWindows", "otherWindows")
BOOLEAN_KEYS = ("menuBarItem", "dockItem")


def check(name, met, **evidence):
    return dict(name=name, met=bool(met), **evidence)


def parse_presentation(text):
    """One guest presentation sample as a dict. Unknown keys and malformed values are dropped; a sample without a readable
    process line, or with `presentation=failed`, keeps `readable` False."""
    sample = dict(readable=False)
    for line in (text or "").splitlines():
        key, sep, value = line.strip().partition("=")
        if not sep:
            continue
        if key == "sampledAt":
            try:
                sample[key] = float(value)
            except ValueError:
                pass
        elif key == "process" and value in ("running", "absent"):
            sample[key] = value
        elif key in INTEGER_KEYS and value.isdigit():
            sample[key] = int(value)
        elif key in BOOLEAN_KEYS and value in ("true", "false"):
            sample[key] = value == "true"
        elif key == "appType":
            sample[key] = value if value in APP_TYPES else "unknown"
        elif key == "presentation" and value == "failed":
            sample["failed"] = True
    running = sample.get("process") == "running" and all(key in sample for key in INTEGER_KEYS + BOOLEAN_KEYS) and "appType" in sample
    sample["readable"] = not sample.get("failed") and (running or sample.get("process") == "absent")
    return sample


def parse_login_item_state(text):
    """The guest `login-item-state` reply: autoConnectAtLogin and hideDockIcon as True, False or None (unset or unreadable)."""
    values = dict(autoConnectAtLogin=None, hideDockIcon=None)
    for line in (text or "").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key in values and value in ("true", "false"):
            values[key] = value == "true"
    return values


def silent(sample):
    return (isinstance(sample, dict) and sample.get("readable") is True and sample.get("process") == "running"
            and sample.get("standardWindows") == 0 and sample.get("otherWindows") == 0 and sample.get("dockItem") is False
            and sample.get("appType") in ("UIElement", "BackgroundOnly") and sample.get("menuBarItem") is True)


def window_shown(sample, dock):
    return (isinstance(sample, dict) and sample.get("readable") is True and sample.get("process") == "running"
            and sample.get("standardWindows") == 1 and sample.get("menuBarItem") is True and sample.get("dockItem") is dock
            and (sample.get("appType") == "Foreground") is dock and sample.get("appType") != "unknown")


def _samples(value):
    # Every entry is kept, malformed ones included, so the series check sees and fails them.
    return list(value) if isinstance(value, list) else []


def _all(samples, predicate):
    return len(samples) >= MIN_SAMPLES and all(predicate(sample) for sample in samples)


def login_silent_checks(observation, prevention_applied):
    """Named LOGIN-SILENT expectations. `prevention_applied(recorded)` re-derives the loginwindow reopen-state prevention from its
    recorded facts (verdict.relaunch_prevention_applied, the BOOT-SECRETS rule)."""
    observation = observation if isinstance(observation, dict) else {}
    row = observation.get("loginSilent") if isinstance(observation.get("loginSilent"), dict) else {}
    checks = []
    configured = row.get("loginItem") if isinstance(row.get("loginItem"), dict) else {}
    checks.append(check("loginItemConfigured", configured.get("autoConnectAtLogin") is True, autoConnectAtLogin=configured.get("autoConnectAtLogin")))
    recorded = observation.get("relaunchPrevention")
    applied = prevention_applied(recorded if isinstance(recorded, dict) else {})
    item = check("reopenRelaunchPrevented", applied, relaunchPrevention=recorded if isinstance(recorded, dict) else None)
    if not applied:
        item["gap"] = ("relaunchPreventionNotApplied: loginwindow could reopen the app at login, so a launch after login would not be "
                       "the login item's")
    checks.append(item)
    ordinary = _samples((row.get("ordinaryLaunch") or {}).get("samples") if isinstance(row.get("ordinaryLaunch"), dict) else None)
    checks.append(check("ordinaryLaunchShowsWindowOnce", _all(ordinary, lambda sample: window_shown(sample, True)), samples=ordinary))
    variants = row.get("variants") if isinstance(row.get("variants"), dict) else {}
    for name, hide in VARIANTS:
        variant = variants.get(name) if isinstance(variants.get(name), dict) else {}
        state = variant.get("loginItem") if isinstance(variant.get("loginItem"), dict) else {}
        checks.append(check("hideDockIconSet:" + name, state.get("hideDockIcon") is hide and state.get("autoConnectAtLogin") is True,
                            hideDockIcon=state.get("hideDockIcon"), autoConnectAtLogin=state.get("autoConnectAtLogin")))
        checks.append(check("loggedOutAndIn:" + name, variant.get("loggedOut") is True and variant.get("loggedIn") is True,
                            loggedOut=variant.get("loggedOut"), loggedIn=variant.get("loggedIn")))
        launched = variant.get("loginLaunchSeen") is True
        after = _samples(variant.get("afterLogin"))
        item = check("silentAfterLogin:" + name, launched and _all(after, silent), loginLaunchSeen=variant.get("loginLaunchSeen"), samples=after)
        if not launched:
            item["gap"] = "loginLaunchMissing: no WGEX process appeared after login, so the login item did not start the app"
        checks.append(item)
        opened = _samples(variant.get("fromMenu"))
        checks.append(check("windowFromMenu:" + name, variant.get("menuOpened") is True and _all(opened, lambda sample: window_shown(sample, not hide)),
                            menuOpened=variant.get("menuOpened"), dockExpected=not hide, samples=opened))
    return checks

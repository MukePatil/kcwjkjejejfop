r"""
Pre/Post Network Change Validation Report Generator
=====================================================
Parses pre-check and post-check device logs, compares a fixed allowlist of
commands, and produces a single self-contained HTML dashboard for NOC
engineers: dashboard summary, per-device health cards, down/missing
callouts (interfaces, OSPF neighbors, IP routes, VLANs, BGP sessions, CDP
neighbors), collapsible side-by-side diffs, search/filter, and a footer
with run metadata.

Precheck/postcheck filenames do NOT need to match exactly — only the
device identifier (FQDN or IP) embedded in the filename needs to be the
same. Everything else in the name (parentheses, "-pre"/"-post"/
"precheck"/"postcheck" markers, capture timestamps, extensions) is
ignored automatically, so e.g.:
    (lcaschc403.ntwk.kp.org)-pre
    (lcaschc403.ntwk.kp.org)-post
and:
    192.168.50.212__20260630_110428   (precheck)
    192.168.50.212__20260630_093027   (postcheck)
are each paired as the same device instead of being skipped/mismatched.

Run on a machine with access to PRE_DIR / POST_DIR (edit the paths below,
or override everything from the command line — run with --help):

    python PrePostValidation1.py
    python PrePostValidation1.py --pre-dir D:\pre --post-dir D:\post -o report.html
    python PrePostValidation1.py --json-summary results.json --workers 8 -v

Log files for pre/post are parsed in parallel (thread pool) for faster
runs against large device counts. A machine-readable JSON summary can be
written alongside the HTML report via --json-summary, for feeding
tickets/alerts/dashboards. The process exit code reflects the outcome
(0 = all passed, 1 = differences only, 2 = critical/missing, 3 = setup
error such as a missing directory) so this script can be dropped into a
scheduler or CI pipeline and reacted to programmatically.

Software version upgrade verification: "show version" is parsed on both
sides and rolled up into a header panel so a maintenance window can be
confirmed complete at a glance — e.g. "42/42 devices confirmed upgraded,
17.12.04 -> 17.15.05". Any device whose version did NOT change, couldn't
be read, or (with --expected-version) landed on the wrong target is
called out by name in that same panel and on its device card, and counts
toward a critical (exit code 2) result so nothing gets missed silently:

    python PrePostValidation1.py --expected-version 17.15.5
"""

import re
import os
import sys
import html
import json
import time
import shutil
import difflib
import logging
import argparse
import platform
import tempfile
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# =====================================================
# CONFIGURATION
# =====================================================
# These are DEFAULTS. All of them can be overridden at run time via
# command-line flags (see parse_args() / main()) without editing this
# file, e.g.:
#   python PrePostValidation1.py --pre-dir D:\pre --post-dir D:\post
#   python PrePostValidation1.py --json-summary results.json --workers 8
#   python PrePostValidation1.py --config myrun.json

PRE_DIR = r"C:\Logs\Prechecks"
POST_DIR = r"C:\Logs\postcheck"

REPORT_FILE = "PrePost_Validation_Report.html"

SCRIPT_VERSION = "3.3.0"

# Default number of worker threads used to parse log files in parallel.
# File parsing is I/O-bound (mostly waiting on disk reads), so a thread
# pool gives a real speedup for hundreds of devices without the
# complexity of multiprocessing.
DEFAULT_WORKERS = 8

# Process exit codes, useful when this script is invoked from a
# scheduler / CI pipeline / monitoring system that wants to react to
# the outcome instead of parsing stdout:
#   0 = every compared device passed with no differences
#   1 = differences found, but nothing critical (no down/missing items)
#   2 = at least one device is FAILED or MISSING data (critical)
#   3 = script could not run at all (bad paths, no files found, etc.)
EXIT_OK = 0
EXIT_CHANGED = 1
EXIT_CRITICAL = 2
EXIT_SETUP_ERROR = 3

log = logging.getLogger("prepost_validation")

# =====================================================
# ALLOWLIST — only these commands are parsed/compared.
# Everything else in the logs is ignored automatically.
# =====================================================

COMPARE_COMMANDS = [
    "show version",
    "show inventory",
    "show ip interface brief",
    "show interfaces status",
    "show interfaces description",
    "show interfaces trunk",
    "show logging",
    "show cdp neighbors detail",
    "show module",
    "show vlan brief",
    "show vtp status",
    "show boot",
    "show environment all",
    "show power inline",
    "show spanning-tree detail",
    "show spanning-tree",
    "show ip route",
    "show ip ospf neighbor",
    "show ip bgp summary",
    "show running-config",
]
# Normalize once for fast matching.
_COMPARE_COMMANDS_NORM = sorted({c.strip().lower() for c in COMPARE_COMMANDS},
                                 key=len, reverse=True)

# Commands whose output lines represent individual interfaces — used to
# pull specific down-interface names for the health cards / header alert.
INTERFACE_STATUS_COMMANDS = {
    "show ip interface brief",
    "show interfaces status",
    "show interfaces description",
    "show interfaces trunk",
    "show power inline",
    "show spanning-tree detail",
    "show spanning-tree",
}

# Specific single commands that get their own structured (not just raw-line)
# down/missing detection, in addition to the normal side-by-side diff.
CMD_OSPF = "show ip ospf neighbor"
CMD_ROUTE = "show ip route"
CMD_VLAN = "show vlan brief"
CMD_BGP = "show ip bgp summary"
CMD_CDP = "show cdp neighbors detail"

# =====================================================
# CRITICAL WORDS — presence of any of these in a changed
# line marks that line (and the device) critical/failed.
# =====================================================

CRITICAL_KEYWORDS = [
    "down",
    "failed",
    "error",
    "inactive",
    "shutdown",
    "err-disabled",
    "notconnect",
]

# OSPF neighbor states that indicate a stuck/bad adjacency (FULL and 2-WAY
# are healthy end states, everything below is transitional-or-worse).
BAD_OSPF_STATES = ("DOWN", "INIT", "ATTEMPT", "EXSTART", "EXCHANGE", "LOADING")

# VLAN statuses that indicate the VLAN is not passing traffic normally.
BAD_VLAN_STATUS = ("SHUTDOWN", "SUSPEND", "INACTIVE")

# =====================================================
# REGEX
# =====================================================

# Matches a device-prompt line like "SW01#show ip interface brief"
COMMAND_PATTERN = re.compile(
    r"^(.+?)[#>]\s*(show|terminal|dir|copy|ping|conf|exit).*",
    re.IGNORECASE
)

# Matches typical Cisco-style interface names at the start of a line,
# e.g. Gi1/0/12, Te1/1/1, Fa0/1, Eth1/1, Po10, Vl100
INTERFACE_NAME_RE = re.compile(
    r"^\s*([A-Za-z]{2,6}[\d/]+(?:\.\d+)?)\b"
)

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
ROUTE_PREFIX_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}")

# "show ip ospf neighbor" — NeighborID  Pri  State  DeadTime  Address  Interface
OSPF_NEIGHBOR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\S+)")

# Pulls the software/OS version string out of "show version" output.
# Matches the common Cisco phrasings, e.g.:
#   "Cisco IOS Software, Version 17.12.04"
#   "Cisco IOS XE Software, Version 17.15.5"
#   "NXOS: version 9.3(8)"
#   "Cisco IOS XR Software, Version 7.9.2"
SH_VERSION_RE = re.compile(
    r"\bversion\s+([A-Za-z0-9][A-Za-z0-9.()\-]*)",
    re.IGNORECASE
)

# =====================================================
# HELPERS — generic
# =====================================================

# A handful of very common Cisco-style abbreviations that don't reduce to
# a clean word-prefix of their canonical COMPARE_COMMANDS entry (so the
# generic abbreviation matching in canonical_command() below can't catch
# them on its own), e.g. "show run" vs "show running-config" — "run" is
# not followed by a space in "running-config". Extend this table if your
# devices/engineers commonly type other short forms.
_COMMAND_ALIASES = {
    "show run": "show running-config",
    "sh run": "show running-config",
    "show ver": "show version",
    "sh ver": "show version",
    "show inv": "show inventory",
    "sh inv": "show inventory",
}


def canonical_command(command):
    """
    Resolve `command` (as typed/captured in a log) to the single
    COMPARE_COMMANDS entry it refers to, or return None if it doesn't
    match any allowlisted command.

    This is what lets precheck and postcheck logs use DIFFERENT phrasing
    for the same logical command and still be compared against each
    other instead of being treated as two unrelated commands, e.g.:
        "show vlan brief"  (precheck)
        "show vlan"        (postcheck)
    both resolve to the same canonical key ("show vlan brief") instead
    of creating two separate, unmatched dictionary entries — which is
    what previously caused every VLAN to be reported as "missing from
    postcheck" any time the two sides simply used different command text.

    Two directions are handled:
      1. `command` IS the canonical command, or an extension of it
         (e.g. "show running-config all" -> "show running-config").
      2. `command` is a SHORTER/abbreviated form of the canonical
         command (e.g. "show vlan" -> "show vlan brief"). This is only
         accepted when it is unambiguous — i.e. it is a word-boundary
         prefix of exactly ONE canonical command. A vague fragment like
         "show ip" matches several canonical commands ("show ip
         interface brief", "show ip route", "show ip ospf neighbor",
         "show ip bgp summary") and is deliberately left unmatched
         rather than guessing.
    """
    c = command.strip().lower()

    if c in _COMMAND_ALIASES:
        return _COMMAND_ALIASES[c]

    # Direction 1: command is the canonical form, or extends it.
    for allowed in _COMPARE_COMMANDS_NORM:
        if c == allowed or c.startswith(allowed + " "):
            return allowed

    # Direction 2: command is a shorter/abbreviated form of a canonical
    # command — only accepted if it's an unambiguous match.
    matches = [allowed for allowed in _COMPARE_COMMANDS_NORM
               if allowed.startswith(c + " ")]
    if len(matches) == 1:
        return matches[0]
    return None


def is_allowed_command(command):
    """Return True if `command` matches (or starts with, or abbreviates)
    an allowlisted command."""
    return canonical_command(command) is not None


def cmd_is(command, target):
    """Return True if `command` is (or starts with) the exact target command."""
    c = command.strip().lower()
    return c == target or c.startswith(target + " ")


def line_is_critical(line):
    low = line.lower()
    return any(word in low for word in CRITICAL_KEYWORDS)


def extract_interface_name(line):
    m = INTERFACE_NAME_RE.match(line)
    if m:
        return m.group(1)
    parts = line.strip().split()
    return parts[0] if parts else None


def extract_sh_version(lines):
    """
    Scan the raw lines of a 'show version' capture and return the software
    version string (e.g. "17.12.04"), or None if no version line is found.
    Only the first match is used — "show version" output normally contains
    exactly one authoritative version line near the top.
    """
    for line in lines:
        m = SH_VERSION_RE.search(line)
        if m:
            return m.group(1).rstrip(",.")
    return None


def dedupe_preserve_order(items):
    seen = set()
    out = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out

# =====================================================
# FILENAME -> DEVICE KEY NORMALIZATION
# =====================================================
# Precheck/postcheck filenames do NOT need to match at all beyond
# sharing the same device identifier (FQDN or IP) somewhere in the
# name. Everything else in the filename -- parentheses, "-pre"/"-post"/
# "precheck"/"postcheck" markers, capture timestamps, run numbers, file
# extensions -- is ignored automatically. For example, all of these
# resolve to the SAME device key:
#
#   (lcaschc403.ntwk.kp.org)-pre
#   (lcaschc403.ntwk.kp.org)-post
#   lcaschc403.ntwk.kp.org_postcheck_20260630_110428.txt
#
# and:
#
#   192.168.50.212__20260630_110428   (precheck)
#   192.168.50.212__20260630_093027   (postcheck)
#
# are correctly treated as the SAME device even though the timestamp
# suffix is different.

# Strips a small set of common log-file extensions (IPs/FQDNs contain
# dots too, so we can't just use Path.suffix — that would chew off part
# of an identifier).
_KNOWN_LOG_EXTENSIONS_RE = re.compile(r"\.(log|txt|cfg|out)$", re.IGNORECASE)

# Strips a trailing timestamp block: an 8-digit date (YYYYMMDD) optionally
# followed by a 6-digit time (HHMMSS), preceded by one or more separator
# characters (_, -, ., or whitespace).
_FILENAME_TIMESTAMP_RE = re.compile(
    r"[_\-\.\s]+\d{8}[_\-\.\s]?\d{6}?[_\-\.\s]*$"
)

# Strips a leading/trailing "pre"/"post"/"precheck"/"postcheck"/"before"/
# "after" marker (whole word only — so a hostname that merely CONTAINS
# "pre"/"post" as a substring, e.g. "PRESTON01", is never touched). Used
# both as a fallback for dot-less hostnames and to trim a stray
# ".pre"/".post" label that an FQDN-shaped match might have picked up.
# NOTE: same explicit-boundary reasoning as the IPv4/FQDN regexes above
# — \b treats '_' as a word character, so "SW01_pre" would not count
# "pre" as a separate word under \b. (?<![A-Za-z0-9]) / (?![A-Za-z0-9])
# correctly treat '_' (and '-', '.', whitespace) as separators.
_PRE_POST_MARKER_RE = re.compile(
    r"^[_\-\.\s]*(?<![A-Za-z0-9])(?:pre|post|precheck|postcheck|before|after)(?![A-Za-z0-9])[_\-\.\s]*"
    r"|[_\-\.\s]*(?<![A-Za-z0-9])(?:pre|post|precheck|postcheck|before|after)(?![A-Za-z0-9])[_\-\.\s]*$",
    re.IGNORECASE
)

# Matches an IPv4 address anywhere in the filename. Checked first — an
# IP is unambiguous and needs no further cleanup.
# NOTE: uses explicit (?<![A-Za-z0-9]) / (?![A-Za-z0-9]) boundaries
# instead of \b — \b treats '_' as a "word" character, which would
# otherwise truncate the match right before an underscore-joined
# timestamp (e.g. "192.168.50.212__20260630" would wrongly stop at
# "192.168.50").
_FQDN_FILENAME_IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9])(\d{1,3}(?:\.\d{1,3}){3})(?![A-Za-z0-9])"
)

# Matches an FQDN-shaped token: dot-separated hostname labels
# (letters/digits/hyphens), requiring at least one dot (2+ labels), e.g.
# "lcaschc403.ntwk.kp.org". Deliberately excludes '(' ')' '_' whitespace
# etc., so surrounding punctuation / "-pre" / "-post" / timestamp text
# simply falls outside the match instead of needing its own strip rule.
# Same explicit-boundary reasoning as the IPv4 regex above.
_FQDN_FILENAME_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![A-Za-z0-9])"
)


def device_key_from_filename(filename):
    """
    Derive a canonical device identifier (FQDN or IP) from a log
    filename, ignoring everything else in the name.

    Order of operations:
      1. Strip a known trailing file extension (repeatable, in case of
         stacked suffixes).
      2. If an IPv4 address appears anywhere in the name, use it — it's
         unambiguous.
      3. Otherwise look for an FQDN-shaped token (dot-separated labels)
         anywhere in the name and take the LONGEST match, so a real
         multi-label FQDN wins over an incidental look-alike such as a
         leftover "pre.log". Any trailing ".pre"/".post"/etc. label the
         match happened to pick up is trimmed off afterward.
      4. If neither an IP nor an FQDN token is found (a bare hostname
         with no dots at all), fall back to stripping a trailing
         capture timestamp and a leading/trailing
         "pre"/"post"/"precheck"/"postcheck" marker, then use whatever
         text is left.

    Case is not treated as significant (the key is upper-cased), so
    "lcaschc403.ntwk.kp.org" and "LCASCHC403.NTWK.KP.ORG" pair up.
    """
    name = filename.strip()

    prev = None
    while prev != name:
        prev = name
        name = _KNOWN_LOG_EXTENSIONS_RE.sub("", name)

    ip_match = _FQDN_FILENAME_IPV4_RE.search(name)
    if ip_match:
        return ip_match.group(1)

    candidates = _FQDN_FILENAME_TOKEN_RE.findall(name)
    if candidates:
        best = max(candidates, key=len)
        best = _PRE_POST_MARKER_RE.sub("", best).strip("_-. ")
        if best:
            return best.upper()

    # Fallback: no FQDN/IP found anywhere — bare hostname with no dots.
    # Strip timestamp + pre/post marker + stray punctuation/parentheses.
    prev = None
    while prev != name:
        prev = name
        name = _FILENAME_TIMESTAMP_RE.sub("", name)
        name = _PRE_POST_MARKER_RE.sub("", name)
    name = name.strip("_-. ()")
    return name.upper()


def remap_devices_to_filename_key(file_data, path):
    """
    Re-key a single parsed file's device data using the device identifier
    embedded in its FILENAME (FQDN/IP, timestamp stripped) instead of
    whatever hostname string was captured from the CLI prompt inside the
    log body. This is what lets precheck/postcheck files pair up
    correctly even when:
      - the two filenames carry different capture timestamps
      - the in-log prompt format differs slightly between runs (short
        hostname vs FQDN vs IP, extra whitespace, etc.)

    Only applied when the file contains a SINGLE device — if a file has
    multiple devices' output batched together, there's no reliable way to
    split the filename's one identifier across them, so those stay keyed
    by their in-content hostnames.
    """
    if len(file_data) != 1:
        return file_data
    key = device_key_from_filename(path.name)
    if not key:
        return file_data
    ((_, cmds),) = file_data.items()
    return {key: cmds}


def collect_log_files(directory):
    """
    All files directly inside `directory`, regardless of extension (or
    lack thereof) — precheck/postcheck filenames only need to share a
    device identifier, not a naming convention or extension.
    """
    p = Path(directory)
    if not p.is_dir():
        log.warning("Directory not found (or not a directory): %s", directory)
        return []
    files = sorted(f for f in p.iterdir() if f.is_file() and not f.name.startswith("."))
    if not files:
        log.warning("No files found in: %s", directory)
    return files

# =====================================================
# HELPERS — structured "down / missing" detectors
# =====================================================
# Each of these compares the pre-check and post-check output of ONE command
# for ONE device and returns a list of human-readable issue strings. They
# key off parsed identifiers (neighbor ID, route prefix, VLAN ID, etc.)
# rather than raw line position, so output reordering doesn't create noise.

def extract_ospf_neighbors(lines):
    """{neighbor_id: state}"""
    neighbors = {}
    for line in lines:
        m = OSPF_NEIGHBOR_RE.match(line.strip())
        if m:
            neighbors[m.group(1)] = m.group(2)
    return neighbors


def ospf_issues(pre_lines, post_lines):
    pre_n = extract_ospf_neighbors(pre_lines)
    post_n = extract_ospf_neighbors(post_lines)
    issues = []
    for nid in pre_n:
        if nid not in post_n:
            issues.append(f"{nid} (neighbor lost)")
    for nid, state in post_n.items():
        if not any(b in state.upper() for b in BAD_OSPF_STATES):
            continue
        # Skip neighbors that were ALREADY in a bad state pre-change —
        # that's a pre-existing condition, not something this change
        # caused, so don't re-flag it every run.
        pre_state = pre_n.get(nid)
        pre_was_bad = pre_state is not None and any(
            b in pre_state.upper() for b in BAD_OSPF_STATES
        )
        if not pre_was_bad:
            issues.append(f"{nid} (state: {state})")
    return issues


def extract_routes(lines):
    """set of route prefixes, e.g. 10.0.0.0/24"""
    routes = set()
    for line in lines:
        m = ROUTE_PREFIX_RE.search(line)
        if m:
            routes.add(m.group(0))
    return routes


def route_issues(pre_lines, post_lines):
    pre_r = extract_routes(pre_lines)
    post_r = extract_routes(post_lines)
    missing = sorted(pre_r - post_r)
    return [f"{route} (missing from postcheck)" for route in missing]


def extract_vlans(lines):
    """{vlan_id: (name, status)}"""
    vlans = {}
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0].isdigit():
            vid = int(parts[0])
            if 1 <= vid <= 4094:
                vlans[parts[0]] = (parts[1], parts[2])
    return vlans


def vlan_issues(pre_lines, post_lines):
    pre_v = extract_vlans(pre_lines)
    post_v = extract_vlans(post_lines)
    issues = []
    for vid, (name, _status) in pre_v.items():
        if vid not in post_v:
            issues.append(f"VLAN {vid} ({name}) missing from postcheck")
    for vid, (name, status) in post_v.items():
        if not any(b in status.upper() for b in BAD_VLAN_STATUS):
            continue
        # Skip VLANs that were ALREADY bad pre-change — pre-existing
        # condition, not caused by this change, so don't re-flag it.
        pre_entry = pre_v.get(vid)
        pre_was_bad = pre_entry is not None and any(
            b in pre_entry[1].upper() for b in BAD_VLAN_STATUS
        )
        if not pre_was_bad:
            issues.append(f"VLAN {vid} ({name}) status: {status}")
    return issues


def extract_interface_status(lines):
    """
    {interface_name: (full_line, is_critical)} built from any line that
    starts with an interface-shaped token (Gi1/0/12, Te1/1/1, Vl100,
    ...). Used to compare an interface's state PRE vs POST by identity
    rather than by raw line position, so a reordered line doesn't look
    like a change and — more importantly — so we know what that same
    interface's state was on the other side of the change window.
    """
    status = {}
    for line in lines:
        iface = extract_interface_name(line)
        if not iface:
            continue
        status[iface] = (line, line_is_critical(line))
    return status


def interface_down_transitions(pre_lines, post_lines):
    """
    Return the interface names that went from a healthy (non-critical)
    or absent state in the precheck to a critical/down state in the
    postcheck -- i.e. an actual UP -> DOWN transition.

    An interface that was ALREADY down/critical in the precheck and is
    still down/critical in the postcheck is deliberately EXCLUDED: that
    is a pre-existing condition the maintenance window didn't cause, so
    it shouldn't be raised as a new "down interface" alert every time
    a counter or timestamp on that same line ticks over.
    """
    pre_status = extract_interface_status(pre_lines)
    post_status = extract_interface_status(post_lines)
    transitioned = []
    for iface, (_post_line, post_crit) in post_status.items():
        if not post_crit:
            continue
        pre_entry = pre_status.get(iface)
        pre_crit = pre_entry[1] if pre_entry else False
        if not pre_crit:
            transitioned.append(iface)
    return transitioned


    """{neighbor_ip: state_or_pfxrcd}"""
    neighbors = {}
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 2 and IPV4_RE.match(parts[0]):
            neighbors[parts[0]] = parts[-1]
    return neighbors


def bgp_issues(pre_lines, post_lines):
    pre_b = extract_bgp_neighbors(pre_lines)
    post_b = extract_bgp_neighbors(post_lines)
    issues = []
    for nid in pre_b:
        if nid not in post_b:
            issues.append(f"{nid} (session lost)")
    for nid, state in post_b.items():
        # A numeric State/PfxRcd column means the session is up and
        # exchanging prefixes; anything else (Idle, Active, Connect, ...)
        # means the session is down.
        if state.replace(".", "").isdigit():
            continue
        # Skip sessions that were ALREADY down pre-change — pre-existing
        # condition, not caused by this change, so don't re-flag it.
        pre_state = pre_b.get(nid)
        pre_was_down = pre_state is not None and not pre_state.replace(".", "").isdigit()
        if not pre_was_down:
            issues.append(f"{nid} (state: {state})")
    return issues


def extract_cdp_neighbors(lines):
    """set of neighbor device IDs from 'show cdp neighbors detail'"""
    neighbors = set()
    for line in lines:
        s = line.strip()
        if s.lower().startswith("device id:"):
            neighbors.add(s.split(":", 1)[1].strip())
    return neighbors


def cdp_issues(pre_lines, post_lines):
    pre_c = extract_cdp_neighbors(pre_lines)
    post_c = extract_cdp_neighbors(post_lines)
    missing = sorted(pre_c - post_c)
    return [f"{n} (neighbor lost)" for n in missing]

# =====================================================
# LOG PARSING
# =====================================================

def parse_log(filename):
    """
    Parse a single log file into: { DEVICE_NAME: { command: [output lines] } }
    Only allowlisted commands are retained — everything else is dropped as
    it is parsed, so it never touches memory beyond the current line.

    Output is stored under the CANONICAL command name (see
    canonical_command()), not the raw text typed at the prompt. This is
    what lets "show vlan brief" (precheck) and "show vlan" (postcheck) —
    or "show running-config" vs "show running-config all", etc. — land
    in the same bucket and get diffed against each other, instead of
    being treated as two unrelated commands (which previously made
    every VLAN/route/etc. on one side look "missing" from the other).
    """
    devices = {}
    device = "UNKNOWN"
    command = None
    command_allowed = False

    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.rstrip()
            match = COMMAND_PATTERN.match(line)

            if match:
                device = match.group(1).strip().upper()

                if "#" in line:
                    typed_command = line.split("#", 1)[1].strip()
                elif ">" in line:
                    typed_command = line.split(">", 1)[1].strip()
                else:
                    typed_command = line.strip()

                command = canonical_command(typed_command)
                command_allowed = command is not None

                if command_allowed:
                    devices.setdefault(device, {})
                    devices[device].setdefault(command, [])
            else:
                if command and command_allowed:
                    devices[device][command].append(line)

    return devices


def merge_device_data(global_data, file_data):
    """
    Merge a single file's parsed data into the global per-device dataset.
    This is what prevents duplicate device sections when a device's output
    is split across multiple log files: each device is merged into one
    entry instead of being appended as a new section per file.
    """
    for device, cmds in file_data.items():
        bucket = global_data.setdefault(device, {})
        for cmd, lines in cmds.items():
            # If the same command shows up twice for a device (e.g. split
            # across files), the most recently parsed copy wins.
            bucket[cmd] = lines

def parse_and_merge_all(paths, workers):
    """
    Parse a list of log files in parallel (I/O-bound, so a thread pool
    helps even under the GIL) and merge them into a single per-device
    dataset. Parsing order doesn't matter for correctness (each file is
    independent), but the merge step is done back on the main thread in
    completion order, matching merge_device_data()'s "last parsed copy
    wins" behavior for a command that appears in more than one file.
    """
    global_data = {}
    if not paths:
        return global_data

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        future_to_path = {pool.submit(parse_log, path): path for path in paths}
        for future in as_completed(future_to_path):
            path = future_to_path[future]
            try:
                file_data = future.result()
            except Exception:
                log.exception("Failed to parse %s — skipping this file.", path)
                continue
            file_data = remap_devices_to_filename_key(file_data, path)
            merge_device_data(global_data, file_data)

    return global_data

# =====================================================
# DIFF RENDERING
# =====================================================

def diff_opcodes_html(pre_lines, post_lines, cmd_id, transitioned_interfaces=None):
    """
    Build the side-by-side diff table body for one command.
    Returns (body_html, hidden_html, changed_bool, critical_bool, down_interfaces_list).
    Equal (unchanged) runs are rendered but collapsed by default.

    transitioned_interfaces: for INTERFACE_STATUS_COMMANDS, the caller
    pre-computes (via interface_down_transitions()) the set of
    interfaces that genuinely went UP -> DOWN between pre and post.
    When this is provided, a critical-looking line only counts toward
    `critical`/`down_interfaces` if its interface is in that set — an
    interface that was already down pre-change and is still down
    post-change (e.g. only a byte counter in the line changed) is
    rendered as a normal modification, not flagged as a new outage.
    Pass None (the default) to keep the old behavior for commands with
    no interface concept, e.g. "show logging".
    """
    sm = difflib.SequenceMatcher(None, pre_lines, post_lines)
    rows_visible = []
    rows_hidden = []
    changed = False
    critical = False
    down_interfaces = []

    def _counts_as_down(line):
        """True if this critical-looking line should actually be flagged."""
        if transitioned_interfaces is None:
            return True
        iface = extract_interface_name(line)
        return iface is not None and iface in transitioned_interfaces

    for tag, a, b, c, d in sm.get_opcodes():
        if tag == "equal":
            for x in pre_lines[a:b]:
                rows_hidden.append(
                    f'<tr class="diff-same"><td>{html.escape(x)}</td><td>{html.escape(x)}</td></tr>'
                )
            continue

        changed = True

        if tag == "insert":
            for line in post_lines[c:d]:
                is_crit = line_is_critical(line) and _counts_as_down(line)
                css = "diff-critical" if is_crit else "diff-added"
                if is_crit:
                    critical = True
                    iface = extract_interface_name(line)
                    if iface:
                        down_interfaces.append(iface)
                rows_visible.append(
                    f'<tr class="{css}"><td class="empty-cell">&mdash;</td>'
                    f'<td>{html.escape(line)}</td></tr>'
                )

        elif tag == "delete":
            for line in pre_lines[a:b]:
                is_crit = line_is_critical(line) and _counts_as_down(line)
                css = "diff-critical" if is_crit else "diff-removed"
                if is_crit:
                    critical = True
                    iface = extract_interface_name(line)
                    if iface:
                        down_interfaces.append(iface)
                rows_visible.append(
                    f'<tr class="{css}"><td>{html.escape(line)}</td>'
                    f'<td class="empty-cell">&mdash;</td></tr>'
                )

        else:  # replace
            old = pre_lines[a:b]
            new = post_lines[c:d]
            length = max(len(old), len(new))
            for i in range(length):
                p = old[i] if i < len(old) else ""
                q = new[i] if i < len(new) else ""
                is_crit = (line_is_critical(p) or line_is_critical(q)) and _counts_as_down(q or p)
                css = "diff-critical" if is_crit else "diff-modified"
                if is_crit:
                    critical = True
                    iface = extract_interface_name(q or p)
                    if iface:
                        down_interfaces.append(iface)
                rows_visible.append(
                    f'<tr class="{css}"><td>{html.escape(p)}</td>'
                    f'<td>{html.escape(q)}</td></tr>'
                )

    body_html = "".join(rows_visible)
    hidden_html = ""
    if rows_hidden:
        hidden_html = f"""
        <tr class="unchanged-toggle-row">
          <td colspan="2">
            <button type="button" class="unchanged-toggle" onclick="toggleUnchanged('{cmd_id}')">
              Show {len(rows_hidden)} unchanged line(s)
            </button>
          </td>
        </tr>
        <tbody id="{cmd_id}" class="unchanged-body" style="display:none;">
        {''.join(rows_hidden)}
        </tbody>
        """

    return body_html, hidden_html, changed, critical, down_interfaces


def issue_panel_html(label, items):
    if not items:
        return ""
    li = "".join(f"<li>{html.escape(i)}</li>" for i in items)
    return f"""
    <div class="down-interfaces">
      <div class="down-interfaces-label">{html.escape(label)} ({len(items)})</div>
      <ul>{li}</ul>
    </div>
    """

# =====================================================
# DEVICE CARD BUILDER
# =====================================================

def build_device_section(device, pre_cmds, post_cmds, section_counter):
    """
    Build the HTML for one device card plus its stats.
    Returns a dict with: html, status, commands_compared, commands_changed,
    down_interfaces, ospf_issues, route_issues, vlan_issues, bgp_issues,
    cdp_issues, missing_side.
    """
    commands = sorted(set(pre_cmds.keys()) | set(post_cmds.keys()))

    if not pre_cmds and post_cmds:
        missing_side = "pre"
    elif pre_cmds and not post_cmds:
        missing_side = "post"
    else:
        missing_side = None

    device_body = []
    device_status = "pass"
    commands_compared = 0
    commands_changed = 0

    device_down_interfaces = []
    device_ospf_issues = []
    device_route_issues = []
    device_vlan_issues = []
    device_bgp_issues = []
    device_cdp_issues = []

    sh_version_pre = None
    sh_version_post = None

    for cmd in commands:
        commands_compared += 1
        pre_lines = pre_cmds.get(cmd, [])
        post_lines = post_cmds.get(cmd, [])

        # Capture the software version even when "show version" output is
        # otherwise byte-for-byte identical pre/post — an unchanged version
        # is itself the signal we need for the upgrade-verification check.
        if cmd_is(cmd, "show version"):
            sh_version_pre = extract_sh_version(pre_lines) if pre_lines else None
            sh_version_post = extract_sh_version(post_lines) if post_lines else None

        if pre_lines == post_lines:
            continue

        commands_changed += 1
        section_counter[0] += 1
        cmd_id = f"unchg-{section_counter[0]}"

        transitioned_interfaces = None
        if cmd in INTERFACE_STATUS_COMMANDS:
            transitioned_interfaces = set(interface_down_transitions(pre_lines, post_lines))

        body_html, hidden_html, changed, critical, down_ifaces = diff_opcodes_html(
            pre_lines, post_lines, cmd_id, transitioned_interfaces=transitioned_interfaces
        )

        if cmd in INTERFACE_STATUS_COMMANDS and down_ifaces:
            device_down_interfaces.extend(down_ifaces)

        # Structured checks for the specific protocol/table commands.
        if cmd_is(cmd, CMD_OSPF):
            found = ospf_issues(pre_lines, post_lines)
            if found:
                device_ospf_issues.extend(found)
                critical = True
        elif cmd_is(cmd, CMD_ROUTE):
            found = route_issues(pre_lines, post_lines)
            if found:
                device_route_issues.extend(found)
                critical = True
        elif cmd_is(cmd, CMD_VLAN):
            found = vlan_issues(pre_lines, post_lines)
            if found:
                device_vlan_issues.extend(found)
                critical = True
        elif cmd_is(cmd, CMD_BGP):
            found = bgp_issues(pre_lines, post_lines)
            if found:
                device_bgp_issues.extend(found)
                critical = True
        elif cmd_is(cmd, CMD_CDP):
            found = cdp_issues(pre_lines, post_lines)
            if found:
                device_cdp_issues.extend(found)
                critical = True

        if critical:
            device_status = "fail"
        elif changed and device_status != "fail":
            device_status = "changed"

        device_body.append(f"""
        <div class="cmd-block">
          <div class="cmd-title">{html.escape(cmd)}</div>
          <table class="diff-table">
            <thead>
              <tr><th>Precheck</th><th>Postcheck</th></tr>
            </thead>
            <tbody>
              {body_html}
            </tbody>
            {hidden_html}
          </table>
        </div>
        """)

    unique_down = dedupe_preserve_order(device_down_interfaces)
    unique_ospf = dedupe_preserve_order(device_ospf_issues)
    unique_routes = dedupe_preserve_order(device_route_issues)
    unique_vlans = dedupe_preserve_order(device_vlan_issues)
    unique_bgp = dedupe_preserve_order(device_bgp_issues)
    unique_cdp = dedupe_preserve_order(device_cdp_issues)

    if missing_side:
        device_status = "missing"

    issue_panels_html = "".join([
        issue_panel_html("Down Interfaces", unique_down),
        issue_panel_html("OSPF Neighbors Down", unique_ospf),
        issue_panel_html("Missing Routes", unique_routes),
        issue_panel_html("VLAN Issues", unique_vlans),
        issue_panel_html("BGP Sessions Down", unique_bgp),
        issue_panel_html("CDP Neighbors Lost", unique_cdp),
    ])

    missing_note = ""
    if missing_side == "pre":
        missing_note = '<div class="missing-note">No precheck data found for this device — postcheck only.</div>'
    elif missing_side == "post":
        missing_note = '<div class="missing-note">No postcheck data found for this device — precheck only.</div>'

    status_label = {
        "pass": "Passed",
        "changed": "Changed",
        "fail": "Failed",
        "missing": "Missing Data",
    }[device_status]

    total_issue_count = (len(unique_down) + len(unique_ospf) + len(unique_routes)
                          + len(unique_vlans) + len(unique_bgp) + len(unique_cdp))

    body_content = "".join(device_body) if device_body else (
        '<div class="no-changes">No differences in compared commands.</div>' if not missing_side else ""
    )

    # ---- Software version badge: shown in the card header so a reviewer
    #      can tell at a glance whether THIS device's "show version" moved
    #      pre -> post, without opening the card. ----
    sh_version_changed = bool(
        sh_version_pre and sh_version_post and sh_version_pre != sh_version_post
    )
    if sh_version_pre and sh_version_post:
        if sh_version_changed:
            version_badge = (
                f'<span class="version-badge version-upgraded">'
                f'{html.escape(sh_version_pre)} &rarr; {html.escape(sh_version_post)}</span>'
            )
        else:
            version_badge = (
                f'<span class="version-badge version-unchanged">'
                f'{html.escape(sh_version_post)} (unchanged)</span>'
            )
    elif sh_version_post or sh_version_pre:
        version_badge = (
            f'<span class="version-badge version-partial">'
            f'{html.escape(sh_version_post or sh_version_pre)} (one side only)</span>'
        )
    else:
        version_badge = ""

    html_out = f"""
    <details class="device-card" data-status="{device_status}" data-name="{html.escape(device.lower())}">
      <summary>
        <span class="status-badge status-{device_status}">{status_label}</span>
        <span class="device-name">{html.escape(device)}</span>
        <span class="device-meta">
          {commands_compared} compared &middot; {commands_changed} changed
          {f' &middot; {total_issue_count} issue(s)' if total_issue_count else ''}
        </span>
        {version_badge}
      </summary>
      <div class="device-card-body">
        {missing_note}
        {issue_panels_html}
        {body_content}
      </div>
    </details>
    """

    return {
        "html": html_out,
        "status": device_status,
        "commands_compared": commands_compared,
        "commands_changed": commands_changed,
        "down_interfaces": unique_down,
        "ospf_issues": unique_ospf,
        "route_issues": unique_routes,
        "vlan_issues": unique_vlans,
        "bgp_issues": unique_bgp,
        "cdp_issues": unique_cdp,
        "missing_side": missing_side,
        "sh_version_pre": sh_version_pre,
        "sh_version_post": sh_version_post,
        "sh_version_changed": sh_version_changed,
    }

# =====================================================
# STATIC HTML HEAD / CSS / JS
# =====================================================

HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Pre/Post Validation Report</title>
<style>

/* =====================================================
   DESIGN — "meter bank": a NOC test-bench console. The
   report reads like a rack of patch-panel indicator LEDs
   and illuminated meter readouts against a blueprint grid,
   because that's the actual instrument this data comes off
   of. One signature move — glowing seven-segment-style
   digits on the dashboard counters — carries the concept;
   everything else stays quiet so the diff data stays legible.
   ===================================================== */

@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

:root{
    --bg:#090c12;
    --grid-line:rgba(120,155,205,0.05);
    --panel:#10141c;
    --panel-2:#161b26;
    --bezel:#0b0e14;
    --border:#232a38;
    --border-soft:#1a2029;
    --text:#e7ecf2;
    --text-dim:#8891a2;
    --text-faint:#4c5566;
    --amber:#ffb020;
    --amber-dim:#8a6320;
    --green:#33d17a;
    --red:#ff5c5c;
    --violet:#9b8cff;
    --slate:#5b6472;
}

*{ box-sizing:border-box; }

html{ scroll-behavior:smooth; }

body{
    font-family:'IBM Plex Sans', 'Segoe UI', sans-serif;
    background:
        repeating-linear-gradient(0deg, rgba(255,255,255,0.012) 0px, rgba(255,255,255,0.012) 1px, transparent 1px, transparent 3px),
        radial-gradient(1100px 550px at 12% -12%, rgba(255,176,32,0.05), transparent),
        var(--bg);
    color:var(--text);
    margin:0;
    padding:0 0 60px;
    font-size:14px;
    line-height:1.5;
}

:focus-visible{ outline:2px solid var(--amber); outline-offset:2px; }

::-webkit-scrollbar{ width:10px; height:10px; }
::-webkit-scrollbar-track{ background:var(--bg); }
::-webkit-scrollbar-thumb{ background:var(--border); border-radius:6px; }
::-webkit-scrollbar-thumb:hover{ background:var(--slate); }

/* ---------- Header ---------- */

.masthead{
    background:
        repeating-linear-gradient(90deg, var(--grid-line) 0px, var(--grid-line) 1px, transparent 1px, transparent 34px),
        repeating-linear-gradient(0deg, var(--grid-line) 0px, var(--grid-line) 1px, transparent 1px, transparent 34px),
        linear-gradient(160deg, #10131c 0%, #0d1017 60%, #0a0d13 100%);
    border-bottom:1px solid var(--border);
    padding:34px 40px 26px;
}

.eyebrow{
    font-family:'JetBrains Mono', monospace;
    font-size:11px;
    font-weight:600;
    letter-spacing:2.5px;
    color:var(--amber);
    text-transform:uppercase;
    margin-bottom:12px;
}

.eyebrow::before{
    content:"";
    display:inline-block;
    width:7px;
    height:7px;
    margin-right:9px;
    vertical-align:middle;
    border-radius:50%;
    background:var(--amber);
    box-shadow:0 0 7px 2px var(--amber-dim);
    animation:led-pulse 2.4s ease-in-out infinite;
}

h1{
    font-family:'JetBrains Mono', monospace;
    font-weight:700;
    font-size:26px;
    letter-spacing:-0.2px;
    text-transform:uppercase;
    color:var(--text);
    margin:0 0 4px 0;
}

h1 span{ color:var(--amber); }

.subtitle{
    font-family:'JetBrains Mono', monospace;
    font-size:12px;
    color:var(--text-faint);
    margin-top:6px;
}

.container{ padding:0 40px; }

/* ---------- Dashboard readouts (LED meter bank) ---------- */

.readouts{
    display:grid;
    grid-template-columns:repeat(auto-fit, minmax(150px, 1fr));
    gap:12px;
    margin-top:24px;
}

.readout{
    background:linear-gradient(180deg, var(--panel) 0%, var(--bezel) 100%);
    border:1px solid var(--border);
    border-radius:6px;
    padding:14px 16px;
    position:relative;
    overflow:hidden;
    box-shadow:inset 0 1px 0 rgba(255,255,255,0.03), inset 0 -12px 18px -14px #000;
}

.readout::before{
    content:"";
    position:absolute;
    top:0; left:0;
    width:100%;
    height:2px;
    background:var(--rc-color, var(--amber));
    box-shadow:0 0 6px var(--rc-color, var(--amber));
}

.readout-label{
    font-family:'JetBrains Mono', monospace;
    font-size:10px;
    font-weight:500;
    letter-spacing:1.2px;
    text-transform:uppercase;
    color:var(--text-dim);
    margin-bottom:9px;
}

.readout-value{
    font-family:'JetBrains Mono', monospace;
    font-size:25px;
    font-weight:700;
    font-variant-numeric:tabular-nums;
    letter-spacing:0.5px;
    color:var(--rc-color, var(--text));
    text-shadow:0 0 10px var(--rc-glow, transparent);
}

.readout.rc-total{ --rc-color:#7fa8ff; --rc-glow:rgba(127,168,255,0.35); }
.readout.rc-diff{ --rc-color:var(--amber); --rc-glow:var(--amber-dim); }
.readout.rc-same{ --rc-color:var(--green); --rc-glow:rgba(51,209,122,0.35); }
.readout.rc-missing{ --rc-color:var(--violet); --rc-glow:rgba(155,140,255,0.35); }
.readout.rc-down{ --rc-color:var(--red); --rc-glow:rgba(255,92,92,0.4); }
.readout.rc-ospf{ --rc-color:var(--amber); --rc-glow:var(--amber-dim); }
.readout.rc-routes{ --rc-color:var(--violet); --rc-glow:rgba(155,140,255,0.35); }
.readout.rc-vlans{ --rc-color:var(--amber); --rc-glow:var(--amber-dim); }
.readout.rc-bgp{ --rc-color:var(--red); --rc-glow:rgba(255,92,92,0.4); }
.readout.rc-cdp{ --rc-color:#7fa8ff; --rc-glow:rgba(127,168,255,0.35); }
.readout.rc-time{ --rc-color:var(--text-dim); }
.readout.rc-time .readout-value{ font-size:15px; text-shadow:none; }
.readout.rc-verup{ --rc-color:var(--green); --rc-glow:rgba(51,209,122,0.35); }
.readout.rc-verpending{ --rc-color:var(--red); --rc-glow:rgba(255,92,92,0.4); }

/* ---------- Down/missing header alert (fault log) ---------- */

.alert-box{
    margin-top:18px;
    background:rgba(255,92,92,0.06);
    border:1px solid rgba(255,92,92,0.3);
    border-left:3px solid var(--red);
    border-radius:6px;
    padding:14px 18px;
}

.alert-section{ margin-bottom:14px; }
.alert-section:last-child{ margin-bottom:0; }

.alert-title{
    font-family:'JetBrains Mono', monospace;
    font-size:11px;
    font-weight:700;
    letter-spacing:1.5px;
    text-transform:uppercase;
    color:var(--red);
    margin-bottom:8px;
}

.alert-title::before{ content:"\\25B8  "; }

.alert-row{
    font-family:'JetBrains Mono', monospace;
    font-size:12.5px;
    color:var(--text-dim);
    padding:3px 0;
}

.alert-row b{ color:var(--text); font-weight:600; }

/* ---------- Software version upgrade verification (header) ---------- */

.version-alert-box{
    margin-top:18px;
    border-radius:6px;
    padding:14px 18px;
}

.version-alert-box.version-box-ok{
    background:rgba(51,209,122,0.06);
    border:1px solid rgba(51,209,122,0.3);
    border-left:3px solid var(--green);
}

.version-alert-box.version-box-warn{
    background:rgba(255,92,92,0.06);
    border:1px solid rgba(255,92,92,0.3);
    border-left:3px solid var(--red);
}

.version-box-summary{
    font-family:'JetBrains Mono', monospace;
    font-size:12.5px;
    font-weight:700;
    color:var(--text);
    margin-bottom:10px;
    letter-spacing:0.3px;
}

.alert-title.version-title-ok{ color:var(--green); }
.alert-title.version-title-warn{ color:var(--red); }

/* ---------- Sticky nav (console toolbar) ---------- */

.nav-bar{
    position:sticky;
    top:0;
    z-index:50;
    background:rgba(11,14,20,0.94);
    backdrop-filter:blur(6px);
    border-bottom:1px solid var(--border);
    padding:12px 40px;
    display:flex;
    align-items:center;
    gap:10px;
    flex-wrap:wrap;
    margin-top:26px;
}

.nav-search{
    flex:1;
    min-width:200px;
    background:var(--bezel);
    border:1px solid var(--border);
    border-radius:4px;
    color:var(--text);
    padding:8px 12px;
    font-family:'JetBrains Mono', monospace;
    font-size:12.5px;
}

.nav-search::placeholder{ color:var(--text-faint); }
.nav-search:focus{ outline:1px solid var(--amber); }

.filter-btn, .action-btn{
    background:var(--panel-2);
    border:1px solid var(--border);
    color:var(--text-dim);
    border-radius:4px;
    padding:8px 14px;
    font-family:'JetBrains Mono', monospace;
    font-size:11.5px;
    font-weight:500;
    letter-spacing:0.5px;
    text-transform:uppercase;
    cursor:pointer;
    transition:all .15s ease;
    white-space:nowrap;
}

.filter-btn:hover, .action-btn:hover{ border-color:var(--amber); color:var(--text); }
.filter-btn.active{
    background:var(--amber);
    color:#1a1204;
    border-color:var(--amber);
    font-weight:700;
    box-shadow:inset 0 1px 3px rgba(0,0,0,0.3), 0 0 10px rgba(255,176,32,0.35);
}

/* ---------- Device cards (equipment panels) ---------- */

.device-list{ margin-top:22px; display:flex; flex-direction:column; gap:12px; }

.device-card{
    background:var(--panel);
    border-radius:6px;
    border:1px solid var(--border);
    border-left:4px solid var(--slate);
    overflow:hidden;
}

.device-card[data-status="pass"]{ border-left-color:var(--green); }
.device-card[data-status="changed"]{ border-left-color:var(--amber); }
.device-card[data-status="fail"]{ border-left-color:var(--red); box-shadow:-1px 0 14px -6px rgba(255,92,92,0.35); }
.device-card[data-status="missing"]{ border-left-color:var(--violet); border-left-style:dashed; }

.device-card summary{
    list-style:none;
    cursor:pointer;
    padding:14px 18px;
    display:flex;
    align-items:center;
    gap:14px;
    background:var(--panel-2);
    font-family:'JetBrains Mono', monospace;
    font-weight:600;
    font-size:14px;
}

.device-card summary::-webkit-details-marker{ display:none; }

.device-card summary::after{
    content:"+";
    margin-left:auto;
    color:var(--text-dim);
    font-family:'JetBrains Mono', monospace;
    font-size:16px;
}

.device-card[open] summary::after{ content:"\\2212"; }

.status-badge{
    font-family:'JetBrains Mono', monospace;
    font-size:10.5px;
    font-weight:700;
    letter-spacing:1px;
    text-transform:uppercase;
    padding:4px 10px 4px 8px;
    border-radius:3px;
    display:inline-flex;
    align-items:center;
}

.status-badge::before{
    content:"";
    width:6px;
    height:6px;
    border-radius:50%;
    margin-right:7px;
    background:currentColor;
    box-shadow:0 0 5px currentColor;
}

.status-pass{ background:rgba(51,209,122,0.12); color:var(--green); }
.status-changed{ background:rgba(255,176,32,0.12); color:var(--amber); }
.status-fail{ background:rgba(255,92,92,0.14); color:var(--red); }
.status-missing{ background:rgba(155,140,255,0.12); color:var(--violet); }

.device-name{ color:var(--text); letter-spacing:0.2px; }

.device-meta{
    margin-left:auto;
    font-family:'JetBrains Mono', monospace;
    font-weight:400;
    font-size:11.5px;
    color:var(--text-faint);
}

.version-badge{
    font-family:'JetBrains Mono', monospace;
    font-size:10.5px;
    font-weight:600;
    letter-spacing:0.3px;
    padding:4px 9px;
    border-radius:3px;
    white-space:nowrap;
}

.version-badge.version-upgraded{ background:rgba(51,209,122,0.12); color:var(--green); border:1px solid rgba(51,209,122,0.3); }
.version-badge.version-unchanged{ background:rgba(255,176,32,0.12); color:var(--amber); border:1px solid rgba(255,176,32,0.3); }
.version-badge.version-partial{ background:rgba(155,140,255,0.12); color:var(--violet); border:1px solid rgba(155,140,255,0.3); }

.device-card-body{ padding:16px 18px 20px; }

.no-changes{
    font-family:'JetBrains Mono', monospace;
    font-size:12.5px;
    color:var(--green);
}

.no-changes::before{ content:"\\2713  "; }

.missing-note{
    font-family:'JetBrains Mono', monospace;
    font-size:12px;
    color:var(--violet);
    margin-bottom:12px;
}

.down-interfaces{
    background:rgba(255,92,92,0.06);
    border:1px solid rgba(255,92,92,0.28);
    border-left:3px solid var(--red);
    border-radius:5px;
    padding:10px 14px;
    margin-bottom:12px;
}

.down-interfaces-label{
    font-family:'JetBrains Mono', monospace;
    font-size:10.5px;
    font-weight:700;
    letter-spacing:1px;
    text-transform:uppercase;
    color:var(--red);
    margin-bottom:6px;
}

.down-interfaces ul{ margin:0; padding-left:18px; }
.down-interfaces li{ font-family:'JetBrains Mono', monospace; font-size:12.5px; color:var(--text-dim); }

.cmd-block{ margin-bottom:16px; }

.cmd-title{
    background:var(--panel-2);
    color:var(--amber);
    padding:8px 14px;
    font-family:'JetBrains Mono', monospace;
    font-size:12px;
    font-weight:600;
    border:1px solid var(--border-soft);
    border-bottom:none;
    border-radius:5px 5px 0 0;
}

.cmd-title::before{ content:"$ "; color:var(--text-faint); }

table.diff-table{ width:100%; border-collapse:collapse; }

.diff-table th{
    background:var(--bezel);
    color:var(--text-dim);
    font-family:'JetBrains Mono', monospace;
    font-size:10px;
    letter-spacing:1.2px;
    text-transform:uppercase;
    font-weight:600;
    text-align:left;
    padding:7px 12px;
    border:1px solid var(--border-soft);
}

.diff-table td{
    padding:6px 12px;
    font-family:'JetBrains Mono', monospace;
    font-size:12px;
    color:var(--text);
    border:1px solid var(--border-soft);
    border-left:3px solid transparent;
    word-break:break-word;
}

.diff-table .empty-cell{ color:var(--text-faint); }

.diff-added{ background:rgba(51,209,122,0.07); border-left-color:var(--green); color:#a7ecc0; }
.diff-removed{ background:rgba(255,92,92,0.07); border-left-color:var(--red); color:#f3b3b3; }
.diff-modified{ background:rgba(255,176,32,0.07); border-left-color:var(--amber); color:#f2cf8f; }
.diff-critical{ background:rgba(255,92,92,0.15); border-left-color:var(--red); color:#ffc7c7; font-weight:600; }
.diff-same{ background:rgba(91,100,114,0.06); border-left-color:var(--slate); color:var(--text-faint); }

.unchanged-toggle-row td{ border:none; padding:4px 0; }

.unchanged-toggle{
    background:none;
    border:1px dashed var(--border);
    color:var(--text-faint);
    font-family:'JetBrains Mono', monospace;
    font-size:11px;
    padding:5px 10px;
    border-radius:4px;
    cursor:pointer;
}

.unchanged-toggle:hover{ color:var(--text); border-color:var(--amber); }

/* ---------- Summary / footer ---------- */

h2{
    font-family:'JetBrains Mono', monospace;
    font-weight:700;
    font-size:15px;
    text-transform:uppercase;
    color:var(--text);
    margin:0 0 14px 0;
}

.footer{
    margin-top:30px;
    padding:18px 22px;
    background:var(--panel);
    border:1px solid var(--border);
    border-radius:6px;
    font-family:'JetBrains Mono', monospace;
    font-size:11.5px;
    color:var(--text-faint);
    display:flex;
    flex-wrap:wrap;
    gap:10px 26px;
}

.footer > div{
    padding-right:26px;
    border-right:1px solid var(--border-soft);
}
.footer > div:last-child{ border-right:none; padding-right:0; }

.footer b{
    color:var(--text-dim);
    font-weight:600;
    display:block;
    font-size:9.5px;
    letter-spacing:1px;
    text-transform:uppercase;
    margin-bottom:3px;
}

#backToTop{
    position:fixed;
    bottom:24px;
    right:28px;
    background:var(--panel-2);
    color:var(--amber);
    border:1px solid var(--border);
    border-radius:4px;
    width:40px;
    height:40px;
    font-size:16px;
    font-weight:700;
    cursor:pointer;
    display:none;
    box-shadow:0 4px 14px rgba(0,0,0,0.5);
    z-index:60;
}

#backToTop:hover{ border-color:var(--amber); }

@keyframes led-pulse{
    0%,100%{ opacity:1; }
    50%{ opacity:0.35; }
}

@media (prefers-reduced-motion: reduce){
    .eyebrow::before{ animation:none; }
    html{ scroll-behavior:auto; }
}

@media (max-width: 900px){
    .masthead, .container, .nav-bar{ padding-left:18px; padding-right:18px; }
}

</style>
</head>
<body>
"""

HTML_TAIL_SCRIPT = """
<button id="backToTop" onclick="window.scrollTo({top:0,behavior:'smooth'})">&uarr;</button>

<script>
function toggleUnchanged(id){
    var el = document.getElementById(id);
    if(!el) return;
    el.style.display = (el.style.display === 'none') ? 'table-row-group' : 'none';
}

(function(){
    var search = document.getElementById('deviceSearch');
    var cards = Array.prototype.slice.call(document.querySelectorAll('.device-card'));
    var filterBtns = Array.prototype.slice.call(document.querySelectorAll('.filter-btn'));
    var currentFilter = 'all';

    function applyFilters(){
        var term = (search.value || '').toLowerCase();
        cards.forEach(function(card){
            var name = card.getAttribute('data-name') || '';
            var status = card.getAttribute('data-status') || '';
            var matchesSearch = name.indexOf(term) !== -1;
            var matchesFilter =
                currentFilter === 'all' ||
                (currentFilter === 'pass' && status === 'pass') ||
                (currentFilter === 'failed' && (status === 'fail' || status === 'missing'));
            card.style.display = (matchesSearch && matchesFilter) ? '' : 'none';
        });
    }

    if(search){ search.addEventListener('input', applyFilters); }

    filterBtns.forEach(function(btn){
        btn.addEventListener('click', function(){
            filterBtns.forEach(function(b){ b.classList.remove('active'); });
            btn.classList.add('active');
            currentFilter = btn.getAttribute('data-filter');
            applyFilters();
        });
    });

    var expandAll = document.getElementById('expandAll');
    var collapseAll = document.getElementById('collapseAll');
    if(expandAll){
        expandAll.addEventListener('click', function(){
            cards.forEach(function(c){ c.open = true; });
        });
    }
    if(collapseAll){
        collapseAll.addEventListener('click', function(){
            cards.forEach(function(c){ c.open = false; });
        });
    }

    var backBtn = document.getElementById('backToTop');
    window.addEventListener('scroll', function(){
        backBtn.style.display = (window.scrollY > 400) ? 'block' : 'none';
    });
})();
</script>
</body>
</html>
"""

# =====================================================
# HEADER ALERT BUILDER
# =====================================================

def build_header_alerts(categories):
    """
    categories: list of (title, [(device, [item_strings]), ...])
    Renders one alert-box with a subsection per non-empty category so all
    down/missing conditions are visible immediately, without scrolling.
    """
    sections = []
    for title, entries in categories:
        if not entries:
            continue
        rows = "".join(
            f'<div class="alert-row"><b>{html.escape(dev)}</b> &rarr; {html.escape(", ".join(items))}</div>'
            for dev, items in entries
        )
        sections.append(f'<div class="alert-section"><div class="alert-title">{html.escape(title)}</div>{rows}</div>')

    if not sections:
        return ""
    return f'<div class="alert-box">{"".join(sections)}</div>'


def build_version_summary(device_results, all_devices, expected_version=None):
    """
    Cross-device rollup of "show version" pre/post so an engineer can
    confirm, from the report header alone, that EVERY device's software
    version actually changed during the maintenance window — no one left
    on the old code. Returns (html, stats_dict); html is "" if no device
    had "show version" data to compare.

    - upgraded:      pre/post version both found and different.
    - not_upgraded:  pre/post version both found but IDENTICAL — device
                     was not upgraded (the case we most want surfaced).
    - unverifiable:  version string missing from pre and/or post capture,
                     so the upgrade can't be confirmed either way.
    - wrong_target:  if --expected-version was given, post version doesn't
                     match it (covers partial/incorrect upgrades too).
    """
    upgraded = []
    not_upgraded = []
    unverifiable = []
    wrong_target = []
    transitions = {}

    for device in all_devices:
        r = device_results.get(device)
        if not r:
            continue
        pre_v = r.get("sh_version_pre")
        post_v = r.get("sh_version_post")

        if not pre_v or not post_v:
            unverifiable.append((device, pre_v, post_v))
            continue

        if pre_v == post_v:
            not_upgraded.append((device, pre_v, post_v))
        else:
            upgraded.append((device, pre_v, post_v))
            key = (pre_v, post_v)
            transitions[key] = transitions.get(key, 0) + 1

        if expected_version and post_v != expected_version:
            wrong_target.append((device, post_v))

    checked = len(upgraded) + len(not_upgraded)
    stats = {
        "checked": checked,
        "upgraded": len(upgraded),
        "not_upgraded": len(not_upgraded),
        "unverifiable": len(unverifiable),
        "wrong_target": len(wrong_target),
        "transitions": [{"from": p, "to": q, "count": c} for (p, q), c in transitions.items()],
    }

    if not (upgraded or not_upgraded or unverifiable):
        return "", stats  # no "show version" output found on either side

    sections = []

    if transitions:
        rows = "".join(
            f'<div class="alert-row"><b>{html.escape(p)} &rarr; {html.escape(q)}</b>'
            f' &middot; {c} device(s)</div>'
            for (p, q), c in sorted(transitions.items(), key=lambda kv: -kv[1])
        )
        sections.append(
            '<div class="alert-section"><div class="alert-title version-title-ok">'
            f'Version Transitions Observed</div>{rows}</div>'
        )

    if not_upgraded:
        rows = "".join(
            f'<div class="alert-row"><b>{html.escape(d)}</b> &rarr; still on '
            f'{html.escape(v1)} (unchanged)</div>'
            for d, v1, v2 in not_upgraded
        )
        sections.append(
            '<div class="alert-section"><div class="alert-title version-title-warn">'
            f'Devices NOT Upgraded ({len(not_upgraded)})</div>{rows}</div>'
        )

    if wrong_target:
        rows = "".join(
            f'<div class="alert-row"><b>{html.escape(d)}</b> &rarr; running '
            f'{html.escape(v)}, expected {html.escape(expected_version)}</div>'
            for d, v in wrong_target
        )
        sections.append(
            '<div class="alert-section"><div class="alert-title version-title-warn">'
            f'Devices NOT On Expected Version ({len(wrong_target)})</div>{rows}</div>'
        )

    if unverifiable:
        rows = "".join(
            '<div class="alert-row"><b>{}</b> &rarr; version not found in {} capture</div>'.format(
                html.escape(d),
                "precheck" if not v1 else "postcheck"
            )
            for d, v1, v2 in unverifiable
        )
        sections.append(
            '<div class="alert-section"><div class="alert-title version-title-warn">'
            f'Version Not Confirmed ({len(unverifiable)})</div>{rows}</div>'
        )

    all_clear = not (not_upgraded or wrong_target or unverifiable)
    box_class = "version-box-ok" if all_clear else "version-box-warn"

    summary_bits = [f'{stats["upgraded"]}/{checked} device(s) confirmed upgraded']
    if stats["not_upgraded"]:
        summary_bits.append(f'{stats["not_upgraded"]} unchanged')
    if stats["wrong_target"]:
        summary_bits.append(f'{stats["wrong_target"]} off target')
    if stats["unverifiable"]:
        summary_bits.append(f'{stats["unverifiable"]} unverifiable')
    summary_line = f'<div class="version-box-summary">{" &middot; ".join(summary_bits)}</div>'

    box_html = (
        f'<div class="alert-box version-alert-box {box_class}">'
        f'{summary_line}{"".join(sections)}</div>'
    )
    return box_html, stats

# =====================================================
# CLI ARGUMENTS
# =====================================================

def parse_args(argv=None):
    """
    All flags are optional and fall back to the CONFIGURATION constants
    above, so running the script with no arguments behaves exactly as
    before (edit-the-constants-and-run). Flags let the same script be
    reused across environments / scheduled jobs without touching code.
    """
    parser = argparse.ArgumentParser(
        description="Pre/Post Network Change Validation Report Generator"
    )
    parser.add_argument("--pre-dir", default=PRE_DIR,
                         help=f"Directory containing precheck logs (default: {PRE_DIR})")
    parser.add_argument("--post-dir", default=POST_DIR,
                         help=f"Directory containing postcheck logs (default: {POST_DIR})")
    parser.add_argument("--output", "-o", default=REPORT_FILE,
                         help=f"Path to the generated HTML report (default: {REPORT_FILE})")
    parser.add_argument("--json-summary", default=None,
                         help="Optional path to also write a machine-readable JSON summary "
                              "(per-device status + issue counts) for dashboards, tickets, or alerts.")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                         help=f"Number of threads used to parse log files in parallel (default: {DEFAULT_WORKERS})")
    parser.add_argument("--expected-version", default=None,
                         help="Optional target software version (as it appears after "
                              "'Version' in 'show version', e.g. 17.15.5). When set, any "
                              "device whose postcheck version doesn't match this exactly "
                              "is called out in the report header as off-target.")
    parser.add_argument("--config", default=None,
                         help="Optional JSON file with any of: pre_dir, post_dir, output, "
                              "json_summary, workers — overrides the defaults above but is "
                              "itself overridden by any matching CLI flag explicitly passed.")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Enable debug-level logging.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {SCRIPT_VERSION}")
    args = parser.parse_args(argv)

    if args.config:
        try:
            with open(args.config, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            parser.error(f"Could not read --config file {args.config}: {e}")
        # Only apply a config value when the user didn't already pass the
        # equivalent flag explicitly (argparse defaults make this simple
        # since we compare against the same defaults used above).
        if args.pre_dir == PRE_DIR and "pre_dir" in cfg:
            args.pre_dir = cfg["pre_dir"]
        if args.post_dir == POST_DIR and "post_dir" in cfg:
            args.post_dir = cfg["post_dir"]
        if args.output == REPORT_FILE and "output" in cfg:
            args.output = cfg["output"]
        if args.json_summary is None and "json_summary" in cfg:
            args.json_summary = cfg["json_summary"]
        if args.workers == DEFAULT_WORKERS and "workers" in cfg:
            args.workers = cfg["workers"]
        if args.expected_version is None and "expected_version" in cfg:
            args.expected_version = cfg["expected_version"]

    return args


def build_json_summary(all_devices, device_results, run_timestamp, elapsed, version_stats=None):
    """
    Machine-readable counterpart to the HTML report: per-device status
    and issue counts, plus the same rollup totals shown in the dashboard
    header. Meant for feeding a ticketing system, chat alert, or a
    separate monitoring dashboard without having to scrape HTML.
    """
    devices_out = []
    for device in all_devices:
        r = device_results[device]
        devices_out.append({
            "device": device,
            "status": r["status"],
            "commands_compared": r["commands_compared"],
            "commands_changed": r["commands_changed"],
            "down_interfaces": r["down_interfaces"],
            "ospf_issues": r["ospf_issues"],
            "route_issues": r["route_issues"],
            "vlan_issues": r["vlan_issues"],
            "bgp_issues": r["bgp_issues"],
            "cdp_issues": r["cdp_issues"],
            "missing_side": r["missing_side"],
            "sh_version_pre": r.get("sh_version_pre"),
            "sh_version_post": r.get("sh_version_post"),
            "sh_version_changed": r.get("sh_version_changed"),
        })

    return {
        "script_version": SCRIPT_VERSION,
        "generated": run_timestamp,
        "execution_seconds": round(elapsed, 2),
        "devices_compared": len(all_devices),
        "devices_passed": sum(1 for d in devices_out if d["status"] == "pass"),
        "devices_changed": sum(1 for d in devices_out if d["status"] == "changed"),
        "devices_failed": sum(1 for d in devices_out if d["status"] == "fail"),
        "devices_missing": sum(1 for d in devices_out if d["status"] == "missing"),
        "version_verification": version_stats or {},
        "devices": devices_out,
    }

# =====================================================
# MAIN
# =====================================================

def main(argv=None):
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    global REPORT_FILE
    REPORT_FILE = args.output

    start_time = time.time()
    run_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pre_paths = collect_log_files(args.pre_dir)
    post_paths = collect_log_files(args.post_dir)

    if not pre_paths and not post_paths:
        log.error("No precheck or postcheck files found. Checked:\n  pre:  %s\n  post: %s",
                   args.pre_dir, args.post_dir)
        return EXIT_SETUP_ERROR

    log.info("Found %d precheck file(s), %d postcheck file(s). Parsing with %d worker thread(s)...",
              len(pre_paths), len(post_paths), args.workers)

    # ---- Pass 1: parse every file exactly once and merge into a single
    #      per-device dataset. This is what eliminates duplicate device
    #      sections when a device's data spans multiple log files.
    #      Each file's device(s) are re-keyed by the FQDN/IP embedded in
    #      its FILENAME (timestamp stripped) so precheck/postcheck files
    #      pair up correctly even when filenames aren't identical — e.g.
    #      "192.168.50.212__20260630_110428" and
    #      "192.168.50.212__20260630_093027" are recognized as the same
    #      device instead of being skipped/mismatched.
    #      Parsing is I/O-bound, so pre and post files are each parsed
    #      across a small thread pool rather than one file at a time. ----
    global_pre = parse_and_merge_all(pre_paths, args.workers)
    global_post = parse_and_merge_all(post_paths, args.workers)

    all_devices = sorted({
        d.strip().upper()
        for d in (set(global_pre.keys()) | set(global_post.keys()))
        if d and d.strip() and d.upper() != "UNKNOWN"
    })

    # ---- Pass 2: build each device card once, stream fragments to a
    #      temp file on disk instead of holding the whole report in
    #      memory (keeps peak memory low for hundreds of devices). ----
    total_commands = 0
    changed_commands = 0

    total_interfaces_down = 0
    total_ospf_down = 0
    total_routes_missing = 0
    total_vlans_missing = 0
    total_bgp_down = 0
    total_cdp_down = 0

    devices_diff = 0
    devices_same = 0
    devices_missing = 0

    down_by_device = []
    ospf_by_device = []
    routes_by_device = []
    vlans_by_device = []
    bgp_by_device = []
    cdp_by_device = []

    device_results = {}

    section_counter = [0]

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".html", prefix="device_sections_")
    os.close(tmp_fd)

    with open(tmp_path, "w", encoding="utf-8") as tmp_f:
        for device in all_devices:
            pre_cmds = global_pre.get(device, {})
            post_cmds = global_post.get(device, {})

            result = build_device_section(device, pre_cmds, post_cmds, section_counter)

            tmp_f.write(result["html"])

            total_commands += result["commands_compared"]
            changed_commands += result["commands_changed"]

            total_interfaces_down += len(result["down_interfaces"])
            total_ospf_down += len(result["ospf_issues"])
            total_routes_missing += len(result["route_issues"])
            total_vlans_missing += len(result["vlan_issues"])
            total_bgp_down += len(result["bgp_issues"])
            total_cdp_down += len(result["cdp_issues"])

            if result["missing_side"]:
                devices_missing += 1
            elif result["status"] == "pass":
                devices_same += 1
            else:
                devices_diff += 1

            if result["down_interfaces"]:
                down_by_device.append((device, result["down_interfaces"]))
            if result["ospf_issues"]:
                ospf_by_device.append((device, result["ospf_issues"]))
            if result["route_issues"]:
                routes_by_device.append((device, result["route_issues"]))
            if result["vlan_issues"]:
                vlans_by_device.append((device, result["vlan_issues"]))
            if result["bgp_issues"]:
                bgp_by_device.append((device, result["bgp_issues"]))
            if result["cdp_issues"]:
                cdp_by_device.append((device, result["cdp_issues"]))

            device_results[device] = result

    header_alerts_html = build_header_alerts([
        ("Interfaces Down", down_by_device),
        ("OSPF Neighbors Down", ospf_by_device),
        ("Missing Routes", routes_by_device),
        ("VLAN Issues", vlans_by_device),
        ("BGP Sessions Down", bgp_by_device),
        ("CDP Neighbors Lost", cdp_by_device),
    ])

    version_summary_html, version_stats = build_version_summary(
        device_results, all_devices, expected_version=args.expected_version
    )

    # ---- Assemble final report: header/dashboard, then stream-copy the
    #      device sections from disk, then footer. ----
    with open(REPORT_FILE, "w", encoding="utf-8") as out:
        out.write(HTML_HEAD)

        out.write(f"""
        <div class="masthead">
          <div class="eyebrow">Network Change Validation</div>
          <h1>Precheck <span>&rarr;</span> Postcheck Report</h1>
          <div class="subtitle">Automated diff of device state before and after maintenance &middot; allowlisted commands only</div>

          <div class="readouts">
            <div class="readout rc-total">
              <div class="readout-label">Devices Compared</div>
              <div class="readout-value">{len(all_devices)}</div>
            </div>
            <div class="readout rc-diff">
              <div class="readout-label">With Differences</div>
              <div class="readout-value">{devices_diff}</div>
            </div>
            <div class="readout rc-same">
              <div class="readout-label">Matching</div>
              <div class="readout-value">{devices_same}</div>
            </div>
            <div class="readout rc-missing">
              <div class="readout-label">Missing</div>
              <div class="readout-value">{devices_missing}</div>
            </div>
            <div class="readout rc-down">
              <div class="readout-label">Interfaces Down</div>
              <div class="readout-value">{total_interfaces_down}</div>
            </div>
            <div class="readout rc-ospf">
              <div class="readout-label">OSPF Down</div>
              <div class="readout-value">{total_ospf_down}</div>
            </div>
            <div class="readout rc-routes">
              <div class="readout-label">Routes Missing</div>
              <div class="readout-value">{total_routes_missing}</div>
            </div>
            <div class="readout rc-vlans">
              <div class="readout-label">VLAN Issues</div>
              <div class="readout-value">{total_vlans_missing}</div>
            </div>
            <div class="readout rc-bgp">
              <div class="readout-label">BGP Down</div>
              <div class="readout-value">{total_bgp_down}</div>
            </div>
            <div class="readout rc-cdp">
              <div class="readout-label">CDP Lost</div>
              <div class="readout-value">{total_cdp_down}</div>
            </div>
            <div class="readout rc-time">
              <div class="readout-label">Generated</div>
              <div class="readout-value">{run_timestamp}</div>
            </div>
            {f'''<div class="readout rc-verup">
              <div class="readout-label">Version Upgraded</div>
              <div class="readout-value">{version_stats["upgraded"]}/{version_stats["checked"]}</div>
            </div>''' if version_stats["checked"] else ''}
            {f'''<div class="readout rc-verpending">
              <div class="readout-label">Version Pending</div>
              <div class="readout-value">{version_stats["not_upgraded"] + version_stats["unverifiable"] + version_stats["wrong_target"]}</div>
            </div>''' if version_stats["checked"] or version_stats["unverifiable"] else ''}
          </div>

          {version_summary_html}
          {header_alerts_html}
        </div>
        """)

        out.write("""
        <div class="nav-bar">
          <input id="deviceSearch" class="nav-search" type="text" placeholder="Search device name...">
          <button class="filter-btn active" data-filter="all">All</button>
          <button class="filter-btn" data-filter="pass">Passed</button>
          <button class="filter-btn" data-filter="failed">Failed</button>
          <button id="expandAll" class="action-btn">Expand All</button>
          <button id="collapseAll" class="action-btn">Collapse All</button>
        </div>
        """)

        out.write('<div class="container"><div class="device-list">')

        with open(tmp_path, "r", encoding="utf-8") as tmp_f:
            shutil.copyfileobj(tmp_f, out)

        out.write("</div>")  # close .device-list

        elapsed = time.time() - start_time
        out.write(f"""
        <div class="footer">
          <div><b>Generated</b> {run_timestamp}</div>
          <div><b>Execution Time</b> {elapsed:.2f}s</div>
          <div><b>Python</b> {platform.python_version()}</div>
          <div><b>Script Version</b> {SCRIPT_VERSION}</div>
        </div>
        """)

        out.write("</div>")  # close .container
        out.write(HTML_TAIL_SCRIPT)

    os.remove(tmp_path)

    elapsed_total = time.time() - start_time

    if args.json_summary:
        summary = build_json_summary(all_devices, device_results, run_timestamp, elapsed_total, version_stats)
        try:
            with open(args.json_summary, "w", encoding="utf-8") as jf:
                json.dump(summary, jf, indent=2)
        except OSError:
            log.exception("Could not write JSON summary to %s", args.json_summary)

    log.info("=" * 60)
    log.info("REPORT GENERATED SUCCESSFULLY")
    log.info("=" * 60)
    log.info("Devices Compared     : %d", len(all_devices))
    log.info("With Differences     : %d", devices_diff)
    log.info("Matching             : %d", devices_same)
    log.info("Missing              : %d", devices_missing)
    log.info("Commands Checked     : %d", total_commands)
    log.info("Commands Changed     : %d", changed_commands)
    log.info("Interfaces Down      : %d", total_interfaces_down)
    log.info("OSPF Neighbors Down  : %d", total_ospf_down)
    log.info("Routes Missing       : %d", total_routes_missing)
    log.info("VLAN Issues          : %d", total_vlans_missing)
    log.info("BGP Sessions Down    : %d", total_bgp_down)
    log.info("CDP Neighbors Lost   : %d", total_cdp_down)
    if version_stats["checked"] or version_stats["unverifiable"]:
        log.info("-" * 60)
        log.info("Version Upgraded     : %d/%d", version_stats["upgraded"], version_stats["checked"])
        log.info("Version Unchanged    : %d", version_stats["not_upgraded"])
        if args.expected_version:
            log.info("Off Target Version   : %d", version_stats["wrong_target"])
        log.info("Version Unverifiable : %d", version_stats["unverifiable"])
    log.info("Execution Time       : %.2fs", elapsed_total)
    log.info("Output File          : %s", REPORT_FILE)
    if args.json_summary:
        log.info("JSON Summary         : %s", args.json_summary)
    log.info("=" * 60)

    # ---- Exit code reflects the worst outcome found, so scheduled runs /
    #      pipelines can alert without scraping stdout or the HTML. ----
    if devices_missing > 0 or total_interfaces_down or total_ospf_down or \
       total_routes_missing or total_vlans_missing or total_bgp_down or total_cdp_down or \
       version_stats["not_upgraded"] or version_stats["wrong_target"]:
        return EXIT_CRITICAL
    if devices_diff > 0:
        return EXIT_CHANGED
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

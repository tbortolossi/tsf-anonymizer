"""scripts/check-identifiers.py: the pre-commit / CI guard against real
identifiers. It is a script, not a package module, so it is loaded by path.

The values the guard must *flag* are assembled at run time: written out,
they would be caught in this very file — and none of them is from a real
archive to begin with."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check-identifiers.py"

ROUTABLE_IP = ".".join(["11", "22", "33", "44"])
FAKE_SERIAL = "0123" + "45678901"
UNLISTED_DOMAIN = "unlisted-corp" + ".fr"
UNLISTED_LOGIN = "oldcorp" + "\\\\" + "someone"


@pytest.fixture(scope="module")
def guard():
    spec = importlib.util.spec_from_file_location("check_identifiers", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ALLOW = {"acme-corp.fr", "acme", "001901000123", "github.com", "8.8.8.8"}


def hits(guard, line, *, allow=ALLOW, deny=frozenset(), code=False):
    return guard.scan_line(line, allow=set(allow), deny=set(deny), code=code)


class TestIPv4:
    @pytest.mark.parametrize("ip", ["10.1.2.3", "172.31.0.9", "192.168.1.1", "127.0.0.1", "100.64.0.3",
                                    "198.18.7.7", "192.0.2.1", "198.51.100.231", "203.0.113.184",
                                    "224.0.0.251", "169.254.1.1", "0.0.0.0"])
    def test_reserved_ranges_pass(self, guard, ip):
        assert hits(guard, f"peer {ip} up") == []

    def test_routable_address_is_flagged_even_inside_a_token(self, guard):
        assert hits(guard, f"connid: lr-{ROUTABLE_IP}-2") == [f"public IPv4: {ROUTABLE_IP}"]

    def test_allowlisted_and_malformed_pass(self, guard):
        assert hits(guard, "dns 8.8.8.8 and 999.1.1.1 and 1.2.3") == []


class TestNames:
    def test_synthetic_vocabulary_passes_by_parent_domain(self, guard):
        assert hits(guard, "mail j.dupont@acme-corp.fr host vpn.acme-corp.fr https://docs.github.com/x") == []

    def test_rfc2606_never_needs_listing(self, guard):
        assert hits(guard, "igw.home-lab.example *.home-lab.example a@b.example x.test y.invalid") == []

    def test_unknown_domain_and_email_are_flagged(self, guard):
        out = hits(guard, f"from someone@{UNLISTED_DOMAIN} via igw.{UNLISTED_DOMAIN}")
        assert f"e-mail: someone@{UNLISTED_DOMAIN}" in out and f"host name: igw.{UNLISTED_DOMAIN}" in out

    def test_code_attribute_chains_are_not_hostnames(self, guard):
        assert hits(guard, "log.info(x); inp.dataset.dev; Path.home(); web.app", code=True) == []


class TestSerials:
    def test_pan_shaped_serial_is_flagged_unless_listed(self, guard):
        assert hits(guard, f"serial {FAKE_SERIAL}") == [f"serial-shaped: {FAKE_SERIAL}"]
        assert hits(guard, "serial 001901000123") == []

    def test_not_a_serial_when_glued_to_digits_or_dots(self, guard):
        assert hits(guard, f"pan.{FAKE_SERIAL}.log {FAKE_SERIAL}1") == []


class TestNetbios:
    def test_domain_backslash_user_needs_a_listed_domain(self, guard):
        assert hits(guard, f'name="{UNLISTED_LOGIN}"', code=True) == [f"DOMAIN\\user: {UNLISTED_LOGIN}"]
        assert hits(guard, r'name="acme\\jdupont"', code=True) == []

    def test_regex_escapes_in_code_are_not_logins(self, guard):
        assert hits(guard, r'printf "serverAuth\nsubjectAltName"; re.compile(r"foo\bbar")', code=True) == []

    def test_prose_accepts_a_single_backslash(self, guard):
        assert hits(guard, r"login as CORP\alice", allow=set()) == ["DOMAIN\\user: CORP\\alice"]


class TestDenylist:
    def test_literal_is_matched_case_insensitively_anywhere(self, guard):
        assert hits(guard, "GP_globalprotect_MyLab_com2026", deny={"mylab"}) == ["denylisted: 'mylab'"]

    def test_denylist_file_is_gitignored(self):
        res = subprocess.run(["git", "check-ignore", "-q", ".identifier-denylist"], cwd=ROOT)
        assert res.returncode == 0


def test_the_tree_is_clean():
    """The real gate: every tracked file passes. A failure here names the
    file, the line and the value — replace it or, if it is synthetic, list
    it in scripts/identifier-allowlist.txt."""
    res = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT, capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr


def test_author_check_uses_the_denylist(guard, monkeypatch):
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "Someone")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "someone@personal-mail.example")
    idents = guard.git_identities()
    assert all("personal-mail.example" in v for v in idents.values()), idents
    assert len(guard.author_hits({"personal-mail"})) == 2
    assert guard.author_hits({"other"}) == []


def test_author_check_survives_a_machine_without_git_identity(guard, monkeypatch):
    """A CI runner has no user.name: `git var` fails there, the fallback
    still sees the e-mail the environment provides."""
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "ci@personal-mail.example")
    monkeypatch.delenv("GIT_AUTHOR_NAME", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent")  # no global config either
    assert "ci@personal-mail.example" in guard.git_identities()["AUTHOR"]

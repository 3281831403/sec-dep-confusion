from deps import resolve, resolve_batch, source_allowed

INTERNAL = "https://pypi.corp.example/simple"
PUBLIC = "https://pypi.org/simple"


def _policy():
    return {
        "internal_prefixes": ["corp.pay"],
        "internal_sources": [INTERNAL],
        "allow_public_fallback": False,
        "lockfile": {"corp.pay.gateway": "1.2.3"},
    }


def test_single_requirement_resolution():
    sources = [
        {
            "url": INTERNAL,
            "internal": True,
            "namespaces": ["corp.pay"],
            "packages": {"corp.pay.gateway": ["1.9.0", "1.10.0"]},
        }
    ]
    result = resolve(["corp.pay.gateway>=1.9.0"], sources, {})
    assert result["ok"] is True
    assert result["packages"]["corp.pay.gateway"]["version"] == "1.10.0"


def test_namespace_prefix_matches_whole_segments():
    policy = _policy()
    assert source_allowed("corp.pay", PUBLIC, policy) is False
    assert source_allowed("corp.payments.tool", PUBLIC, policy) is True


def test_public_source_shadow_is_rejected():
    sources = [
        {
            "url": INTERNAL,
            "internal": True,
            "namespaces": ["corp.pay"],
            "packages": {},
        },
        {
            "url": PUBLIC,
            "internal": False,
            "packages": {"corp.pay.gateway": ["1.0.0"]},
        },
    ]
    result = resolve(["corp.pay.gateway==1.0.0"], sources, {})
    assert result["errors"]
    assert "corp.pay.gateway" not in result["packages"]


def test_lockfile_wins_over_floating_range():
    sources = [
        {
            "url": INTERNAL,
            "internal": True,
            "namespaces": ["corp.pay"],
            "packages": {"corp.pay.gateway": ["1.2.3", "1.5.0"]},
        }
    ]
    result = resolve(
        ["corp.pay.gateway>=1.0.0"],
        sources,
        {"corp.pay.gateway": "1.2.3"},
    )
    assert result["packages"]["corp.pay.gateway"]["version"] == "1.2.3"


def test_batch_sets_are_independent():
    sets = [
        {
            "name": "first",
            "requirements": ["requests==2.31.0"],
            "sources": [
                {
                    "url": "https://mirror.one.example/simple",
                    "internal": False,
                    "packages": {"requests": ["2.31.0"]},
                }
            ],
            "lockfile": {},
        },
        {
            "name": "second",
            "requirements": ["requests==2.32.0"],
            "sources": [
                {
                    "url": "https://mirror.two.example/simple",
                    "internal": False,
                    "packages": {"requests": ["2.32.0"]},
                }
            ],
            "lockfile": {},
        },
    ]
    result = resolve_batch(sets, {"lockfile": {}})
    assert result["second"]["packages"]["requests"]["version"] == "2.32.0"
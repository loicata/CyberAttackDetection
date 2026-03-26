"""Tests for configuration loading and validation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.core.config import (
    AppConfig,
    _build_app_config,
    _deep_merge,
    _get_nested,
    _load_toml,
    _set_nested,
    _apply_env_overrides,
    load_config,
    DEFAULT_CONFIG_PATH,
)
from src.core.exceptions import ConfigError


class TestDeepMerge:
    """Tests for _deep_merge utility."""

    def test_flat_merge(self) -> None:
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self) -> None:
        base = {"x": {"a": 1, "b": 2}}
        override = {"x": {"b": 3, "c": 4}}
        result = _deep_merge(base, override)
        assert result == {"x": {"a": 1, "b": 3, "c": 4}}

    def test_does_not_mutate_inputs(self) -> None:
        base = {"a": {"b": 1}}
        override = {"a": {"c": 2}}
        _deep_merge(base, override)
        assert base == {"a": {"b": 1}}
        assert override == {"a": {"c": 2}}

    def test_override_replaces_non_dict_with_dict(self) -> None:
        base = {"a": "string"}
        override = {"a": {"nested": True}}
        result = _deep_merge(base, override)
        assert result == {"a": {"nested": True}}


class TestNestedAccess:
    """Tests for _get_nested and _set_nested."""

    def test_get_simple_key(self) -> None:
        data = {"a": 1}
        assert _get_nested(data, "a") == 1

    def test_get_dotted_key(self) -> None:
        data = {"a": {"b": {"c": 42}}}
        assert _get_nested(data, "a.b.c") == 42

    def test_get_missing_key(self) -> None:
        data = {"a": 1}
        assert _get_nested(data, "b") is None

    def test_get_missing_nested(self) -> None:
        data = {"a": {"b": 1}}
        assert _get_nested(data, "a.c.d") is None

    def test_set_simple_key(self) -> None:
        data: dict = {}
        _set_nested(data, "a", 1)
        assert data == {"a": 1}

    def test_set_nested_key(self) -> None:
        data: dict = {}
        _set_nested(data, "a.b.c", 42)
        assert data == {"a": {"b": {"c": 42}}}


class TestEnvOverrides:
    """Tests for environment variable overrides."""

    def test_override_applies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAD_GENERAL__LOG_LEVEL", "DEBUG")
        config = {"general": {"log_level": "INFO"}}
        result = _apply_env_overrides(config)
        assert _get_nested(result, "general.log_level") == "DEBUG"

    def test_no_override_without_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTHER_VAR", "test")
        config = {"general": {"app_name": "CAD"}}
        result = _apply_env_overrides(config)
        assert result == config


class TestLoadToml:
    """Tests for TOML file loading."""

    def test_load_default_config(self) -> None:
        data = _load_toml(DEFAULT_CONFIG_PATH)
        assert "general" in data
        assert "detection" in data
        assert "analysis" in data

    def test_load_nonexistent_file(self) -> None:
        with pytest.raises(ConfigError, match="not found"):
            _load_toml(Path("/nonexistent/file.toml"))


class TestBuildAppConfig:
    """Tests for _build_app_config."""

    def test_builds_from_default_toml(self) -> None:
        data = _load_toml(DEFAULT_CONFIG_PATH)
        config = _build_app_config(data)
        assert isinstance(config, AppConfig)
        assert config.app_name == "Cyber Attack Detection"
        assert config.analysis.score_threshold == 40
        assert 4444 in config.suspicious_ports

    def test_invalid_score_threshold(self) -> None:
        data = {"analysis": {"score_threshold": 150}}
        with pytest.raises(ConfigError, match="score_threshold"):
            _build_app_config(data)

    def test_invalid_parent_child_pair(self) -> None:
        data = {
            "detection": {
                "process": {
                    "suspicious_parent_child": [["only_one_element"]]
                }
            }
        }
        with pytest.raises(ConfigError, match="Invalid parent-child pair"):
            _build_app_config(data)

    def test_empty_data_uses_defaults(self) -> None:
        config = _build_app_config({})
        assert config.app_name == "Cyber Attack Detection"
        assert config.analysis.score_threshold == 40


class TestLoadConfig:
    """Tests for the full load_config function."""

    def test_load_default(self) -> None:
        config = load_config()
        assert isinstance(config, AppConfig)
        assert config.db_wal_mode is True

    def test_load_with_local_override(self, tmp_path: Path) -> None:
        local_toml = tmp_path / "local.toml"
        local_toml.write_text('[general]\nlog_level = "DEBUG"\n')
        config = load_config(local_path=local_toml)
        assert config.log_level == "DEBUG"

    def test_load_nonexistent_local_is_ok(self, tmp_path: Path) -> None:
        # Local file doesn't exist -> should just use defaults
        config = load_config(local_path=tmp_path / "nonexistent.toml")
        assert isinstance(config, AppConfig)

"""Smoke tests verifying module imports and basic integration."""
import importlib


def test_modules_import():
    """Verify all top-level project modules can be imported without error."""
    modules = ["scanner", "skills_loader", "agent"]
    for mod_name in modules:
        mod = importlib.import_module(mod_name)
        assert mod is not None

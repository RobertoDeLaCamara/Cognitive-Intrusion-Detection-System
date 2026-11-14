"""Tests for configuration validation."""



class TestConfigValidation:
    def test_valid_config_passes(self):
        """Default config should pass validation."""
        from src.config import _validate_config
        # Should not raise with default values
        _validate_config()

    def test_validation_function_exists(self):
        """ConfigurationError should be importable."""
        from src.config import ConfigurationError
        assert issubclass(ConfigurationError, Exception)

import tempfile
import unittest

from backend.app.config.profile import (
    load_runtime_profile_config,
    normalize_profile,
    profile_metadata,
    require_valid_runtime_config,
)


class RuntimeProfileTests(unittest.TestCase):
    def test_valid_profiles_are_accepted(self):
        for profile in ("dev", "desktop", "server", "sensor", "agent"):
            self.assertEqual(normalize_profile(profile), profile)

    def test_invalid_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_profile("public-root")

    def test_default_profile_preserves_desktop_behavior(self):
        config = load_runtime_profile_config({}, validate_paths=False)

        self.assertEqual(config.profile, "desktop")
        self.assertFalse(config.server_mode)

    def test_public_server_without_token_is_rejected(self):
        config = load_runtime_profile_config(
            {
                "NETBOT_PROFILE": "server",
                "NETBOT_HOST": "0.0.0.0",
                "NETBOT_ALLOWED_ORIGINS": "https://netbot.example",
            },
            validate_paths=False,
        )

        self.assertIn("server_profile_requires_trusted_token", config.validation_errors)
        with self.assertRaises(RuntimeError):
            require_valid_runtime_config(config)

    def test_server_rejects_wildcard_cors_debug_and_default_secret(self):
        config = load_runtime_profile_config(
            {
                "NETBOT_PROFILE": "server",
                "NETBOT_HOST": "0.0.0.0",
                "NETBOT_TRUSTED_TOKENS": "changeme",
                "NETBOT_ALLOWED_ORIGINS": "*",
                "NETBOT_DEBUG": "true",
            },
            validate_paths=False,
        )

        self.assertIn("server_profile_rejects_wildcard_cors", config.validation_errors)
        self.assertIn("server_profile_rejects_debug", config.validation_errors)
        self.assertIn("server_profile_rejects_default_secret", config.validation_errors)

    def test_explicit_server_config_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            config = load_runtime_profile_config(
                {
                    "NETBOT_PROFILE": "server",
                    "NETBOT_HOST": "0.0.0.0",
                    "NETBOT_PUBLIC_BASE_URL": "https://netbot.example",
                    "NETBOT_ALLOWED_ORIGINS": "https://netbot.example",
                    "NETBOT_TRUSTED_TOKENS": "a-long-random-token",
                    "NETBOT_RUNTIME_DIR": td,
                    "NETBOT_LOG_DIR": td,
                },
                validate_paths=True,
            )

        self.assertEqual(config.validation_errors, ())
        self.assertEqual(profile_metadata(config)["profile"], "server")


if __name__ == "__main__":
    unittest.main()


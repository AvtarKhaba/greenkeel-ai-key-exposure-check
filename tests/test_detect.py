import unittest

import helpers
from ai_key_exposure_check import detect as d


def providers(text: str) -> list[str]:
    return [hit.provider for hit in d.detect(text)]


class ProviderDetection(unittest.TestCase):
    def test_prefix_detection_without_any_variable_name(self):
        cases = [
            (d.ANTHROPIC, helpers.fake_anthropic()),
            (d.OPENAI, helpers.fake_openai()),
            (d.OPENROUTER, helpers.fake_openrouter()),
            (d.GOOGLE, helpers.fake_google()),
            (d.AWS, helpers.fake_aws_access()),
            (d.AWS, helpers.fake_bedrock_api_key()),
        ]
        for provider, key in cases:
            with self.subTest(provider=provider):
                self.assertEqual(providers(f"some text {key} more text"), [provider])

    def test_openai_pattern_does_not_claim_other_sk_prefixes(self):
        self.assertEqual(providers(helpers.fake_anthropic()), [d.ANTHROPIC])
        self.assertEqual(providers(helpers.fake_openrouter()), [d.OPENROUTER])

    def test_azure_detected_only_by_adjacent_name(self):
        key = helpers.fake_azure()
        self.assertEqual(providers(f"AZURE_OPENAI_API_KEY={key}"), [d.AZURE])
        self.assertEqual(providers(f"AOAI_KEY={key}"), [d.AZURE])
        self.assertEqual(providers(key), [])

    def test_mistral_detected_only_by_adjacent_name(self):
        key = helpers.fake_mistral()
        self.assertEqual(providers(f"MISTRAL_API_KEY={key}"), [d.MISTRAL])
        self.assertEqual(providers(key), [])

    def test_named_detection_for_other_providers(self):
        value = helpers.fake_generic("named")
        for name, provider in [
            ("ANTHROPIC_API_KEY", d.ANTHROPIC),
            ("OPENAI_API_KEY", d.OPENAI),
            ("OPENROUTER_API_KEY", d.OPENROUTER),
            ("GEMINI_API_KEY", d.GOOGLE),
            ("GOOGLE_API_KEY", d.GOOGLE),
            ("NEXT_PUBLIC_OPENAI_API_KEY", d.OPENAI),
            ("AWS_BEARER_TOKEN_BEDROCK", d.AWS),
        ]:
            with self.subTest(name=name):
                self.assertEqual(providers(f"{name}={value}"), [provider])

    def test_aws_secret_access_key_by_name(self):
        self.assertEqual(providers(f"AWS_SECRET_ACCESS_KEY={helpers.fake_aws_secret()}"), [d.AWS])

    def test_prefix_wins_over_a_misleading_name(self):
        self.assertEqual(providers(f"MY_TOKEN={helpers.fake_anthropic()}"), [d.ANTHROPIC])

    def test_value_syntaxes(self):
        key = helpers.fake_mistral()
        for text in [
            f"MISTRAL_API_KEY={key}",
            f'export MISTRAL_API_KEY="{key}"',
            f"MISTRAL_API_KEY: '{key}'",
            f'"MISTRAL_API_KEY": "{key}"',
            f'{{\\"MISTRAL_API_KEY\\":\\"{key}\\"}}',
            f'os.environ["MISTRAL_API_KEY"] = "{key}"',
            f"set -gx MISTRAL_API_KEY {key}",
            f"$env:MISTRAL_API_KEY = '{key}'",
            f"run --mistral-api-key {key}",
            f"run --mistral-api-key={key}",
            f'"args": ["--mistral-api-key", "{key}"]',
        ]:
            with self.subTest(text=text.replace(key, "KEY")):
                self.assertEqual(providers(text), [d.MISTRAL])

    def test_finds_name_after_an_unrelated_prefix(self):
        key = helpers.fake_mistral()
        self.assertEqual(providers(f"env:MISTRAL_API_KEY={key}"), [d.MISTRAL])


class GenericEntropyRule(unittest.TestCase):
    def test_true_positives(self):
        value = helpers.fake_generic()
        for text in [
            f"MY_SERVICE_TOKEN={value}",
            f"API_KEY={value}",
            f"client_secret: {value}",
            f"apiKey = '{value}'",
            f'curl -H "x-api-key: {value}"',
            f'curl -H "Authorization: Bearer {value}"',
        ]:
            with self.subTest(text=text.replace(value, "VALUE")):
                self.assertEqual(providers(text), [d.GENERIC])

    def test_false_positives_are_rejected(self):
        for text in [
            "MAX_TOKENS=4096",
            "API_KEY=" + "a" * 40,
            "API_KEY=" + "ab" * 20,
            "TOKEN_NAME=my-very-long-descriptive-token-name",
            "SECRET=" + "your-secret-goes-here-" + "1" + "2" + "a9",
            "SECRET_KEY=" + "exam" + "ple-value-for-the-docs-42",
            "KEY_PATH=/usr/local/share/keys1/deploy2.pem",
            "API_KEY=https://vault.internal/v1/keys/service-a1",
            "API_KEY=${API_KEY_FROM_VAULT_VALUE_HERE1}",
            "API_KEY=$API_KEY_FROM_VAULT_VALUE_HERE1",
            "API_KEY=<paste-the-real-value-here-1>",
            "api_key = settings.service1.api_key_value",
            "api_key = getApiKeyFromVaultSomehow1(service)",
            "TOKEN=thisIsAVeryLongCamelCaseIdentifierName",
            "TOKEN=" + "-".join(["3f2a1b4c", "9d8e", "4f7a", "b6c5", "0e1d2c3b4a59"]),
            "MONKEY_BUSINESS=" + helpers.fake_generic(),
            "KEYBOARD_LAYOUT=" + helpers.fake_generic(),
            "PUBLIC_KEY=" + helpers.fake_generic(),
            "STRIPE_PUBLISHABLE_KEY=" + helpers.fake_generic(),
            "BUILD_ID=" + helpers.fake_generic(),
            "SHORT_TOKEN=a1b2c3d4",
            "integrity_key: sha512-" + helpers.fake_generic(),
            helpers.fake_generic(),
        ]:
            with self.subTest(text=text[:24]):
                self.assertEqual(providers(text), [])

    def test_placeholders_after_a_real_prefix_are_rejected(self):
        for text in [
            "OPENAI_API_KEY=" + "sk" + "-" + "x" * 40,
            "OPENAI_API_KEY=" + "sk" + "-" + "your-key-goes-here-please-1",
            "ANTHROPIC_API_KEY=" + "sk" + "-" + "an" + "t-api03-" + "x" * 40,
            "AWS_ACCESS_KEY_ID=" + "AK" + "IA" + "IOSFODNN7" + "EXAM" + "PLE",
        ]:
            with self.subTest(text=text[:18]):
                self.assertEqual(providers(text), [])

    def test_hyphenated_english_is_not_an_openai_key(self):
        self.assertEqual(providers("task-assignment-for-the-whole-engineering-team"), [])
        self.assertEqual(providers("sk-learn-tutorials-for-beginners-and-experts"), [])

    def test_long_line_without_separators_scans_quickly(self):
        self.assertEqual(providers("a" * 2_000_000), [])
        self.assertEqual(providers("ab.-" * 500_000), [])


class Masking(unittest.TestCase):
    def test_mask_is_four_characters_and_ellipsis(self):
        self.assertEqual(d.mask("abcdefgh"), "abcd…")

    def test_hit_holds_only_the_masked_value(self):
        key = helpers.fake_anthropic()
        hit = d.detect(key)[0]
        self.assertEqual(hit.preview, key[:4] + "…")
        self.assertNotIn(key, repr(hit))
        self.assertNotIn(key[:5], repr(hit))

    def test_redact_masks_credentials_in_free_text(self):
        key = helpers.fake_anthropic()
        redacted = d.redact(f"/tmp/{key}/.env")
        self.assertEqual(redacted, f"/tmp/{key[:4]}…/.env")


if __name__ == "__main__":
    unittest.main()

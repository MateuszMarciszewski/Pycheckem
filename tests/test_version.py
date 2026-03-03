from pycheckem.diff import is_downgrade, is_major_change, parse_version


class TestParseVersion:
    def test_standard_version(self):
        assert parse_version("3.11.4") == (3, 11, 4)

    def test_two_part_version(self):
        assert parse_version("2.31") == (2, 31)

    def test_single_part_version(self):
        assert parse_version("5") == (5,)

    def test_invalid_version_fallback(self):
        assert parse_version("invalid") == ("invalid",)

    def test_prerelease_fallback(self):
        assert parse_version("3.11.0rc1") == ("3.11.0rc1",)

    def test_empty_string_fallback(self):
        assert parse_version("") == ("",)


class TestIsMajorChange:
    def test_major_version_differs(self):
        assert is_major_change("3.11.4", "4.0.0") is True

    def test_minor_version_differs(self):
        assert is_major_change("3.11.4", "3.12.0") is False

    def test_same_version(self):
        assert is_major_change("3.11.4", "3.11.4") is False

    def test_non_standard_different(self):
        assert is_major_change("alpha", "beta") is True

    def test_non_standard_same(self):
        assert is_major_change("alpha", "alpha") is False


class TestIsDowngrade:
    def test_downgrade(self):
        assert is_downgrade("2.31.0", "2.28.0") is True

    def test_upgrade(self):
        assert is_downgrade("2.28.0", "2.31.0") is False

    def test_same_version(self):
        assert is_downgrade("2.31.0", "2.31.0") is False

    def test_major_downgrade(self):
        assert is_downgrade("3.0.0", "2.9.9") is True

    def test_non_standard_comparison(self):
        # String comparison fallback
        assert is_downgrade("beta", "alpha") is True

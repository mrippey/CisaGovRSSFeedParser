from cisagovrssparser import __version__
import pytest


def test_version():
    assert __version__ == "0.1.0"


@pytest.mark.parametrize(
    "test_input, expected",
    [
        "CVE-2021-27104",
        "CVE: CVE-2021-27104, Summary: Accellion FTA 9_12_370 and earlier is affected by OS command execution via a crafted POST request to various admin endpoints. URL: https://nvd.nist.gov/vuln/detail/CVE-2021-27104 Date Published: November 3, 2021",
    ],
    [
        "CVE-2021-30858",
        "CVE: CVE-2021-30858, Summary: Apple iOS and iPadOS Arbitrary Code Execution, URL: https://nvd.nist.gov/vuln/detail/CVE-2021-27102 Date Published: November 3, 2021"

    ]
)


def search_results_test(test_input, expected):
    actual_result = test_input
    assert actual_result == expected

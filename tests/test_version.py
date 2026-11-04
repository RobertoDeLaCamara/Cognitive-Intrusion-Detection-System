import re

from src.version import __version__


def test_version_is_pep440():
    assert re.fullmatch(r"\d+\.\d+\.\d+((a|b|rc)\d+)?", __version__)


def test_api_reports_the_version():
    from src.api.main import app

    assert app.version == __version__

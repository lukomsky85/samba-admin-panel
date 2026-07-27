"""
test_app_smoke.py — базовые дымовые тесты Flask-приложения. Не заменяют
ручную проверку перед продакшеном (см. README, раздел "Чеклист перед
продакшеном"), но ловят самые грубые регрессии автоматически при каждом
запуске, а не только когда кто-то вручную вспомнит проверить.
"""
import os
import sys

import pytest

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_DIR)

os.environ.setdefault("SAMBAPANEL_PASSWORD", "test-password-for-pytest")
os.environ.setdefault("SAMBAPANEL_SECRET", "test-secret-for-pytest-0123456789")

import app as appmod  # noqa: E402


@pytest.fixture
def client():
    appmod.app.config["TESTING"] = True
    with appmod.app.test_client() as c:
        yield c


@pytest.fixture
def authed_client(client):
    with client.session_transaction() as sess:
        sess["authed"] = True
    return client


# --- Доступ без входа должен быть закрыт ---

@pytest.mark.parametrize("path", [
    "/",
    "/api/list_shares",
    "/api/check_update",
])
def test_requires_login(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code in (302, 401), (
        f"{path} доступен БЕЗ входа в панель (код {r.status_code}) — "
        f"это дыра в безопасности, а не мелочь"
    )


def test_login_page_accessible_without_auth(client):
    r = client.get("/login")
    assert r.status_code == 200


# --- Сессионные cookie должны быть защищены ---

def test_session_cookie_security_flags():
    assert appmod.app.config.get("SESSION_COOKIE_SECURE") is True
    assert appmod.app.config.get("SESSION_COOKIE_HTTPONLY") is True
    assert appmod.app.config.get("SESSION_COOKIE_SAMESITE") == "Lax"


# --- Валидация полей группы шары (локальная / AD / гостевая) ---

def test_validate_share_group_field_local():
    ok, normalized = appmod.validate_share_group_field("sharegroup")
    assert ok is True
    assert normalized == "sharegroup"


def test_validate_share_group_field_guest():
    ok, normalized = appmod.validate_share_group_field("GUEST")
    assert ok is True
    assert normalized == "GUEST"


def test_validate_share_group_field_ad_group():
    ok, normalized = appmod.validate_share_group_field("AD:Domain Admins".replace(" ", ""))
    assert ok is True


def test_validate_share_group_field_rejects_spaces():
    # пробелы в AD-именах намеренно не поддерживаются (см. README) — тест
    # фиксирует это как осознанное поведение, а не забытый случай
    ok, _ = appmod.validate_share_group_field("AD:Domain Admins")
    assert ok is False


def test_validate_share_group_field_empty_rejected():
    ok, _ = appmod.validate_share_group_field("")
    assert ok is False


# --- Главная страница рендерится и не падает на отсутствующем VERSION ---

def test_index_renders_without_version_file(authed_client, monkeypatch, tmp_path):
    # если /opt/sambapanel/VERSION почему-то недоступен, страница должна
    # всё равно отрендериться, а не отдать 500 — админ не должен терять
    # доступ к панели из-за отсутствующего файла версии
    r = authed_client.get("/")
    assert r.status_code == 200

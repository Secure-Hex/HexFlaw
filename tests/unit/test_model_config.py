"""Tests de la configuración de modelos por tier y de la clave del caché."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hexflaw.core.model_policy import ModelTier, Task, choose_model
from hexflaw.core.models import AnalysisMode
from hexflaw.infrastructure import secrets_store
from hexflaw.infrastructure.analysis_cache import AnalysisCache
from hexflaw.infrastructure.config import resolve_config
from hexflaw.services.llm_service import (
    ANTHROPIC_MODELS,
    OPENAI_MODELS,
    AgentQueueLLMService,
    LLMService,
    LLMServiceError,
    OpenAILLMService,
    build_llm_service,
    models_from_config,
)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Aísla ``~/.hexflaw`` para no leer la config real del usuario."""
    monkeypatch.setenv("HEXFLAW_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(secrets_store, "get_secret", lambda key: None)


def _key(model: str) -> str:
    """Clave de caché de un mismo chunk y perfil, variando solo el modelo."""
    return AnalysisCache.make_key("CHUNK_HASH", model, ["command_injection"], 1)


def test_each_backend_resolves_the_same_tier_to_its_own_model() -> None:
    """El tier es el contrato; el modelo concreto es detalle de cada backend."""
    tier = choose_model(Task.TAINT, AnalysisMode.BALANCED)
    anthropic = LLMService(api_key="x", models=dict(ANTHROPIC_MODELS))
    openai = OpenAILLMService(api_key="x", models=dict(OPENAI_MODELS))

    assert anthropic.resolve_model(tier) == ANTHROPIC_MODELS[tier]
    assert openai.resolve_model(tier) == OPENAI_MODELS[tier]
    assert anthropic.resolve_model(tier) != openai.resolve_model(tier)


def test_model_without_magic_words_in_its_name_resolves_correctly() -> None:
    """Un modelo cuyo nombre no dice 'opus' ni 'haiku' debe resolver igual.

    La implementación anterior deducía el tier por substring del nombre del modelo
    de Anthropic, así que cualquier modelo con otro nombre —uno local, uno nuevo,
    uno de otro proveedor— caía al tier del medio sin decir nada.
    """
    svc = LLMService(
        api_key="x",
        models={**ANTHROPIC_MODELS, ModelTier.DEEP: "mi-modelo-local-v3"},
    )
    assert svc.resolve_model(ModelTier.DEEP) == "mi-modelo-local-v3"


def test_missing_tier_fails_loudly() -> None:
    """Un tier sin modelo no puede degradar en silencio a otro."""
    svc = LLMService(api_key="x", models={ModelTier.CHEAP: "algo"})
    with pytest.raises(LLMServiceError, match="deep"):
        svc.resolve_model(ModelTier.DEEP)


def test_cache_key_differs_across_backends() -> None:
    """REGRESIÓN: dos backends no pueden compartir clave de caché.

    La clave usaba el nombre que pedía el pipeline, no el que realmente corrió. Con
    el backend de OpenAI, un chunk analizado por ``gpt-4o-mini`` quedaba guardado
    bajo una clave que afirmaba ``claude-haiku-…``; el run siguiente con Anthropic
    servía esa respuesta como si la hubiera producido Claude.
    """
    tier = choose_model(Task.STATIC_SIMPLE, AnalysisMode.BALANCED)
    anthropic = LLMService(api_key="x", models=dict(ANTHROPIC_MODELS))
    openai = OpenAILLMService(api_key="x", models=dict(OPENAI_MODELS))

    assert _key(anthropic.resolve_model(tier)) != _key(openai.resolve_model(tier))


def test_changing_a_model_invalidates_its_cached_analysis() -> None:
    """Cambiar el modelo de un tier debe invalidar lo analizado con el anterior."""
    viejo = LLMService(api_key="x", models={**ANTHROPIC_MODELS, ModelTier.DEEP: "claude-opus-4-8"})
    nuevo = LLMService(api_key="x", models={**ANTHROPIC_MODELS, ModelTier.DEEP: "claude-opus-5"})

    assert _key(viejo.resolve_model(ModelTier.DEEP)) != _key(nuevo.resolve_model(ModelTier.DEEP))
    # Y no arrastra a los tiers que no se tocaron.
    assert _key(viejo.resolve_model(ModelTier.CHEAP)) == _key(nuevo.resolve_model(ModelTier.CHEAP))


def test_config_override_reaches_the_service() -> None:
    """Editar config alcanza para estrenar un modelo nuevo, sin tocar código."""
    cfg = resolve_config(overrides={"anthropic_model_deep": "claude-opus-6"})
    assert build_llm_service(cfg).models[ModelTier.DEEP] == "claude-opus-6"


def test_defaults_come_from_the_backend_catalog() -> None:
    """Sin overrides, los tres tiers resuelven al catálogo del paquete."""
    assert build_llm_service(resolve_config()).models == ANTHROPIC_MODELS


def test_local_config_overrides_only_the_tier_it_names(tmp_path: Path) -> None:
    """Sobreescribir un tier en el config local no puede borrar los otros dos.

    Es el motivo por el que las claves son planas y no un dict anidado: la
    jerarquía de config mergea con ``dict.update()`` por capa.
    """
    hexflaw_dir = tmp_path / ".hexflaw"
    hexflaw_dir.mkdir()
    (hexflaw_dir / "config.json").write_text(
        json.dumps({"anthropic_model_deep": "solo-este"}), encoding="utf-8"
    )
    models = build_llm_service(resolve_config(tmp_path)).models

    assert models[ModelTier.DEEP] == "solo-este"
    assert models[ModelTier.CHEAP] == ANTHROPIC_MODELS[ModelTier.CHEAP]
    assert models[ModelTier.MID] == ANTHROPIC_MODELS[ModelTier.MID]


def test_deprecated_model_key_still_works() -> None:
    """La clave 'model' de antes de los tiers no puede romperle la config a nadie."""
    cfg = resolve_config(overrides={"model": "claude-sonnet-4-6"})
    models = build_llm_service(cfg).models
    assert models[ModelTier.MID] == "claude-sonnet-4-6"
    assert models[ModelTier.DEEP] == ANTHROPIC_MODELS[ModelTier.DEEP]


def test_explicit_tier_beats_the_deprecated_key() -> None:
    """Si están las dos, gana la específica."""
    cfg = resolve_config(
        overrides={"model": "viejo", "anthropic_model_mid": "nuevo"}
    )
    assert build_llm_service(cfg).models[ModelTier.MID] == "nuevo"


def test_agent_backend_inherits_the_anthropic_catalog() -> None:
    """El request que se parkea debe nombrar un modelo, no un tier opaco.

    Quien responde la cola necesita saber qué capacidad se espera de él; ``deep``
    no se lo dice.
    """
    svc = build_llm_service(resolve_config(overrides={"llm_backend": "agent"}))
    assert isinstance(svc, AgentQueueLLMService)
    assert svc.resolve_model(ModelTier.DEEP) == ANTHROPIC_MODELS[ModelTier.DEEP]


def test_models_from_config_is_total() -> None:
    """El mapa siempre trae los tres tiers, aunque la config esté vacía."""
    for prefix, fallback in (("anthropic", ANTHROPIC_MODELS), ("openai", OPENAI_MODELS)):
        models = models_from_config(resolve_config(), prefix, fallback)
        assert set(models) == set(ModelTier)
        assert all(models.values())


def test_models_set_persists_and_list_reflects_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """El comando escribe la config global y 'list' muestra el valor efectivo."""
    from typer.testing import CliRunner

    from hexflaw.cli.commands.models import app

    runner = CliRunner()
    result = runner.invoke(app, ["set", "--deep", "claude-opus-6"])
    assert result.exit_code == 0, result.output
    # La advertencia de invalidación del caché no es opcional: es la consecuencia
    # real de cambiar el modelo y el usuario tiene que verla.
    assert "invalidado" in result.output

    saved = json.loads((tmp_path / "home" / "config.json").read_text(encoding="utf-8"))
    assert saved["anthropic_model_deep"] == "claude-opus-6"
    assert build_llm_service(resolve_config()).models[ModelTier.DEEP] == "claude-opus-6"

    listed = runner.invoke(app, ["list"])
    assert listed.exit_code == 0, listed.output
    assert "claude-opus-6" in listed.output


def test_models_set_without_any_tier_fails() -> None:
    """Un 'set' sin argumentos no puede reportar éxito sin haber hecho nada."""
    from typer.testing import CliRunner

    from hexflaw.cli.commands.models import app

    result = CliRunner().invoke(app, ["set"])
    assert result.exit_code == 1


def test_models_set_rejects_a_backend_without_catalog() -> None:
    """El backend 'agent' no tiene catálogo propio: pedirlo debe fallar claro."""
    from typer.testing import CliRunner

    from hexflaw.cli.commands.models import app

    result = CliRunner().invoke(app, ["set", "--backend", "agent", "--deep", "x"])
    assert result.exit_code == 1

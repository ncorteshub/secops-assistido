import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Union

from secops_core.db import SecOpsRepository
from secops_core.explainer.renderer import (
    AlertExplanationContext,
    AlertExplanationRenderer,
)
from secops_core.pipeline import DetectionResult

logger = logging.getLogger(__name__)


class OllamaExplainerClient:
    """
    Cliente de integração com o servidor Ollama local (ex: llama3.2, qwen2.5, mistral, phi3)
    com mecanismo de fallback resiliente baseado em templates Jinja2 e persistência em SQLite.
    Execução 100% local, privada e com custo zero (sem APIs externas pagas).
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        timeout: float = 30.0,
        healthcheck_timeout: float = 2.0,
        renderer: Optional[AlertExplanationRenderer] = None,
        repository: Optional[SecOpsRepository] = None,
    ) -> None:
        raw_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.base_url = raw_url.rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.2")
        self.timeout = float(timeout)
        self.healthcheck_timeout = float(healthcheck_timeout)
        self.renderer = renderer or AlertExplanationRenderer()
        self.repository = repository
        self.last_source: Optional[str] = None

    def healthcheck(self) -> bool:
        """
        Consulta rápida de integridade para verificar se o servidor Ollama está ativo.
        Utiliza GET /api/tags com timeout reduzido para não travar o pipeline.
        """
        url = f"{self.base_url}/api/tags"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=self.healthcheck_timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                return 200 <= status < 400
        except Exception as e:
            logger.debug("Ollama healthcheck falhou em %s: %s", url, e)
            return False

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """
        Executa POST /api/generate no Ollama local sem streaming.
        Captura exceções de rede, timeout e status HTTP inválidos.
        """
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                if 200 <= status < 300:
                    body = resp.read().decode("utf-8")
                    parsed = json.loads(body)
                    response_text = parsed.get("response")
                    if response_text and isinstance(response_text, str):
                        return response_text.strip()
                logger.warning(
                    "Ollama retornou status HTTP inesperado (%s) em %s",
                    status,
                    url,
                )
                return None
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            logger.warning(
                "Falha na comunicação com o servidor Ollama (%s): %s",
                url,
                e,
            )
            return None
        except Exception as e:
            logger.error("Erro inesperado na chamada ao Ollama (%s): %s", url, e)
            return None

    def persist_explanation(self, event_id: str, explanation: str) -> bool:
        """Persiste a explicação gerada na coluna ai_explanation do registro SQLite."""
        if not event_id:
            return False
        repo = self.repository or SecOpsRepository()
        return repo.update_ai_explanation(event_id, explanation)

    def generate_explanation(
        self,
        data: Union[DetectionResult, AlertExplanationContext, Dict[str, Any], None] = None,
        event_id: Optional[str] = None,
        persist: bool = False,
        **kwargs: Any,
    ) -> str:
        """
        Gera uma explicação contextualizada e estruturada para o alerta:
        1. Renderiza o prompt anti-alucinação a partir de alert_explanation.j2.
        2. Tenta inferência via Ollama local (/api/generate).
        3. Se offline, timeout ou erro de rede, aciona automaticamente o fallback Jinja2 (fallback_explanation.j2).
        4. Opcionalmente persiste a explicação no banco SQLite.
        """
        target_event_id = event_id
        if not target_event_id:
            if isinstance(data, DetectionResult):
                target_event_id = data.event_id
            elif isinstance(data, dict):
                target_event_id = data.get("event_id") or data.get("eventID")

        prompt = self.renderer.render_prompt(data, **kwargs)

        explanation: Optional[str] = None
        source = "fallback"

        # Tenta inferência via Ollama apenas se o servidor estiver ativo
        if self.healthcheck():
            explanation = self._call_ollama(prompt)
            if explanation:
                source = "ollama"

        # Fallback determinístico e estruturado via Jinja2 caso o Ollama esteja offline ou falhe
        if not explanation:
            logger.info("Acionando fallback determinístico Jinja2 para o alerta %s", target_event_id or "desconhecido")
            explanation = self.renderer.render_fallback(data, **kwargs)
            source = "fallback"

        self.last_source = source

        # Persistência no SQLite
        if target_event_id and (persist or self.repository is not None):
            self.persist_explanation(target_event_id, explanation)

        return explanation

    def explain_and_persist(
        self,
        data: Union[DetectionResult, AlertExplanationContext, Dict[str, Any], None] = None,
        event_id: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Gera a explicação e força a persistência no banco SQLite."""
        return self.generate_explanation(data=data, event_id=event_id, persist=True, **kwargs)

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import BaseModel, Field

from secops_core.detectors.cloudtrail_rules import RuleViolation, Severity
from secops_core.pipeline import DetectionResult


class AlertExplanationContext(BaseModel):
    """Contexto estruturado e tipado para alimentação de templates de explicação SecOps."""

    user: Optional[str] = Field(default=None, description="Identidade / ARN / Usuário do evento")
    source_ip: Optional[str] = Field(default=None, description="Endereço IP de origem")
    event_name: Optional[str] = Field(default=None, description="Nome do evento (ex: StopLogging, GetObject)")
    event_source: Optional[str] = Field(default=None, description="Serviço AWS de origem (ex: s3.amazonaws.com)")
    timestamp: Optional[str] = Field(default=None, description="Data/hora do evento em formato ISO ou texto")
    severity: str = Field(default="MEDIUM", description="Nível de severidade consolidado")
    zscore: Optional[float] = Field(default=None, description="Score Z estatístico, se detectado")
    iforest_score: Optional[float] = Field(default=None, description="Score do Isolation Forest, se detectado")
    cloudtrail_rules: Optional[List[Any]] = Field(
        default=None, description="Lista de violações de regras determinísticas disparadas"
    )
    technical_justification: Optional[str] = Field(
        default=None, description="Justificativa técnica consolidada do pipeline"
    )


class AlertExplanationRenderer:
    """
    Renderizador de prompts de contextualização e explicação de alertas SecOps.
    Utiliza Jinja2 com StrictUndefined e FileSystemLoader garantindo determinismo
    e conformidade estrita com modelos locais leves (Ollama: llama3.2, qwen2.5, mistral, phi3).
    """

    def __init__(
        self,
        templates_dir: Optional[Union[str, Path]] = None,
        template_name: str = "alert_explanation.j2",
    ) -> None:
        if templates_dir is None:
            templates_dir = Path(__file__).resolve().parent / "templates"
        self.templates_dir = Path(templates_dir)
        self.template_name = template_name

        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.template = self.env.get_template(self.template_name)

    @staticmethod
    def _extract_user(event_dict: Dict[str, Any]) -> Optional[str]:
        """Extrai o identificador de usuário/ARN lidando com variações de schema."""
        raw_user = (
            event_dict.get("user")
            or event_dict.get("user_identity")
            or event_dict.get("userIdentity")
            or event_dict.get("user_arn")
        )
        if isinstance(raw_user, dict):
            return raw_user.get("arn") or raw_user.get("userName") or raw_user.get("type")
        if raw_user is not None:
            return str(raw_user)
        return None

    @staticmethod
    def _extract_ip(event_dict: Dict[str, Any]) -> Optional[str]:
        """Extrai o IP de origem a partir de chaves comuns."""
        ip = (
            event_dict.get("source_ip")
            or event_dict.get("sourceIPAddress")
            or event_dict.get("ip")
        )
        return str(ip) if ip is not None else None

    def build_context(
        self,
        data: Union[DetectionResult, AlertExplanationContext, Dict[str, Any], None] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Consolida e normaliza os dados de entrada em um dicionário seguro e completo
        para renderização com StrictUndefined sem riscos de KeyError ou UndefinedError.
        """
        context: Dict[str, Any] = {
            "user": None,
            "source_ip": None,
            "event_name": None,
            "event_source": None,
            "timestamp": None,
            "severity": "MEDIUM",
            "zscore": None,
            "iforest_score": None,
            "cloudtrail_rules": None,
            "technical_justification": None,
        }

        if isinstance(data, DetectionResult):
            raw = data.raw_event or {}
            context["user"] = self._extract_user(raw)
            context["source_ip"] = self._extract_ip(raw)
            context["event_name"] = data.event_name or raw.get("event_name") or raw.get("eventName")
            context["event_source"] = data.event_source or raw.get("event_source") or raw.get("eventSource")
            context["timestamp"] = data.timestamp or raw.get("timestamp") or raw.get("eventTime")
            context["severity"] = data.severity.value if hasattr(data.severity, "value") else str(data.severity)
            context["zscore"] = data.zscore_value if data.zscore_anomaly else None
            context["iforest_score"] = data.isolation_forest_score if data.isolation_forest_anomaly else None
            context["cloudtrail_rules"] = data.rule_violations if data.rule_violations else None
            context["technical_justification"] = data.technical_justification

        elif isinstance(data, AlertExplanationContext):
            dumped = data.model_dump()
            context.update({k: v for k, v in dumped.items() if v is not None})

        elif isinstance(data, dict):
            raw = data.get("raw_event") or data
            context["user"] = self._extract_user(raw)
            context["source_ip"] = self._extract_ip(raw)
            context["event_name"] = (
                data.get("event_name")
                or data.get("eventName")
                or raw.get("event_name")
                or raw.get("eventName")
            )
            context["event_source"] = (
                data.get("event_source")
                or data.get("eventSource")
                or raw.get("event_source")
                or raw.get("eventSource")
            )
            context["timestamp"] = (
                data.get("timestamp")
                or data.get("eventTime")
                or data.get("horario")
                or raw.get("timestamp")
                or raw.get("eventTime")
            )
            sev = data.get("severity") or data.get("final_severity")
            if sev is not None:
                context["severity"] = sev.value if hasattr(sev, "value") else str(sev)

            z_val = data.get("zscore") if data.get("zscore") is not None else data.get("zscore_value")
            z_flag = data.get("zscore_anomaly") or data.get("is_zscore_anomaly")
            if z_flag is not None:
                context["zscore"] = float(z_val) if z_flag and z_val is not None else None
            elif z_val is not None:
                context["zscore"] = float(z_val)

            if_val = data.get("iforest_score") if data.get("iforest_score") is not None else data.get("isolation_forest_score")
            if_flag = data.get("isolation_forest_anomaly") or data.get("is_iforest_anomaly")
            if if_flag is not None:
                context["iforest_score"] = float(if_val) if if_flag and if_val is not None else None
            elif if_val is not None:
                context["iforest_score"] = float(if_val)

            rules = (
                data.get("cloudtrail_rules")
                or data.get("rule_violations")
                or data.get("cloudtrail_rules_triggered")
            )
            if isinstance(rules, str):
                try:
                    rules = json.loads(rules)
                except Exception:
                    rules = [rules]
            context["cloudtrail_rules"] = rules if rules else None
            context["technical_justification"] = (
                data.get("technical_justification")
                or data.get("anomaly_reason")
            )

        # Atualizações diretas via kwargs têm prioridade máxima
        for k, v in kwargs.items():
            if k == "severity" and hasattr(v, "value"):
                context["severity"] = v.value
            elif k in context:
                context[k] = v
            else:
                context[k] = v

        return context

    def render(
        self,
        data: Union[DetectionResult, AlertExplanationContext, Dict[str, Any], None] = None,
        template_name: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Renderiza o template especificado (ou alert_explanation.j2) sem qualquer concatenação hardcoded em Python."""
        context = self.build_context(data, **kwargs)
        tpl = self.env.get_template(template_name) if template_name else self.template
        return tpl.render(context)

    def render_prompt(
        self,
        data: Union[DetectionResult, AlertExplanationContext, Dict[str, Any], None] = None,
        **kwargs: Any,
    ) -> str:
        """Renderiza o prompt contextualizado otimizado para envio ao LLM local."""
        return self.render(data, template_name="alert_explanation.j2", **kwargs)

    def render_fallback(
        self,
        data: Union[DetectionResult, AlertExplanationContext, Dict[str, Any], None] = None,
        **kwargs: Any,
    ) -> str:
        """Renderiza a explicação de fallback determinística quando o LLM estiver offline ou falhar."""
        return self.render(data, template_name="fallback_explanation.j2", **kwargs)


def render_alert_explanation(
    data: Union[DetectionResult, AlertExplanationContext, Dict[str, Any], None] = None,
    **kwargs: Any,
) -> str:
    """Função de conveniência para renderizar o prompt de explicação de alertas SecOps."""
    renderer = AlertExplanationRenderer()
    return renderer.render_prompt(data, **kwargs)


def render_fallback_explanation(
    data: Union[DetectionResult, AlertExplanationContext, Dict[str, Any], None] = None,
    **kwargs: Any,
) -> str:
    """Função de conveniência para renderizar a explicação determinística de fallback."""
    renderer = AlertExplanationRenderer()
    return renderer.render_fallback(data, **kwargs)

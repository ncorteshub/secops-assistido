import json
import logging
import pandas as pd
from pydantic import BaseModel, ValidationError
from datetime import datetime
from typing import List, Optional

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

# ---------------------------------------------------------
# 1. SCHEMA CANÔNICO (Padrão AWS CloudTrail)
# ---------------------------------------------------------
class UserIdentity(BaseModel):
    """Sub-modelo para mapear o dicionário aninhado de identidade"""
    arn: str

class CanonicalLog(BaseModel):
    """Mapeamento exato das chaves geradas pelo seu script"""
    timestamp: datetime
    event_id: str
    event_name: str
    event_source: str
    user_identity: UserIdentity
    source_ip: str
    aws_region: str
    status: str
    error_code: Optional[str] = None
    request_count: int
    bytes_transferred: int

# ---------------------------------------------------------
# 2. PROCESSADOR LGMS
# ---------------------------------------------------------
class LGMSProcessor:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.parsed_logs: List[CanonicalLog] = []

    def parse_file(self):
        with open(self.filepath, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                if not line.strip():
                    continue
                try:
                    raw_dict = json.loads(line)
                    valid_log = CanonicalLog(**raw_dict)
                    self.parsed_logs.append(valid_log)
                except json.JSONDecodeError:
                    logging.warning(f"Linha {line_num}: JSON Invalido. Ignorando...")
                except ValidationError as e:
                    logging.warning(f"Linha {line_num}: Fora do Schema. Erro: {e.errors()[0]['msg']}")

        print(f"Sucesso: {len(self.parsed_logs)} logs processados e validados com sucesso.")

    def get_feature_matrix(self) -> pd.DataFrame:
        if not self.parsed_logs:
            return pd.DataFrame()

        # Converte para DataFrame do Pandas
        df = pd.DataFrame([log.model_dump() for log in self.parsed_logs])

        # --- ENGENHARIA DE FEATURES ---
        
        # 1. Achatamento (Flatten) do ARN
        # O Pandas cria a coluna user_identity como um dicionário. Precisamos extrair apenas o texto.
        df['user_arn'] = df['user_identity'].apply(lambda x: x['arn'] if isinstance(x, dict) else None)
        df = df.drop(columns=['user_identity'])

        # 2. Features Temporais
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour_of_day'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek

        # 3. Indicador Binário de Erro
        # No seu log, o sucesso vem escrito como "Success". Tudo diferente disso vira 1 (Erro).
        df['is_error'] = df['status'].apply(lambda x: 0 if str(x).upper() == 'SUCCESS' else 1)

        # 4. Frequência de Comportamento (Contagem de volumetria)
        df['ip_freq_count'] = df.groupby('source_ip')['source_ip'].transform('count')
        df['user_freq_count'] = df.groupby('user_arn')['user_arn'].transform('count')

        return df

if __name__ == "__main__":
    processor = LGMSProcessor(filepath="data/logs_simulados.jsonl")
    processor.parse_file()
    df_features = processor.get_feature_matrix()
    
    if not df_features.empty:
        print("\nMatriz de Features gerada com sucesso. Amostra para o modelo:")
        # Exibe colunas chaves prontas para as regras de negócio
        print(df_features[['timestamp', 'event_name', 'user_arn', 'is_error', 'ip_freq_count', 'bytes_transferred']].head())
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import yaml
from mon_scanner.utils.logger import logger

# Désactiver les alertes pour les certificats SSL auto-signés
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Requester:
    def __init__(self, config_path="mon_scanner/config/config.yaml"):
        self.session = requests.Session()
        self.config = self._load_config(config_path)
        self.timeout = self.config.get('scanner', {}).get('timeout', 10)
        
        # Configuration des en-têtes par défaut
        user_agent = self.config.get('scanner', {}).get('user_agent', 'WebVulnScanner/1.0')
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })
    
    def _load_config(self, config_path):
        try:
            with open(config_path, 'r') as file:
                return yaml.safe_load(file)
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {e}")
            return {}

    def get(self, url, params=None, allow_redirects=True):
        try:
            response = self.session.get(
                url, 
                params=params, 
                timeout=self.timeout, 
                allow_redirects=allow_redirects,
                verify=False # Utile pour tester des environnements de dev
            )
            return response
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout lors de la requête GET sur {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Erreur de requête GET sur {url}: {e}")
            return None

    def post(self, url, data=None, json=None, allow_redirects=True):
        try:
            response = self.session.post(
                url, 
                data=data, 
                json=json,
                timeout=self.timeout, 
                allow_redirects=allow_redirects,
                verify=False
            )
            return response
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout lors de la requête POST sur {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Erreur de requête POST sur {url}: {e}")
            return None

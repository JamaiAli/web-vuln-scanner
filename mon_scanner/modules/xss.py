from mon_scanner.utils.logger import logger
import urllib.parse
import os

class XSSScanner:
    def __init__(self, requester):
        self.requester = requester
        self.payloads = self._load_payloads("mon_scanner/payloads/xss.txt")

    def _load_payloads(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            logger.warning(f"Fichier de payloads ({filepath}) non trouvé. Utilisation des payloads XSS par défaut.")
            return [
                "<script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "javascript:alert('XSS')"
            ]

    def is_vulnerable(self, response, payload):
        """Vérifie si le payload est reflété non-échappé dans la réponse"""
        if not response:
            return False
            
        content = response.text
        # Si le payload est renvoyé tel quel, c'est potentiellement un Reflected XSS
        return payload in content

    def scan_url(self, url):
        results = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query)

        if not params:
            return results

        for key, value in params:
            for payload in self.payloads:
                test_params = {}
                for k, v in params:
                    if k == key:
                        test_params[k] = payload
                    else:
                        test_params[k] = v
                
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                response = self.requester.get(base_url, params=test_params)
                
                if self.is_vulnerable(response, payload):
                    logger.error(f"[XSS] Reflected XSS trouvé sur {url} (param: {key})")
                    results.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "Medium",
                        "url": url,
                        "parameter": key,
                        "method": "GET",
                        "payload": payload,
                        "description": "Les données entrées sont retournées sans nettoyage au sein de la vue HTML, exposant à une exécution JavaScript.",
                        "remediation": "Utilisez de l'encodage HTML entités (Html Entities Encoding) avant l'affichage des données."
                    })
                    break 
        return results

    def scan_form(self, url, form):
        results = []
        action = form.get("action")
        method = form.get("method", "get")
        inputs = form.get("inputs", [])

        for target_input in inputs:
            input_name = target_input.get("name")
            if not input_name or target_input.get("type") in ["hidden", "submit"]:
                continue

            for payload in self.payloads:
                data = {}
                for inp in inputs:
                    if inp.get("name") == input_name:
                        data[inp.get("name")] = payload
                    else:
                        data[inp.get("name")] = "test"
                
                if method == "post":
                    response = self.requester.post(action, data=data)
                else:
                    response = self.requester.get(action, params=data)
                
                if self.is_vulnerable(response, payload):
                    logger.error(f"[XSS] XSS trouvé dans {url} via le champ '{input_name}'")
                    results.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "Medium",
                        "url": url,
                        "parameter": input_name,
                        "method": method.upper(),
                        "payload": payload,
                        "description": "L'entrée utilisateur est affichée directement dans la page. Un attaquant peut injecter du Javascript malveillant.",
                        "remediation": "Encodez proprement toutes les sorties web avec un encodeur sensible au contexte HTML."
                    })
                    break
        return results

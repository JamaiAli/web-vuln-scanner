from mon_scanner.utils.logger import logger
import urllib.parse
import os

class SQLiScanner:
    def __init__(self, requester):
        self.requester = requester
        self.payloads = self._load_payloads("mon_scanner/payloads/sqli.txt")
        # Liste des erreurs SQL communes retournées par les BDD
        self.sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "syntax error in string in query expression"
        ]

    def _load_payloads(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            logger.warning(f"Fichier de payloads interne ({filepath}) non trouvé. Utilisation de payloads par défaut.")
            return ["'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "\\\\", "%;", "' or 1=1--", "' OR '1'='1"]

    def is_vulnerable(self, response):
        """Vérifie si la réponse contient une erreur SQL classique (Error-Based SQLi)"""
        if not response:
            return False
            
        content = response.text.lower()
        for error in self.sql_errors:
            if error in content:
                return True
        return False

    def scan_url(self, url):
        """Scan les paramètres GET d'une URL"""
        results = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query)

        if not params:
            return results

        for key, value in params:
            for payload in self.payloads:
                # Construire le dictionnaire de param modifiés
                test_params = {}
                for k, v in params:
                    if k == key:
                        test_params[k] = v + payload
                    else:
                        test_params[k] = v
                
                # Reconstruire l'URL
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                response = self.requester.get(base_url, params=test_params)
                
                if self.is_vulnerable(response):
                    logger.critical(f"[SQLi] Vulnérabilité probable trouvée sur {url} via le paramètre GET '{key}' avec le payload '{payload}'")
                    results.append({
                        "type": "SQL Injection",
                        "severity": "High",
                        "url": url,
                        "parameter": key,
                        "method": "GET",
                        "payload": payload,
                        "description": "Une erreur de syntaxe SQL a été retournée en fuyant dans la réponse de la page. Cela indique une injection classique basée sur l'erreur.",
                        "remediation": "Utilisez des requêtes préparées (Prepared Statements) ou des requêtes paramétrées."
                    })
                    break # On passe au paramètre suivant si on a trouvé
        return results

    def scan_form(self, url, form):
        """Scan les inputs d'un formulaire"""
        results = []
        action = form.get("action")
        method = form.get("method", "get")
        inputs = form.get("inputs", [])

        for target_input in inputs:
            input_name = target_input.get("name")
            if not input_name:
                continue

            for payload in self.payloads:
                # Préparer les données pour POST/GET
                data = {}
                for inp in inputs:
                    if inp.get("name") == input_name:
                        data[inp.get("name")] = target_input.get("value", "") + payload
                    else:
                        data[inp.get("name")] = inp.get("value", "test")
                
                if method == "post":
                    response = self.requester.post(action, data=data)
                else:
                    response = self.requester.get(action, params=data)
                
                if self.is_vulnerable(response):
                    logger.critical(f"[SQLi] Vulnérabilité probable trouvée dans le formulaire de {url} via l'input '{input_name}'")
                    results.append({
                        "type": "SQL Injection",
                        "severity": "High",
                        "url": url,
                        "parameter": input_name,
                        "method": method.upper(),
                        "payload": payload,
                        "description": "Le formulaire semble vulnérable aux injections SQL.",
                        "remediation": "Utilisez des requêtes préparées pour sécuriser et ne concaténez jamais les entrées utilisateur directement."
                    })
                    break
        return results

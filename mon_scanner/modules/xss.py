from mon_scanner.utils.logger import logger
import urllib.parse
import os
import uuid

class XSSScanner:
    def __init__(self, requester):
        self.requester = requester
        self.payloads = self._load_payloads("mon_scanner/payloads/xss.txt")
        self.injected_stored_payloads = [] # Pour garder trace des payloads balises injectés

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
        """Vérifie si le payload est reflété non-échappé dans la réponse (Reflected XSS)"""
        if not response:
            return False
            
        content = response.text
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
                        "type": "Cross-Site Scripting (Reflected)",
                        "severity": "Medium",
                        "url": url,
                        "parameter": key,
                        "method": "GET",
                        "payload": payload,
                        "description": "Les données entrées sont retournées sans nettoyage au sein de la vue HTML, exposant à une exécution JavaScript ciblée.",
                        "remediation": "Utilisez un encodage HTML (Html Entities Encoding) avant l'affichage des données."
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
                # Préparation des données pour tester le Reflected XSS
                data = {}
                for inp in inputs:
                    if inp.get("name") == input_name:
                        data[inp.get("name")] = payload
                    else:
                        data[inp.get("name")] = "test"
                
                # Exécution de la requête pour Reflected
                if method == "post":
                    response = self.requester.post(action, data=data)
                    
                    # En parallèle, injection silencieuse pour le Stored XSS
                    unique_stored_payload = f"<u>test_{str(uuid.uuid4())[:8]}</u>"
                    data_stored = data.copy()
                    data_stored[input_name] = unique_stored_payload
                    self.requester.post(action, data=data_stored)
                    self.injected_stored_payloads.append({
                        "payload": unique_stored_payload,
                        "source_url": url,
                        "input_name": input_name
                    })
                else:
                    response = self.requester.get(action, params=data)
                
                # Check Reflected (Maintenant actif pour GET ET POST)
                if self.is_vulnerable(response, payload):
                    logger.error(f"[XSS] Reflected XSS trouvé dans {url} via le champ '{input_name}'")
                    results.append({
                        "type": "Cross-Site Scripting (Reflected)",
                        "severity": "Medium",
                        "url": url,
                        "parameter": input_name,
                        "method": method.upper(),
                        "payload": payload,
                        "description": "L'entrée utilisateur est affichée directement dans la page sans échappement.",
                        "remediation": "Encodez proprement toutes les sorties web sensibles pour le contexte d'insertion HTML."
                    })
                    break
        return results

    def verify_stored_xss(self, crawled_urls):
        """
        Passe sur toutes les URL trouvées lors du crawl afin de déterminer
        si l'un des payloads poussés en POST s'affiche sur les autres pages (XSS Persistant)
        """
        results = []
        if not self.injected_stored_payloads:
            return results

        # Parcourir notamment les pages de resume (account-summary, dashboard etc.)
        for url in crawled_urls:
            response = self.requester.get(url)
            if not response or 'text/html' not in response.headers.get('Content-Type', ''):
                continue
                
            content = response.text
            
            # Vérifier la présence persistante de nos payloads (ex: <u>test_123</u>)
            for injected in self.injected_stored_payloads:
                if injected["payload"] in content:
                    logger.critical(f"[XSS STORED] Vulnérabilité XSS Persistante découverte sur {url} via l'injection dans {injected['source_url']} (champ '{injected['input_name']}')")
                    
                    # Eviter d'enregistrer le même payload s'il apparait sur pleins de pages différentes
                    found_payloads = [r["payload"] for r in results]
                    if injected["payload"] not in found_payloads:
                        results.append({
                            "type": "Stored Cross-Site Scripting (Persistent XSS)",
                            "severity": "Critical",
                            "url": url,
                            "parameter": injected['input_name'] + " (depuis " + injected['source_url'] + ")",
                            "method": "POST",
                            "payload": injected['payload'],
                            "description": "Une grave vulnérabilité XSS où la donnée a été enregistrée en base de données ou en session, et est réutilisée sans nettoyage lors de l'affichage global. La balise cible s'est exécutée.",
                            "remediation": "Encodez impérativement à la SAISIE et / ou à la SORTIE chaque valeur extraite d'une data store utilisateur."
                        })
        return results

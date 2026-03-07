from mon_scanner.utils.logger import logger
import re

class CSRFScanner:
    def __init__(self):
        # Liste de noms typiques utilisés pour les tokens anti-CSRF
        self.csrf_tokens_names = [
            "csrf", "csrf_token", "csrftoken", "authenticity_token", "_token", "xsrf", "xsrf_token", "user_token"
        ]
        
        # Mots-clés indiquant qu'un formulaire est sensible (transfert, banque, compte, passwd)
        self.sensitive_keywords = ["transfer", "bank", "account", "password", "settings", "profile"]

    def is_sensitive_form(self, action, url):
        """Détermine si le formulaire est une cible probable pour une attaque CSRF"""
        combined = (action + url).lower()
        return any(keyword in combined for keyword in self.sensitive_keywords)

    def scan_form(self, url, form):
        """Vérifie si un formulaire sensible (POST) possède un token anti-CSRF"""
        results = []
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])
        action = form.get("action", url)

        # CSRF s'applique par essence sur des actions d'état (POST)
        if method != "post":
            return results
            
        # Si le formulaire n'a pas l'air sensible, on l'ignore pour éviter les faux positifs (ex: barre de recherche en POST)
        if not self.is_sensitive_form(action, url):
            return results

        has_token = False
        for inp in inputs:
            name = inp.get("name", "").lower()
            input_type = inp.get("type", "").lower()
            
            # Un jeton CSRF est très souvent un champ caché (hidden)
            if input_type == "hidden" and (any(token in name for token in self.csrf_tokens_names) or "token" in name):
                has_token = True
                break
        
        if not has_token:
            logger.critical(f"[CSRF] ALERTE: Aucun jeton anti-CSRF trouvé dans le formulaire CRITIQUE: {action}")
            results.append({
                "type": "Cross-Site Request Forgery (CSRF)",
                "severity": "High", # Passé à High car ciblé sur formulaire sensible
                "url": url,
                "parameter": "Form Action: " + action,
                "method": "POST",
                "payload": "N/A (Missing Token)",
                "description": "Le formulaire (réalisant une action sensible) ne contient pas de jeton Anti-CSRF (champ hidden type user_token). Un attaquant pourrait forcer l'utilisateur à exécuter cette action sans son consentement.",
                "remediation": "Implémentez un jeton CSRF, imprévisible et unique par session, vérifié obligatoirement côté serveur lors de la soumission."
            })
            
        return results

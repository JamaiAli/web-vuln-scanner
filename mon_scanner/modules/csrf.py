from mon_scanner.utils.logger import logger
import re

class CSRFScanner:
    def __init__(self):
        # Liste de noms typiques utilisés pour les tokens anti-CSRF
        self.csrf_tokens_names = [
            "csrf", "csrf_token", "csrftoken", "authenticity_token", "_token", "xsrf", "xsrf_token"
        ]

    def scan_form(self, url, form):
        """Vérifie si un formulaire (surtout POST) possède un token anti CSRF"""
        results = []
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])
        action = form.get("action", url)

        # On se concentre surtout sur les requêtes à effet de bord (POST)
        if method != "post":
            return results

        has_token = False
        for inp in inputs:
            name = inp.get("name", "").lower()
            if any(token in name for token in self.csrf_tokens_names) or "token" in name:
                # Optionnellement, on pourrait vérifier si le champ type est 'hidden'
                has_token = True
                break
        
        if not has_token:
            logger.warning(f"[CSRF] Aucun jeton anti-CSRF trouvé dans le formulaire POST vers: {action}")
            results.append({
                "type": "Cross-Site Request Forgery (CSRF)",
                "severity": "Low",
                "url": url,
                "parameter": "Form Action: " + action,
                "method": "POST",
                "payload": "N/A (Missing Token)",
                "description": "Le formulaire ne contient pas de protection Anti-CSRF visible. Un attaquant pourrait tromper un utilisateur pour exécuter des actions non-désirées sur le site.",
                "remediation": "Implémentez et validez un jeton CSRF, unique par session et inclus dans chaque requête POST."
            })
            
        return results

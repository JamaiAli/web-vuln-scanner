from mon_scanner.utils.logger import logger
import urllib.parse
from bs4 import BeautifulSoup

class Authenticator:
    def __init__(self, requester):
        self.requester = requester
        
    def login(self, login_url, username, password, username_field="user_login", password_field="user_password"):
        """
        Effectue une requête GET pour extraire les tokens de sécurité cachés (CSRF),
        puis soumet le POST pour s'authentifier.
        Le cookie de session sera stocké dans l'objet Session du Requester.
        """
        logger.info(f"Tentative de connexion sur {login_url} avec l'utilisateur '{username}'...")
        
        # 1. Faire un GET pour récupérer la page et ses tokens (ex: user_token sur zero.webapp)
        res_get = self.requester.get(login_url)
        if not res_get:
            logger.error("[FAIL] Impossible de joindre la page de login.")
            return False

        # Extraire tous les inputs cachés ou existants du formulaire de login
        soup = BeautifulSoup(res_get.text, 'html.parser')
        form = soup.find('form')
        
        login_data = {}
        if form:
            for inp in form.find_all('input'):
                name = inp.get('name')
                if name:
                    login_data[name] = inp.get('value', '')
        
        # 2. Forcer les valeurs d'identification
        login_data[username_field] = username
        login_data[password_field] = password
        
        # 3. Soumettre la requête POST d'authentification complète
        response = self.requester.post(login_url, data=login_data)
        
        if response and response.status_code == 200:
            content_lower = response.text.lower()
            # Sur zero.webappsecurity, en cas d'erreur de connexion, le texte contient explicitement "Wrong username or password"
            if "wrong" in content_lower or "login error" in content_lower or "incorrect" in content_lower:
                logger.error("[FAIL] Identifiants incorrects ou échec de l'authentification (message d'erreur détecté).")
                return False
                
            # Sur ZeroBank, une connexion valide renvoie ironiquement un contenu de type "Zero Bank" basique (index) sans formulaire
            if "zero - log in" not in content_lower or "transfer funds" in content_lower or "account summary" in content_lower:
                logger.info("[SUCCESS] Authentification réussie ! La session est maintenant active.")
                return True
                
            logger.info("[SUCCESS] Authentification jugée réussie (pas de message d'erreur et jeton soumis).")
            return True
        else:
            logger.error(f"[FAIL] Erreur serveur lors de la soumission du login (Status: {response.status_code if response else 'None'}).")
            return False

import argparse
import sys
import yaml
import urllib.parse
from urllib.parse import urlparse

# Import des composants locaux
from mon_scanner.core.requester import Requester
from mon_scanner.core.crawler import Crawler
from mon_scanner.core.extractor import Extractor
from mon_scanner.core.auth import Authenticator
from mon_scanner.modules.sqli import SQLiScanner
from mon_scanner.modules.xss import XSSScanner
from mon_scanner.modules.csrf import CSRFScanner
from mon_scanner.reporting.generator import ReportGenerator
from mon_scanner.utils.logger import logger

def print_banner():
    banner = """
    ==================================================
           PROFESSIONAL WEB VULNERABILITY SCANNER      
    ==================================================
        Crawl • Extract • Scan (SQLi, XSS, CSRF)      
    ==================================================
    """
    print(banner)

def load_config(config_path):
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.warning(f"Impossible de charger la configuration locale: {e}. Utilisation des valeurs par défaut.")
        return {}

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Scanner de vulnérabilités Web")
    parser.add_argument("-u", "--url", help="URL cible à scanner (ex: http://example.com)", required=True)
    parser.add_argument("-d", "--depth", type=int, help="Profondeur du crawl (défaut: 3)", default=3)
    parser.add_argument("-c", "--config", help="Chemin vers le fichier de config", default="mon_scanner/config/config.yaml")
    
    # Nouveaux arguments pour l'authentification
    parser.add_argument("--login-url", help="URL de la page de connexion")
    parser.add_argument("--username", help="Nom d'utilisateur pour la connexion")
    parser.add_argument("--password", help="Mot de passe pour la connexion")
    
    args = parser.parse_args()

    target_url = args.url
    parsed_url = urlparse(target_url)
    if not parsed_url.scheme:
        target_url = "http://" + target_url

    config = load_config(args.config)
    modules_config = config.get("modules", {"sqli": True, "xss": True, "csrf": True})

    logger.info(f"Initialisation du scanner sur la cible: {target_url}")

    # 1. Initialiser le cœur (la session démarre ici)
    requester = Requester(config_path=args.config)
    
    # 1.5 Authentification optionnelle
    if args.login_url and args.username and args.password:
        auth_module = Authenticator(requester)
        login_absolute_url = args.login_url
        if not urlparse(args.login_url).scheme:
            login_absolute_url = urllib.parse.urljoin(target_url, args.login_url)
            
        success = auth_module.login(login_absolute_url, args.username, args.password)
        if not success:
            logger.critical("Arrêt du scanner car l'authentification a échoué.")
            sys.exit(1)
            
        # Si connecté, vérifier s'il faut forcer un crawl depuis l'index connecté pour amorcer la découverte
        # (souvent nécessaire car la redirection du POST de login n'est pas suivie par le Crawler)
        base_index = urllib.parse.urljoin(target_url, "/index.html")
        logger.info(f"Pré-amorçage du crawler avec : {base_index}")
        # On va l'ajouter au Crawler via une méthode dédiée ou en le passant

    crawler = Crawler(requester, target_url, max_depth=args.depth)
    if args.login_url and args.username and args.password:
         crawler.to_visit.append((urllib.parse.urljoin(target_url, "/index.html"), 0))
         crawler.to_visit.append((urllib.parse.urljoin(target_url, "/bank/account-summary.html"), 0))
         crawler.to_visit.append((urllib.parse.urljoin(target_url, "/bank/transfer-funds.html"), 0))
         crawler.to_visit.append((urllib.parse.urljoin(target_url, "/bank/pay-bills.html"), 0))
    
    # 2. Phase de Reconnaissance (Crawling) connecté
    logger.info("=== Phase 1: Reconnaissance (Crawling) ===")
    discovered_urls = crawler.crawl()
    logger.info(f"Crawl terminé. {len(discovered_urls)} URLs uniques découvertes.")
    
    # Initialisation des Modules
    sqli_scanner = SQLiScanner(requester)
    xss_scanner = XSSScanner(requester)
    csrf_scanner = CSRFScanner()
    
    all_vulnerabilities = []

    # 3. Phase d'Extraction et Scan pour chaque URL
    logger.info("=== Phase 2: Analyse et Scan ===")
    for url in discovered_urls:
        logger.info(f"Analyse en cours: {url}")
        response = requester.get(url)
        
        if not response or 'text/html' not in response.headers.get('Content-Type', ''):
            continue

        extractor = Extractor(response.text, url)
        forms = extractor.get_forms()
        # On pourrait également extraire les paramètres d'URL directement de la page si besoin
        
        # Scan URL Parameters (GET)
        if modules_config.get("sqli"):
            all_vulnerabilities.extend(sqli_scanner.scan_url(url))
        if modules_config.get("xss"):
            all_vulnerabilities.extend(xss_scanner.scan_url(url))

        # Scan Formulaires (POST/GET)
        for form in forms:
            if modules_config.get("sqli"):
                all_vulnerabilities.extend(sqli_scanner.scan_form(url, form))
            if modules_config.get("xss"):
                all_vulnerabilities.extend(xss_scanner.scan_form(url, form))
            if modules_config.get("csrf"):
                all_vulnerabilities.extend(csrf_scanner.scan_form(url, form))

    # Phase XSS Stored : Validation globale en repassant sur les pages importantes
    if modules_config.get("xss"):
        logger.info("--- Vérification finale du XSS Stocké ---")
        stored_results = xss_scanner.verify_stored_xss(discovered_urls)
        all_vulnerabilities.extend(stored_results)

    # 4. Phase de Reporting
    logger.info("=== Phase 3: Génération du Rapport ===")
    if not all_vulnerabilities:
        logger.info("Félicitations, aucune vulnérabilité grave détectée !")
    else:
        logger.warning(f"{len(all_vulnerabilities)} vulnérabilités potentielles ont été trouvées.")
    
    generator = ReportGenerator(config_path=args.config)
    domain_name = urlparse(target_url).netloc.replace(':', '_')
    report_html_path = f"reports/report_{domain_name}.html"
    report_json_path = f"reports/report_{domain_name}.json"
    
    generator.generate_html(target_url, all_vulnerabilities, report_html_path)
    if config.get("reporting", {}).get("format", "") == "json":
        generator.generate_json(target_url, all_vulnerabilities, report_json_path)
        
    logger.info("Scan terminé avec succès. Consultez les rapports dans le dossier 'reports'.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Scan interrompu par l'utilisateur.")
        sys.exit(0)

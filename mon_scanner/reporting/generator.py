from jinja2 import Environment, FileSystemLoader
import json
import os
from datetime import datetime
from mon_scanner.utils.logger import logger

class ReportGenerator:
    def __init__(self, config_path="mon_scanner/config/config.yaml"):
        # Initialisation du moteur de template
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        
        # Sévérités par ordre pour trier les vulnérabilités
        self.severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}

    def generate_html(self, target_url, vulnerabilities, output_file="report.html"):
        """Génère un rapport HTML stylisé en utilisant Jinja2"""
        try:
            template = self.env.get_template('report.html')
            
            # Trier les vulnérabilités par sévérité
            sorted_vulnerabilities = sorted(
                vulnerabilities, 
                key=lambda x: self.severity_order.get(x.get("severity", "Info"), 99)
            )

            # Statistiques pour le résumé
            stats = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for vuln in sorted_vulnerabilities:
                sev = vuln.get("severity", "Info")
                if sev in stats:
                    stats[sev] += 1
                else:
                    stats[sev] = 1

            html_out = template.render(
                target_url=target_url,
                scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                vulnerabilities=sorted_vulnerabilities,
                stats=stats,
                total_vulns=len(sorted_vulnerabilities)
            )
            
            # Créer le dossier s'il n'existe pas
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_out)
                
            logger.info(f"Rapport HTML généré avec succès: {output_file}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport HTML: {e}")

    def generate_json(self, target_url, vulnerabilities, output_file="report.json"):
        """Génère un rapport JSON pour l'automatisation (CI/CD)"""
        try:
            data = {
                "target_url": target_url,
                "scan_date": datetime.now().isoformat(),
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities": vulnerabilities
            }
            
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
                
            logger.info(f"Rapport JSON généré avec succès: {output_file}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport JSON: {e}")

from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from mon_scanner.utils.helpers import normalize_url

class Extractor:
    def __init__(self, html, url):
        self.soup = BeautifulSoup(html, 'html.parser')
        self.url = url
        
    def get_forms(self):
        """
        Extrait tous les formulaires HTML de la page avec leurs inputs.
        Retourne une liste de dictionnaires représentant chaque formulaire.
        """
        forms = []
        for form_tag in self.soup.find_all('form'):
            form_data = {
                'action': form_tag.get('action', ''),
                'method': form_tag.get('method', 'get').lower(),
                'inputs': []
            }
            
            # Formater l'action pour qu'elle soit absolue
            if form_data['action']:
                form_data['action'] = normalize_url(self.url, form_data['action'])
            else:
                form_data['action'] = self.url
                
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                input_value = input_tag.get('value', '')
                
                if input_name:
                    form_data['inputs'].append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_value
                    })
            forms.append(form_data)
        return forms

    def get_url_parameters(self):
        """
        Extrait les paramètres d'URL (GET params) qui seront de bons vecteurs d'attaque.
        Retourne un dictionnaire des paramètres.
        """
        parsed_url = urlparse(self.url)
        return parse_qs(parsed_url.query)

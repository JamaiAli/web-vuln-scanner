from bs4 import BeautifulSoup
from mon_scanner.utils.logger import logger
from mon_scanner.utils.helpers import normalize_url, is_same_domain

class Crawler:
    def __init__(self, requester, target_url, max_depth=3):
        self.requester = requester
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited = set()
        self.to_visit = [(target_url, 0)] # File d'attente contenant des tuples (URL, profondeur)
        
    def extract_links(self, html, current_url):
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            # Ignorer les ancres, emails, javascript
            if href.startswith(('#', 'mailto:', 'javascript:')):
                continue
            
            absolute_url = normalize_url(current_url, href)
            # Ne garder que les liens du même domaine
            if is_same_domain(self.target_url, absolute_url):
                # Nettoyer l'URL (enlever les fragments #)
                clean_url = absolute_url.split('#')[0]
                links.add(clean_url)
        return links

    def crawl(self):
        logger.info(f"Démarrage du crawl sur: {self.target_url} (Profondeur max: {self.max_depth})")
        
        while self.to_visit:
            current_url, depth = self.to_visit.pop(0)
            
            if current_url in self.visited or depth > self.max_depth:
                continue
                
            logger.info(f"Crawling: {current_url} (Profondeur {depth})")
            self.visited.add(current_url)
            
            response = self.requester.get(current_url)
            if not response or 'text/html' not in response.headers.get('Content-Type', ''):
                continue
                
            links = self.extract_links(response.text, current_url)
            for link in links:
                if link not in self.visited:
                    self.to_visit.append((link, depth + 1))
                    
        return list(self.visited)

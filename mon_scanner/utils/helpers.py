import urllib.parse

def is_same_domain(url1, url2):
    """
    Vérifie si deux URLs appartiennent au même domaine.
    Utile pour éviter que le crawler ne sorte du périmètre.
    """
    try:
        domain1 = urllib.parse.urlparse(url1).netloc
        domain2 = urllib.parse.urlparse(url2).netloc
        return domain1 == domain2
    except Exception:
        return False

def normalize_url(base_url, link):
    """
    Transforme un lien relatif en lien absolu basé sur l'URL de base.
    """
    return urllib.parse.urljoin(base_url, link)

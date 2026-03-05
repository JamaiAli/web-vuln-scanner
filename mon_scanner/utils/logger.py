import logging
import sys

# Configuration des couleurs pour le terminal
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[94m',    # Bleu
        'INFO': '\033[92m',     # Vert
        'WARNING': '\033[93m',  # Jaune
        'ERROR': '\033[91m',    # Rouge
        'CRITICAL': '\033[1;91m', # Rouge gras
        'RESET': '\033[0m'      # Réinitialiser
    }

    def format(self, record):
        log_message = super().format(record)
        return f"{self.COLORS.get(record.levelname, self.COLORS['RESET'])}{log_message}{self.COLORS['RESET']}"

def setup_logger(name="WebVulnScanner", level=logging.INFO):
    """
    Configure et retourne un logger professionnel avec des couleurs (si supporté).
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Éviter d'ajouter plusieurs handlers si la fonction est appelée plusieurs fois
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        
        # Format du log: [DATE] [NIVEAU] Message
        formatter = ColoredFormatter('%(asctime)s - [%(levelname)s] - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        console_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)

    return logger

# Logger global par défaut
logger = setup_logger()

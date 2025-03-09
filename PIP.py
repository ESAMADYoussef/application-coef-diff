from flask import Flask, render_template, request, flash
import os
import secrets
import logging
from diffusion_module import calculate_diffusion_coefficient

# Fonctions de sécurité intégrées
def setup_security():
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    logging.basicConfig(
        filename='logs/security.log',
        level=logging.WARNING,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def is_safe_path(path, base_dir):
    resolved_path = os.path.realpath(path)
    base_dir = os.path.realpath(base_dir)
    
    return os.path.commonpath([resolved_path, base_dir]) == base_dir

def check_root_privileges():
    if os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() == 0:
        return "AVERTISSEMENT: L'application ne doit pas être exécutée en tant que root!"
    return None

def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    
    return response

def log_suspicious_activity(reason):
    client_ip = request.remote_addr
    path = request.path
    method = request.method
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    logging.warning(
        f"Activité suspecte - IP: {client_ip}, Chemin: {path}, "
        f"Méthode: {method}, Agent: {user_agent}, Raison: {reason}"
    )

# Vérifier les privilèges root
root_warning = check_root_privileges()
if root_warning:
    print(root_warning)

# Initialisation de l'application Flask
app = Flask(_name_)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Configuration de la sécurité
setup_security()

# Configuration du journal d'erreurs
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@app.after_request
def after_request(response):
    return add_security_headers(response)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/calculator', methods=['GET', 'POST'])
def calculator():
    default_values = {
        'x_A': 0.25,
        'D_AB0': 2.1e-5,
        'D_BA0': 2.67e-5,
        'ra': 1.4311,
        'rb': 0.92,
        'q_A': 1.432,
        'q_B': 1.4,
        'T': 313.13,
        'a_AB': -10.7575,
        'a_BA': 194.5302,
        'D_exp': 1.33e-5
    }

    if request.method == 'POST':
        try:
            x_A = float(request.form.get('x_A', default_values['x_A']))
            D_AB0 = float(request.form.get('D_AB0', default_values['D_AB0']))
            D_BA0 = float(request.form.get('D_BA0', default_values['D_BA0']))
            ra = float(request.form.get('ra', default_values['ra']))
            rb = float(request.form.get('rb', default_values['rb']))
            q_A = float(request.form.get('q_A', default_values['q_A']))
            q_B = float(request.form.get('q_B', default_values['q_B']))
            T = float(request.form.get('T', default_values['T']))
            a_AB = float(request.form.get('a_AB', default_values['a_AB']))
            a_BA = float(request.form.get('a_BA', default_values['a_BA']))
            D_exp = float(request.form.get('D_exp', default_values['D_exp']))

            if not 0 <= x_A <= 1:
                flash("La fraction molaire doit être comprise entre 0 et 1", "error")
                return render_template('calculator.html', values=default_values)

            if D_AB0 <= 0 or D_BA0 <= 0 or ra <= 0 or rb <= 0 or T <= 0:
                flash("Les valeurs physiques doivent être positives", "error")
                return render_template('calculator.html', values=default_values)

            D_AB, error = calculate_diffusion_coefficient(
                x_A, D_AB0, D_BA0, q_A, q_B, T, a_AB, a_BA, ra, rb, D_exp
            )

            results = {
                'x_A': x_A,
                'x_B': 1 - x_A,
                'D_AB': D_AB,
                'error': error,
                'D_exp': D_exp
            }

            return render_template('result.html', results=results)

        except ValueError as e:
            flash(f"Erreur de format des données: {str(e)}", "error")
            return render_template('calculator.html', values=default_values)

        except Exception as e:
            flash("Une erreur s'est produite lors du calcul", "error")
            logging.error(f"Erreur: {str(e)}")
            return render_template('calculator.html', values=default_values)

    return render_template('calculator.html', values=default_values)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('base.html', content="Page non trouvée"), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"Erreur 500: {str(e)}")
    return render_template('base.html', content="Erreur interne du serveur"), 500

if _name_ == '_main_':
    app.run(debug=False, host='127.0.0.1', port=5000)
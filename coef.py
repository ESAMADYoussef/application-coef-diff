from flask import Flask, render_template, render_template_string, request, jsonify
import numpy as np
import webview  # Importez PyWebView

app = Flask(__name__)

# Constantes pour le calcul de D_AB
D_AB_0_A = 2.1e-5
D_AB_0_B = 2.67e-5
phi_A = 0.279
phi_B = 0.721
lambda_A = 1.127
lambda_B = 0.973
q_A = 1.432
q_B = 1.4
theta_BA = 0.612
theta_BB = 0.739
theta_AB = 0.261
theta_AA = 0.388
tau_BA = 0.5373
tau_AB = 1.035
D_AB_reference = 1.33e-5  # Valeur de référence pour D_AB

# Page d'accueil
@app.route('/')
def home():
    return '''
    <h1>Bonjour, voici le calcul de coefficient de diffusion</h1>
    <p>Cliquez sur le bouton ci-dessous pour accéder au calculateur.</p>
    <a href="/coeff-diffusion"><button>Accéder au calculateur</button></a>
    '''

# Route pour le calculateur de coefficient de diffusion
@app.route('/coeff-diffusion', methods=['GET', 'POST'])
def coeff_diffusion():
    if request.method == 'POST':
        try:
            # Récupérer les valeurs de xA et xB
            xA = float(request.form['xA'])
            xB = float(request.form['xB'])

            # Vérifier que xA + xB = 1
            if abs(xA + xB - 1) > 1e-6:
                return '''
                <h1>Erreur</h1>
                <p>La somme de x<sub>A</sub> et x<sub>B</sub> doit être égale à 1.</p>
                <a href="/coeff-diffusion">Retour</a>
                '''

            # Calcul des termes de la formule
            term1 = xB * np.log(D_AB_0_A) + xA * np.log(D_AB_0_B)
            term2 = 2 * (xA * np.log(xA / phi_A) + xB * np.log(xB / phi_B))
            term3 = 2 * xA * xB * ((phi_A / xA) * (1 - (lambda_A / lambda_B)) + (phi_B / xB) * (1 - (lambda_B / lambda_A)))
            term4 = (xB * q_A) * ((1 - theta_BA ** 2) * np.log(tau_BA) + (1 - theta_BB ** 2) * tau_AB * np.log(tau_AB))
            term5 = (xA * q_B) * ((1 - theta_AB ** 2) * np.log(tau_AB) + (1 - theta_AA ** 2) * tau_BA * np.log(tau_BA))

            # Calcul de D_AB
            ln_D_AB = term1 + term2 + term3 + term4 + term5
            D_AB_calcule = np.exp(ln_D_AB)

            # Calcul de l'erreur
            erreur = abs((D_AB_calcule - D_AB_reference) / D_AB_reference) * 100

            # Affichage des résultats
            return f"""
            <h1>Résultat du calcul</h1>
            <p>D<sub>AB</sub> calculé = {D_AB_calcule:.6e} cm²/s</p>
            <p>Erreur = {erreur:.2f} %</p>
            <a href="/coeff-diffusion">Nouveau calcul</a>
            <br>
            <a href="/">Retour à l'accueil</a>
            """

        except ValueError:
            return '''
            <h1>Erreur</h1>
            <p>Veuillez saisir des valeurs numériques valides pour x<sub>A</sub> et x<sub>B</sub>.</p>
            <a href="/coeff-diffusion">Retour</a>
            '''

        except Exception as e:
            return f'''
            <h1>Erreur</h1>
            <p>Une erreur inattendue s'est produite : {str(e)}</p>
            <a href="/coeff-diffusion">Retour</a>
            '''

    # Affichage du formulaire (méthode GET)
    return '''
    <h1>Calculateur de coefficient de diffusion D<sub>AB</sub></h1>
    <form method="post">
        x<sub>A</sub> : <input type="number" step="0.01" name="xA" value="0.5" required><br>
        x<sub>B</sub> : <input type="number" step="0.01" name="xB" value="0.5" required><br>
        <input type="submit" value="Calculer">
    </form>
    <br>
    <a href="/">Retour à l'accueil</a>
    '''

# Gestion de l'erreur 404 (page non trouvée)
@app.errorhandler(404)
def page_not_found(error):
    return jsonify({"error": "Cette page n'existe pas !"}), 404

# Gestion d'autres erreurs (ex: erreur serveur 500)
@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Erreur interne du serveur"}), 500

# Démarrer l'application Flask dans une fenêtre PyWebView
if __name__ == '__main__':
    # Démarrer Flask dans un thread séparé
    import threading
    threading.Thread(target=app.run, daemon=True).start()

    # Créer une fenêtre PyWebView
    webview.create_window(
        "Calculateur de D_AB",  # Titre de la fenêtre
        "http://localhost:5000",  # URL de l'application Flask
        width=800,  # Largeur de la fenêtre
        height=600   # Hauteur de la fenêtre
    )
    webview.start()  # Démarrer la boucle principale de PyWebView
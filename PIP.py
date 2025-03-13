from flask import Flask, request, redirect, url_for
import math
import webview
import threading

app = Flask(__name__)

# Fonction pour calculer le coefficient de diffusion et l'erreur relative
def calcul_diffusion(x_A, D_AB0, D_BA0, q_A, q_B, r_A, r_B, a_AB, a_BA, T, D_exp):
    try:
        # Calcul de x_B
        x_B = 1 - x_A

        # Calcul de y_A et y_B
        y_A = r_A ** (1 / 3)
        y_B = r_B ** (1 / 3)

        # Calcul de phi (fraction de surface)
        phi_A = (x_A * y_A) / (x_A * y_A + (1 - x_A) * y_B)
        phi_B = ((1 - x_A) * y_B) / (x_A * y_A + (1 - x_A) * y_B)

        # Calcul de theta (paramètre de volume)
        theta_A = (x_A * q_A) / (x_A * q_A + x_B * q_B)
        theta_B = (x_B * q_B) / (x_A * q_A + x_B * q_B)

        # Calcul de tau (facteurs d'interaction)
        tau_AB = math.exp(-a_AB / T)
        tau_BA = math.exp(-a_BA / T)

        # Calcul des thêta (θ_AA, θ_BB, θ_AB, θ_BA)
        theta_AA = (theta_A * 1) / (theta_A * 1 + theta_B * tau_BA)
        theta_BB = (theta_B * 1) / (theta_A * tau_AB + theta_B * 1)
        theta_AB = (theta_A * tau_AB) / (theta_A * tau_AB + theta_B * tau_BA)
        theta_BA = (theta_B * tau_BA) / (theta_A * 1 + theta_B * tau_BA)

        # Equation pour calculer le logarithme du coefficient de diffusion
        ln_D_AB = (
            (x_A * math.log(D_BA0) + (1 - x_A) * math.log(D_AB0)) +
            2 * (x_A * math.log(x_A / phi_A) + (1 - x_A) * math.log((1 - x_A) / phi_B)) +
            2 * x_A * (1 - x_A) * (
                (phi_A / x_A) * (1 - (y_A / y_B)) + (phi_B / (1 - x_A)) * (1 - (y_B / y_A))
            ) +
            x_A * q_B * ((1 - theta_AB**2) * math.log(tau_AB) + (1 - theta_AA**2) * tau_BA * math.log(tau_BA)) +
            (1 - x_A) * q_A * ((1 - theta_BA**2) * math.log(tau_BA) + (1 - theta_BB**2) * tau_AB * math.log(tau_AB))
        )

        # Calcul du coefficient de diffusion final
        D_AB = math.exp(ln_D_AB)

        # Calcul de l'erreur relative entre la valeur calculée et expérimentale
        error = abs((D_AB - D_exp) / D_exp) * 100

        return D_AB, error
    except ValueError:
        return None, None

# Page d'accueil
@app.route('/')
def home():
    return """
        <html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f4f4f9;
                    }

                    h1 {
                        text-align: center;
                        color: #333;
                    }

                    p {
                        font-size: 16px;
                        color: #666;
                    }

                    button {
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 20px;
                        border: none;
                        cursor: pointer;
                        font-size: 16px;
                    }

                    button:hover {
                        background-color: #45a049;
                    }

                    a {
                        display: block;
                        text-align: center;
                        margin-top: 20px;
                        text-decoration: none;
                        color: #007BFF;
                    }

                    a:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <h1>Bonjour👋</h1>
                <center><p>Bienvenue dans le calculateur du coefficient de diffusion.</p></center>
                <a href='/page2'><button>Suivant</button></a>
            </body>
        </html>
    """

# Page formulaire
@app.route('/page2', methods=['GET'])
def page2():
    return """
        <html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f4f4f9;
                    }

                    h1 {
                        text-align: center;
                        color: #333;
                    }

                    form {
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: white;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    }

                    input[type="text"] {
                        width: 100%;
                        padding: 8px;
                        margin: 5px 0 15px 0;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                    }

                    button {
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 20px;
                        border: none;
                        cursor: pointer;
                        font-size: 16px;
                    }

                    button:hover {
                        background-color: #45a049;
                    }

                    a {
                        display: block;
                        text-align: center;
                        margin-top: 20px;
                        text-decoration: none;
                        color: #007BFF;
                    }

                    a:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <h1>Input the values</h1>
                <form action='/page3' method='post'>
                    Mole fraction of A (x_A): <input type='text' name='x_A' value='0.25' required><br><br>
                    Base diffusion coefficient D_AB^0: <input type='text' name='D_AB0' value='2.1e-5' required><br><br>
                    Base diffusion coefficient D_BA^0: <input type='text' name='D_BA0' value='2.67e-5' required><br><br>
                    Volume parameter q_A: <input type='text' name='q_A' value='1.432' required><br><br>
                    Volume parameter q_B: <input type='text' name='q_B' value='1.4' required><br><br>
                    Parameter r_A: <input type='text' name='r_A' value='1.4311' required><br><br>
                    Parameter r_B: <input type='text' name='r_B' value='0.92' required><br><br>
                    Interaction parameter a_AB: <input type='text' name='a_AB' value='-10.7575' required><br><br>
                    Interaction parameter a_BA: <input type='text' name='a_BA' value='194.5302' required><br><br>
                    Temperature T (K): <input type='text' name='T' value='313.13' required><br><br>
                    Experimental diffusion coefficient (cm²/s): <input type='text' name='D_exp' value='1.33e-5' required><br><br>
                    <button type='submit'>Calculate</button>
                </form>
            </body>
        </html>
    """

# Page résultat avec gestion des erreurs
@app.route('/page3', methods=['POST'])
def page3():
    try:
        x_A = float(request.form['x_A'].replace(',', '.'))
        D_AB0 = float(request.form['D_AB0'])
        D_BA0 = float(request.form['D_BA0'])
        q_A = float(request.form['q_A'])
        q_B = float(request.form['q_B'])
        r_A = float(request.form['r_A'])
        r_B = float(request.form['r_B'])
        a_AB = float(request.form['a_AB'])
        a_BA = float(request.form['a_BA'])
        T = float(request.form['T'])
        D_exp = float(request.form['D_exp'])

        D_AB, error = calcul_diffusion(x_A, D_AB0, D_BA0, q_A, q_B, r_A, r_B, a_AB, a_BA, T, D_exp)
        
        if D_AB is None:
            raise ValueError("Invalid input values.")
        
        return f"""
            <html>
                <head>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            margin: 0;
                            padding: 0;
                            background-color: #f4f4f9;
                        }}

                        h1 {{
                            text-align: center;
                            color: #333;
                        }}

                        p {{
                            font-size: 16px;
                            color: #666;
                        }}

                        button {{
                            background-color: #4CAF50;
                            color: white;
                            padding: 10px 20px;
                            border: none;
                            cursor: pointer;
                            font-size: 16px;
                        }}

                        button:hover {{
                            background-color: #45a049;
                        }}

                        a {{
                            display: block;
                            text-align: center;
                            margin-top: 20px;
                            text-decoration: none;
                            color: #007BFF;
                        }}

                        a:hover {{
                            text-decoration: underline;
                        }}
                    </style>
                </head>
                <body>
                    <h1>Here is the result</h1>
                    <p>The diffusion coefficient D_AB is: {D_AB:.4e} cm²/s</p>
                    <p>The relative error compared to the experimental value is: {error:.2f}%</p>
                    <a href="/">Return to home</a>
                </body>
            </html>
        """
    except (ValueError, KeyError) as e:
        return redirect(url_for('home'))

# Gestion des erreurs pour les routes inexistantes
@app.errorhandler(404)
def page_not_found(e):
    return redirect(url_for('home'))

# Fonction pour lancer Flask et pywebview simultanément
def start_flask():
    app.run(debug=True, use_reloader=False)

def start_webview():
    webview.create_window("Diffusion Coefficient Calculator", "http://127.0.0.1:5000/")
    webview.start()

if __name__ == '__main__':
    threading.Thread(target=start_flask).start()
    start_webview()

import numpy as np
import pickle
import warnings

warnings.filterwarnings('ignore')

from flask import Flask, request, render_template
from feature import FeatureExtraction

with open("pickle/model.pkl", "rb") as f:
    gbc = pickle.load(f)

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

        return render_template('index.html', xx=round(y_pro_non_phishing, 2), url=url)

    return render_template("index.html", xx=-1)


if __name__ == "__main__":
    app.run(debug=True)

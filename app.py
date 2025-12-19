from flask import Flask,request,jsonify
from src.ai_models import get_classifier,Action,Classifier

app = Flask(__name__)

model = get_classifier(Classifier.KNN,Action.PREDICT)

@app.route("/")
def hello_world():
    return "linga"

@app.route("/scan",methods=["POST"])
def scan():
    lista = [request.json["url"]]
    result = model.predict(lista)
    return jsonify(result[0]), 200
"""意図的に脆弱なサンプル (E2E テスト用). 実運用には使わないこと."""

import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    filename = request.form["filename"]
    # OS コマンドインジェクション: ユーザー入力がシェルに渡る
    subprocess.run("convert " + filename + " /tmp/out.png", shell=True)
    return "ok"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # SQL インジェクション: 文字列連結でクエリを組み立てている
    conn.execute("SELECT * FROM users WHERE id = '" + str(user_id) + "'")
    return "ok"


@app.route("/render")
def render():
    template = request.args.get("t", "")
    # 安全でない eval
    return str(eval(template))  # noqa: S307


def run() -> None:
    os.system("echo " + os.environ.get("MSG", ""))
    app.run(host="0.0.0.0", debug=True)

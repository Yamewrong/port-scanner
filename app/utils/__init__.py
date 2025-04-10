from flask import Flask
from app.routes.main import main_bp
from app.routes.analysis import analysis_bp
from app.routes.custom_scan import custom_scan_bp
from app.routes.docker import docker_bp
import os

# ✅ static 경로 명시!
app = Flask(__name__, static_folder=os.path.abspath("static"))

# Blueprint 등록
app.register_blueprint(main_bp)
app.register_blueprint(analysis_bp)
app.register_blueprint(custom_scan_bp)
app.register_blueprint(docker_bp)

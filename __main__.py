from app import create_app
from . import auth

app = application = create_app()

app.register_blueprint(auth.bp)


if __name__ == "__main__":
    app.run(debug=True)
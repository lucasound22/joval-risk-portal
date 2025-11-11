FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir streamlit pandas plotly pyyaml reportlab bcrypt
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]

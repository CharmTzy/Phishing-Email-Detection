#!/bin/bash
# Start Flask backend in the background
gunicorn server:app --bind 0.0.0.0:5000 &
# Start Streamlit frontend
streamlit run app.py --server.port 10000 --server.address 0.0.0.0
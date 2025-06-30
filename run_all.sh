#!/bin/bash
# Start backend in background
python3 -m uvicorn backend.main:app --reload &
BACKEND_PID=$!
# Wait a few seconds to ensure backend is up
sleep 3
# Start frontend (this will block)
python3 -m streamlit run frontend/app.py
# When frontend exits, kill backend
kill $BACKEND_PID 
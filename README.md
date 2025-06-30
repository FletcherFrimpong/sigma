# Detection Rule Canvas

A professional, international-standard platform for generating detection rules for multiple security platforms using AI. Inspired by [detections.ai](https://detections.ai/landing).

## Features
- Generate detection rules for Sigma, Azure Sentinel (KQL), CrowdStrike (Falcon), SentinelOne (SQL), Splunk (SPL)
- AI-powered rule generation (OpenAI integration)
- Modern, accessible web UI (Streamlit)
- Secure secret management (.env)
- Professional API with FastAPI (OpenAPI docs at `/docs`)
- Download and copy rules easily
- Internationalization-ready (English, easy to translate)
- Open source (MIT License)

## Project Structure
```
sigma/
  backend/
    main.py
    requirements.txt
  frontend/
    app.py
    requirements.txt
  .env.example
  .gitignore
  README.md
  LICENSE
```

## Quick Start

1. **Install dependencies:**
   ```
   pip install -r backend/requirements.txt
   pip install -r frontend/requirements.txt
   ```
2. **Set your OpenAI API key:**
   - Copy `backend/.env.example` to `backend/.env` and fill in your key, or set `OPENAI_API_KEY` in your environment.
3. **Run the backend:**
   ```
   uvicorn backend.main:app --reload
   ```
4. **Run the frontend:**
   ```
   streamlit run frontend/app.py
   ```
5. **Open your browser:**
   Go to [http://localhost:8501](http://localhost:8501)

## Usage
- Paste or upload threat intelligence
- Select platforms
- Click "Generate Detection Rules"
- Download or copy generated rules

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License
MIT License. See [LICENSE](LICENSE).

## Security
- Never commit secrets. Use `.env` for local development.
- Validate and sanitize all user input.
- Use HTTPS for API calls in production.

## Internationalization
- All UI and code comments are in English.
- Structure UI text for easy translation.

## Contact
For questions or support, open an issue or contact the maintainers. 
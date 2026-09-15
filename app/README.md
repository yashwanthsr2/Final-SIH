# `app/` Directory Architecture Notice

> [!NOTE]
> **Canonical Production Code is in [`backend/app/`](../backend/app/)**

### Historical Context
This `app/` directory contains the initial rapid-prototyping sprint codebase for the CyberSentinel platform. 

During architectural modernization for team parallel development, clean testing, and production scaling:
- All monolithic routes in `app/main.py` were decomposed into modular FastAPI routers under [`backend/app/api/`](../backend/app/api/).
- Core components were refactored into [`backend/app/core/`](../backend/app/core/), [`backend/app/detectors/`](../backend/app/detectors/), [`backend/app/services/`](../backend/app/services/), and [`backend/app/schemas/`](../backend/app/schemas/).
- Modern single-page application UI assets are maintained in [`frontend/public/`](../frontend/public/).

### Development Guideline
- **For all new features, bugfixes, and API enhancements**: Make changes in [`backend/app/`](../backend/app/).
- Files in this directory (`app/`) are retained for backwards compatibility with earlier notebooks and standalone scripts.

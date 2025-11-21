<div align="center">
<img src="./icon.png">

**Protect yourself online with real-time URL security analysis**

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](https://choosealicense.com/licenses/mit/)
[![Node Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen?style=flat-square&logo=node.js)](https://nodejs.org/)
[![Express.js](https://img.shields.io/badge/Express.js-4.18.2-black?style=flat-square&logo=express)](https://expressjs.com/)
[![Puppeteer](https://img.shields.io/badge/Puppeteer-21.11.0-40B5A4?style=flat-square&logo=puppeteer)](https://pptr.dev/)

[Features](#features) • [Demo](#demo) • [Deployment](#deployment) • [API](#api-endpoints)

</div>

---

## Features

- **Malware Detection** - Identify malicious websites
- **Phishing Protection** - Detect deceptive sites
- **Threat Analysis** - Real-time security checks powered by Google Safe Browsing API
- **Website Screenshots** - Capture any website in real-time
- **URL Expansion** - Expand shortened links and track redirections
- **Redirection Detection** - Track and display URL redirects
- **Proxified Access** - Anonymous browsing through proxy

---

## Demo

Check out the live demo: **[https://websafe-6qzg.onrender.com](https://websafe-6qzg.onrender.com)**

### Screenshots

<div align="center">

| Safe URL Detection | Malicious URL Warning |
|:------------------:|:---------------------:|
| ![Safe URL](./safe.jpg) | ![Malicious URL](./malicious.jpg) |

</div>

---

## Quick Start

### Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** (v20.0.0 or higher) - [Download](https://nodejs.org/)
- **npm** or **yarn** package manager
- **Google Safe Browsing API Key** - [Get API Key](https://developers.google.com/safe-browsing/v4/get-started)

---

## Local Installation

### Clone the Repository

```bash
git clone https://github.com/prateek-chaubey/WebSafe.git
cd WebSafe
```

### Install Dependencies

```bash
npm install
```

### Configure Environment Variables

Create a `.env` file in the root directory:

```env
SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key_here
PORT=3000
```

> [!NOTE]
> Visit [Google Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started) to obtain your free API key.

### Run the Application

**Development Mode (with auto-reload):**
```bash
npm run dev
```

**Production Mode:**
```bash
npm start
```

### Access the Application

Open your browser and navigate to:
```
http://localhost:3000
```

---

## Deployment

### Deploy to Render.com

<div align="center">

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com)

</div>

#### Step-by-Step Guide

**1. Create a Render Account**
- Visit [Render.com](https://render.com) and sign up

**2. Create a New Web Service**
- Click **"New +"** → **"Web Service"**
- Connect your GitHub repository

**3. Configure Build Settings**

| Setting | Value |
|---------|-------|
| **Name** | WebSafe |
| **Environment** | Node |
| **Build Command** | `npm install` |
| **Start Command** | `npm start` |
| **Plan** | Free |

**4. Add Environment Variables**

Go to **Environment** tab and add:

```
SAFE_BROWSING_API_KEY = your_google_safe_browsing_api_key
```

**5. Deploy**
- Click **"Create Web Service"**
- Wait for deployment to complete (3-5 minutes)
- Your app will be live at `https://your-app-name.onrender.com`

---

## API Endpoints

### Safety Check
```http
GET /safety?url=https://example.com
```

**Response:**
```json
[
  "https://example.com",
  {
    "matches": [
      {
        "threatType": "MALWARE",
        "platformType": "ANY_PLATFORM",
        "threat": {
          "url": "https://example.com"
        }
      }
    ]
  }
]
```

### Screenshot Capture
```http
GET /screenshot?page=https://example.com&fullpage=true
```

**Parameters:**
- `page` (required) - URL to capture
- `fullpage` (optional) - Capture full page (true/false)

**Response:** PNG image

### Proxified Access
```http
GET /proxy?url=https://example.com
```

**Response:** Proxified website content

---

## Technology Stack

<div align="center">

| Technology | Purpose |
|------------|---------|
| ![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white) | Runtime Environment |
| ![Express](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white) | Web Framework |
| ![Puppeteer](https://img.shields.io/badge/Puppeteer-40B5A4?style=for-the-badge&logo=googlechrome&logoColor=white) | Headless Browser |
| ![Google Safe Browsing](https://img.shields.io/badge/Google%20Safe%20Browsing-4285F4?style=for-the-badge&logo=google&logoColor=white) | Threat Detection |

</div>

<div align="center">
  
# Made with ❤️ for a Safer Internet
</div>

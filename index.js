const express = require("express");
const puppeteer = require("puppeteer-core");
const chrome = require("@sparticuz/chromium");
const path = require('path');
const cors = require("cors");
const { createProxyMiddleware } = require("http-proxy-middleware");
const fetch = global.fetch;

const app = express();

app.use(
  cors({
    origin: "https://prateek.is-a.dev",   
    methods: "GET",
    allowedHeaders: "Content-Type,Authorization",
    credentials: true,
  })
);

app.get("/safety", async (req, res) => {
  const safeBrowsingApiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.SAFE_BROWSING_API_KEY}`;
  const targetUrl = decodeURIComponent(req.query.url);
  const responseData = [];

  try {
    new URL(targetUrl);
  } catch (error) {
    return res.json({ error: "Incorrect URL" });
  }

  let finalRedirectUrl;
  try {
    const headResponse = await fetch(targetUrl, {
      method: "HEAD",
      redirect: 'follow'
    });
    finalRedirectUrl = headResponse.url;
    responseData.push(finalRedirectUrl);
  } catch (error) {
    return res.json({ error: "Error while fetching URL" });
  }

  const requestBody = {
    client: {
      clientId: "safe-browse-url-lookup",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: { url: finalRedirectUrl }
    }
  };

  try {
    const threatResponse = await fetch(safeBrowsingApiUrl, {
      method: "POST",
      body: JSON.stringify(requestBody)
    }).then(response => response.json());

    responseData.push(threatResponse);
    res.json(responseData);
  } catch (error) {
    console.log(error);
    res.json(responseData);
  }
});

app.get("/screenshot", async (req, res) => {
  const targetUrl = req.query.page;
  const captureFullPage = req.query.fullpage === "true" || req.query.fullpage === "1";

  if (!targetUrl) {
    return res.status(400).json({ error: "Missing URL" });
  }

  try {
    const browser = await puppeteer.launch({
      args: [...chrome.args, "--no-sandbox", "--disable-setuid-sandbox"],
      executablePath: await chrome.executablePath(),
      headless: chrome.headless,
    });

    const page = await browser.newPage();
    await page.setViewport({ width: 1920, height: 1080 });
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 30000 });

    const screenshotBuffer = await page.screenshot({
      type: "png",
      fullPage: captureFullPage
    });

    await browser.close();

    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.status(200).end(screenshotBuffer);
  } catch (error) {
    res.status(500).json({ error: "Screenshot failed", message: error.message });
  }
});

app.use("/proxy", (req, res, next) => {
  const proxyTargetUrl = req.query.url;
  if (!proxyTargetUrl) {
    return res.status(400).json({ error: "Missing ?url parameter" });
  }
  try {
    new URL(proxyTargetUrl);
    next();
  } catch (error) {
    return res.status(400).json({ error: "Invalid URL" });
  }
});

app.use("/proxy", createProxyMiddleware({
  router: (req) => {
    const proxyTargetUrl = req.query.url;
    try {
      const parsedUrl = new URL(proxyTargetUrl);
      return parsedUrl.origin;
    } catch (error) {
      return null;
    }
  },
  changeOrigin: true,
  followRedirects: true, 
  pathRewrite: (requestPath, req) => {
    const proxyTargetUrl = req.query.url;
    try {
      const parsedUrl = new URL(proxyTargetUrl);
      return parsedUrl.pathname + parsedUrl.search + parsedUrl.hash;
    } catch (error) {
      return '/';
    }
  },

  onProxyReq: (proxyRequest, req, res) => {
    const proxyTargetUrl = req.query.url;
    
    try {
      const parsedUrl = new URL(proxyTargetUrl);
      
      proxyRequest.removeHeader('host');
      proxyRequest.removeHeader('referer');
      proxyRequest.removeHeader('origin');
      
      proxyRequest.setHeader('Host', parsedUrl.host);
      proxyRequest.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
      proxyRequest.setHeader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8');
      proxyRequest.setHeader('Accept-Language', 'en-US,en;q=0.9');
      proxyRequest.setHeader('Referer', parsedUrl.origin + '/');
    } catch (error) {
      console.error('Header error:', error);
    }
  },

  onProxyRes: (proxyResponse, req, res) => {
    delete proxyResponse.headers['x-frame-options'];
    delete proxyResponse.headers['content-security-policy'];
    delete proxyResponse.headers['content-security-policy-report-only'];
    delete proxyResponse.headers['strict-transport-security'];
  },

  onError: (error, req, res) => {
    console.error('Proxy error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Proxy failed', message: error.message });
    }
  }
}));

app.get('/', (req, res) => {
  res.sendFile(path.join(process.cwd(), "./index.html"));
});

app.use((error, req, res, next) => {
  console.error("Error:", error);
  res.status(500).json({ error: "Internal server error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

require('dotenv').config();

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const config = require('./config');
const { createPageRepository } = require('./models/pageRepository');
const { detectCodeType, extractCodeBlocks } = require('./utils/codeDetector');
const { renderContent, escapeHtml } = require('./utils/contentRenderer');
const {
  DEFAULT_PASSWORD_LENGTH,
  createCsrfToken,
  createScopedToken,
  generateId,
  generateNumericPassword,
  hashSecret,
  verifyCsrfToken,
  verifyScopedToken,
  verifySecret
} = require('./utils/security');

const ADMIN_COOKIE = 'admin_session';
const ADMIN_TTL_MS = 24 * 60 * 60 * 1000;
const PAGE_ACCESS_TTL_MS = 24 * 60 * 60 * 1000;
const VALID_CODE_TYPES = new Set(['html', 'markdown', 'svg', 'mermaid']);

const app = express();
const pageRepository = createPageRepository();

let initPromise = null;

app.locals.config = config;
app.locals.pageRepository = pageRepository;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(morgan(config.logLevel));
app.use(cors({ origin: false }));
app.use(bodyParser.json({ limit: '15mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '15mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function ensureDatabase() {
  if (!initPromise) {
    initPromise = pageRepository.init();
  }

  return initPromise;
}

function getAdminSession(req) {
  const token = req.cookies?.[ADMIN_COOKIE];
  const payload = verifyScopedToken(token, 'admin');

  if (!payload) {
    return null;
  }

  return {
    payload,
    token
  };
}

function requireAdmin(req, res, next) {
  if (!config.authEnabled) {
    return next();
  }

  const session = getAdminSession(req);

  if (!session) {
    return res.redirect('/login');
  }

  req.adminSession = session;
  return next();
}

function requireApiAdmin(req, res, next) {
  if (!config.authEnabled) {
    return next();
  }

  const session = getAdminSession(req);

  if (!session) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized'
    });
  }

  req.adminSession = session;
  return next();
}

function requireCsrf(req, res, next) {
  if (!config.authEnabled) {
    return next();
  }

  const sessionToken = req.adminSession?.token || req.cookies?.[ADMIN_COOKIE];
  const csrfToken = req.get('x-csrf-token') || req.body?._csrf;

  if (!verifyCsrfToken(sessionToken, csrfToken)) {
    return res.status(403).json({
      success: false,
      error: 'Invalid CSRF token'
    });
  }

  return next();
}

async function verifyAdminPassword(password) {
  if (!password) {
    return false;
  }

  if (config.adminPasswordHash) {
    return verifySecret(password, config.adminPasswordHash);
  }

  if (!config.authPassword) {
    return false;
  }

  return verifySecret(password, config.authPassword);
}

function setAdminCookie(res) {
  const token = createScopedToken('admin', {}, ADMIN_TTL_MS);

  res.cookie(ADMIN_COOKIE, token, {
    maxAge: ADMIN_TTL_MS,
    httpOnly: true,
    secure: config.secureCookies,
    sameSite: 'lax'
  });

  return token;
}

function clearAdminCookie(res) {
  res.clearCookie(ADMIN_COOKIE, {
    httpOnly: true,
    secure: config.secureCookies,
    sameSite: 'lax'
  });
}

function pageAccessCookieName(id) {
  return `page_access_${id}`;
}

function setPageAccessCookie(res, id) {
  const token = createScopedToken('page-access', { id }, PAGE_ACCESS_TTL_MS);

  res.cookie(pageAccessCookieName(id), token, {
    maxAge: PAGE_ACCESS_TTL_MS,
    httpOnly: true,
    secure: config.secureCookies,
    sameSite: 'lax'
  });
}

function hasPageAccess(req, id) {
  const token = req.cookies?.[pageAccessCookieName(id)];
  const payload = verifyScopedToken(token, 'page-access');

  return payload?.id === id;
}

function normalizeCodeType(content, requestedCodeType) {
  if (VALID_CODE_TYPES.has(requestedCodeType)) {
    return requestedCodeType;
  }

  const detectedType = detectCodeType(content);
  return VALID_CODE_TYPES.has(detectedType) ? detectedType : 'html';
}

async function createPageWithRetry(data) {
  let lastError = null;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const id = generateId();

    try {
      await pageRepository.create({
        ...data,
        id
      });

      return id;
    } catch (error) {
      lastError = error;

      if (!String(error.message || '').includes('UNIQUE') &&
          !String(error.code || '').includes('23505')) {
        throw error;
      }
    }
  }

  throw lastError || new Error('Failed to create a unique page id');
}

function injectCodeTypeMeta(renderedContent, contentType) {
  if (!renderedContent.includes('</head>')) {
    return renderedContent;
  }

  return renderedContent.replace(
    '</head>',
    `<meta name="code-type" content="${escapeHtml(contentType)}">\n</head>`
  );
}

function renderSandboxedDocument(renderedContent, contentType) {
  const escapedContent = escapeHtml(renderedContent);

  return `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="code-type" content="${escapeHtml(contentType)}">
      <title>HTML-GO Viewer</title>
      <style>
        html, body {
          width: 100%;
          height: 100%;
          margin: 0;
          background: #ffffff;
        }
        iframe {
          width: 100%;
          height: 100vh;
          border: 0;
          display: block;
        }
      </style>
    </head>
    <body>
      <iframe
        title="Shared content"
        sandbox="allow-downloads allow-forms allow-modals allow-popups allow-scripts"
        referrerpolicy="no-referrer"
        srcdoc="${escapedContent}">
      </iframe>
    </body>
    </html>
  `;
}

app.get('/login', (req, res) => {
  if (!config.authEnabled || getAdminSession(req)) {
    return res.redirect('/');
  }

  return res.render('login', {
    title: 'HTML-Go | Login',
    page: 'login-page',
    error: null
  });
});

app.post('/login', async (req, res) => {
  if (!config.authEnabled) {
    return res.redirect('/');
  }

  const isValid = await verifyAdminPassword(req.body.password);

  if (!isValid) {
    return res.status(401).render('login', {
      title: 'HTML-Go | Login',
      page: 'login-page',
      error: '密码错误，请重试'
    });
  }

  setAdminCookie(res);
  return res.redirect('/');
});

app.get('/logout', (req, res) => {
  clearAdminCookie(res);
  return res.redirect('/login');
});

app.get('/', requireAdmin, (req, res) => {
  const sessionToken = req.adminSession?.token || req.cookies?.[ADMIN_COOKIE] || '';

  return res.render('index', {
    title: 'QuickShare | 粘贴代码，一键分享',
    page: 'home-page',
    csrfToken: config.authEnabled ? createCsrfToken(sessionToken) : ''
  });
});

app.post('/api/pages/create', requireApiAdmin, requireCsrf, async (req, res) => {
  try {
    await ensureDatabase();

    const { htmlContent, isProtected, codeType, title, description } = req.body;

    if (!htmlContent || typeof htmlContent !== 'string') {
      return res.status(400).json({
        success: false,
        error: '请提供内容'
      });
    }

    const normalizedCodeType = normalizeCodeType(htmlContent, codeType);
    const password = isProtected ? generateNumericPassword(DEFAULT_PASSWORD_LENGTH) : null;
    const passwordHash = password ? await hashSecret(password) : null;
    const id = await createPageWithRetry({
      htmlContent,
      passwordHash,
      isProtected: Boolean(isProtected),
      codeType: normalizedCodeType,
      title,
      description,
      createdAt: Date.now(),
      expiresAt: null
    });

    return res.json({
      success: true,
      urlId: id,
      password,
      isProtected: Boolean(password),
      codeType: normalizedCodeType
    });
  } catch (error) {
    console.error('Create page failed:', error);
    return res.status(500).json({
      success: false,
      error: '服务器错误'
    });
  }
});

app.get('/api/pages/list/recent', requireApiAdmin, async (req, res) => {
  try {
    await ensureDatabase();

    const limit = Math.min(Number.parseInt(req.query.limit || '10', 10), 50);
    const pages = await pageRepository.listRecent(Number.isFinite(limit) ? limit : 10);

    return res.json({
      success: true,
      pages
    });
  } catch (error) {
    console.error('List recent pages failed:', error);
    return res.status(500).json({
      success: false,
      error: '服务器错误'
    });
  }
});

app.get('/api/pages/:id', async (req, res) => {
  try {
    await ensureDatabase();

    const page = await pageRepository.getById(req.params.id);

    if (!page) {
      return res.status(404).json({
        success: false,
        error: '页面不存在'
      });
    }

    return res.json({
      success: true,
      page: {
        id: page.id,
        createdAt: page.created_at,
        codeType: page.code_type,
        title: page.title,
        description: page.description,
        isProtected: page.is_protected === 1
      }
    });
  } catch (error) {
    console.error('Get page failed:', error);
    return res.status(500).json({
      success: false,
      error: '服务器错误'
    });
  }
});

app.post('/api/pages/:id/protect', requireApiAdmin, requireCsrf, async (req, res) => {
  try {
    await ensureDatabase();

    const page = await pageRepository.getById(req.params.id);

    if (!page) {
      return res.status(404).json({
        success: false,
        error: '页面不存在'
      });
    }

    const isProtected = Boolean(req.body.isProtected);
    const password = isProtected ? generateNumericPassword(DEFAULT_PASSWORD_LENGTH) : null;
    const passwordHash = password ? await hashSecret(password) : null;

    await pageRepository.updateProtection(req.params.id, {
      isProtected,
      passwordHash
    });

    return res.json({
      success: true,
      isProtected,
      password
    });
  } catch (error) {
    console.error('Update page protection failed:', error);
    return res.status(500).json({
      success: false,
      error: '更新保护状态失败'
    });
  }
});

app.post('/view/:id/password', async (req, res) => {
  try {
    await ensureDatabase();

    const page = await pageRepository.getById(req.params.id);

    if (!page || page.is_protected !== 1) {
      return res.status(404).json({
        valid: false
      });
    }

    const isValid = await verifySecret(req.body.password, page.password_hash || page.password);

    if (!isValid) {
      return res.status(401).json({
        valid: false
      });
    }

    setPageAccessCookie(res, req.params.id);
    return res.json({
      valid: true,
      redirectUrl: `/view/${req.params.id}`
    });
  } catch (error) {
    console.error('Validate page password failed:', error);
    return res.status(500).json({
      valid: false
    });
  }
});

app.get('/view/:id', async (req, res) => {
  try {
    await ensureDatabase();

    const page = await pageRepository.getById(req.params.id);

    if (!page) {
      return res.status(404).render('error', {
        title: '页面未找到',
        page: 'error-page',
        message: '您请求的页面不存在或已被删除'
      });
    }

    if (page.is_protected === 1 && !hasPageAccess(req, req.params.id)) {
      return res.render('password', {
        title: 'HTML-Go | 密码保护',
        page: 'password-page',
        id: req.params.id,
        passwordLength: DEFAULT_PASSWORD_LENGTH,
        error: null
      });
    }

    let processedContent = page.html_content;
    let contentType = page.code_type;
    const codeBlocks = extractCodeBlocks(page.html_content);

    if (!VALID_CODE_TYPES.has(contentType)) {
      contentType = normalizeCodeType(page.html_content, contentType);
    }

    if (codeBlocks.length === 1 && codeBlocks[0].content.length > page.html_content.length * 0.7) {
      processedContent = codeBlocks[0].content;
      contentType = codeBlocks[0].type;
    }

    if (!VALID_CODE_TYPES.has(contentType)) {
      contentType = 'html';
    }

    const renderedContent = await renderContent(processedContent, contentType);
    const contentWithTypeInfo = injectCodeTypeMeta(renderedContent, contentType);

    return res.send(renderSandboxedDocument(contentWithTypeInfo, contentType));
  } catch (error) {
    console.error('View page failed:', error);
    return res.status(500).render('error', {
      title: '服务器错误',
      page: 'error-page',
      message: '查看页面时发生错误，请稍后再试'
    });
  }
});

app.use((req, res) => {
  res.status(404).render('error', {
    title: '页面未找到',
    page: 'error-page',
    message: '您请求的页面不存在'
  });
});

module.exports = app;

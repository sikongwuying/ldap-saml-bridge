require('dotenv').config();
const express = require('express');
const ldap = require('ldapjs');
const passport = require('passport');
const { Strategy: SamlStrategy } = require('passport-saml');
const winston = require('winston');

// 配置日志记录器
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Express应用配置
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());

// SAML策略配置
const samlStrategy = new SamlStrategy({
  callbackUrl: process.env.SAML_CALLBACK_URL,
  entryPoint: process.env.SAML_ENTRY_POINT,
  issuer: process.env.SAML_ISSUER,
  cert: process.env.SAML_CERT,
  validateInResponseTo: true,
  disableRequestedAuthnContext: true
}, (profile, done) => {
  return done(null, profile);
});

passport.use('saml', samlStrategy);

// LDAP服务器配置
const ldapServer = ldap.createServer();

// 处理LDAP绑定请求
ldapServer.bind('dc=example,dc=com', async (req, res, next) => {
  const dn = req.dn.toString();
  const password = req.credentials;

  logger.info('LDAP bind request received', { dn });

  try {
    // 初始化SAML认证流程
    const samlRequest = await samlStrategy.generateAuthorizeRequest({
      nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    });

    // 存储LDAP请求信息，以便在SAML回调时使用
    req.session = {
      ldapDN: dn,
      ldapPassword: password
    };

    res.end();
  } catch (error) {
    logger.error('Error during LDAP bind', { error: error.message, dn });
    return next(new ldap.InvalidCredentialsError());
  }
});

// SAML回调处理
app.post('/saml/callback',
  passport.authenticate('saml', { session: false }),
  (req, res) => {
    const samlResponse = req.user;

    logger.info('SAML assertion received', {
      nameID: samlResponse.nameID,
      issuer: samlResponse.issuer
    });

    // 验证SAML断言
    if (validateSamlAssertion(samlResponse)) {
      res.status(200).json({ success: true });
    } else {
      logger.warn('Invalid SAML assertion', { nameID: samlResponse.nameID });
      res.status(401).json({ success: false });
    }
  }
);

// SAML断言验证
function validateSamlAssertion(assertion) {
  // 验证必要字段
  if (!assertion.nameID || !assertion.issuer) {
    return false;
  }

  // 验证断言有效期
  const now = new Date();
  if (assertion.notBefore && now < new Date(assertion.notBefore)) {
    return false;
  }
  if (assertion.notOnOrAfter && now >= new Date(assertion.notOnOrAfter)) {
    return false;
  }

  // 验证颁发者
  if (assertion.issuer !== process.env.SAML_ISSUER) {
    return false;
  }

  return true;
}

// 错误处理中间件
app.use((err, req, res, next) => {
  logger.error('Application error', { error: err.message });
  res.status(500).json({ error: 'Internal server error' });
});

// 启动服务器
const EXPRESS_PORT = process.env.PORT || 3000;
const LDAP_PORT = process.env.LDAP_PORT || 389;

app.listen(EXPRESS_PORT, () => {
  logger.info(`Express server listening on port ${EXPRESS_PORT}`);
});

ldapServer.listen(LDAP_PORT, () => {
  logger.info(`LDAP server listening on port ${LDAP_PORT}`);
});
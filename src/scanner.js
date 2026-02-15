/**
 * Credential pattern detection and domain scanning
 */

// Common credential patterns to detect
const CREDENTIAL_PATTERNS = [
  {
    name: 'API Key',
    pattern: /api[_-]?key["']?\s*[:=]\s*["']?([a-zA-Z0-9_]{16,})/gi,
    type: 'api_key'
  },
  {
    name: 'AWS Access Key',
    pattern: /aws[_-]?access[_-]?key[_-]?id["']?\s*[:=]\s*["']?([A-Z0-9]{20,})/gi,
    type: 'aws_key'
  },
  {
    name: 'Password',
    pattern: /(password|passwd|pwd|secret)["']?\s*[:=]\s*["']?([^\s'"]{4,})/gi,
    type: 'password'
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN.*PRIVATE KEY-----/g,
    type: 'private_key'
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    type: 'jwt'
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[a-zA-Z0-9]{36,}/g,
    type: 'github_token'
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    type: 'slack_token'
  },
  {
    name: 'Database Connection String',
    pattern: /(mongodb|mysql|postgres|postgresql|redis|amqp|jdbc):\/\/[^\s]+/gi,
    type: 'connection_string'
  },
  {
    name: 'Email:Password',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s]+/g,
    type: 'email_password'
  },
  {
    name: 'Bearer Token',
    pattern: /bearer\s+[a-zA-Z0-9_\-\.]+/gi,
    type: 'bearer_token'
  },
  {
    name: 'Basic Auth',
    pattern: /basic\s+[a-zA-Z0-9+/=]+/gi,
    type: 'basic_auth'
  },
  {
    name: 'NPM Token',
    pattern: /npm_[a-zA-Z0-9]{36}/g,
    type: 'npm_token'
  },
  {
    name: 'Stripe Key',
    pattern: /(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}/gi,
    type: 'stripe_key'
  },
  {
    name: 'Twilio Key',
    pattern: /SK[a-f0-9]{32}/g,
    type: 'twilio_key'
  },
  {
    name: 'SendGrid Key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    type: 'sendgrid_key'
  },
  {
    name: 'Generic Token',
    pattern: /(token|auth|access[_-]?key)[_-]?secret["']?\s*[:=]\s*["']?([a-zA-Z0-9_]{20,})/gi,
    type: 'generic_token'
  }
];

/**
 * Detect credentials in text content
 * @param {string} content - Text content to scan
 * @returns {string[]} Array of detected credential types
 */
function detectCredentials(content) {
  if (!content || typeof content !== 'string') {
    return [];
  }

  const detectedTypes = new Set();

  for (const cred of CREDENTIAL_PATTERNS) {
    // Reset regex state
    const regex = new RegExp(cred.pattern.source, cred.pattern.flags);
    
    if (regex.test(content)) {
      detectedTypes.add(cred.type);
    }
  }

  return Array.from(detectedTypes);
}

/**
 * Scan content for specific domains
 * @param {string} content - Text content to scan
 * @param {string[]} domains - Array of domains to search for
 * @returns {string[]} Array of matched domains
 */
function scanForDomains(content, domains) {
  if (!content || !Array.isArray(domains) || domains.length === 0) {
    return [];
  }

  const matchedDomains = new Set();

  for (const domain of domains) {
    const escapedDomain = domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    // Check for domain in content
    const domainRegex = new RegExp(escapedDomain, 'i');
    if (domainRegex.test(content)) {
      matchedDomains.add(domain);
    }
    
    // Also check for email patterns with this domain
    const emailRegex = new RegExp('[a-zA-Z0-9._%+-]+@' + escapedDomain, 'i');
    if (emailRegex.test(content)) {
      matchedDomains.add(domain);
    }
  }

  return Array.from(matchedDomains);
}

/**
 * Extract potential credentials from content (for reporting)
 * @param {string} content - Text content to scan
 * @returns {object[]} Array of found credentials with context
 */
function extractCredentials(content) {
  if (!content || typeof content !== 'string') {
    return [];
  }

  const extracted = [];

  for (const cred of CREDENTIAL_PATTERNS) {
    const regex = new RegExp(cred.pattern.source, cred.pattern.flags);
    let match;
    
    while ((match = regex.exec(content)) !== null) {
      extracted.push({
        type: cred.type,
        name: cred.name,
        value: match[0].substring(0, 50) + (match[0].length > 50 ? '...' : ''),
        index: match.index
      });
    }
  }

  return extracted;
}

/**
 * Create a custom scanner with additional patterns
 * @param {Array} additionalPatterns - Additional credential patterns to detect
 * @returns {object} Scanner functions
 */
function createScanner(additionalPatterns = []) {
  const allPatterns = [...CREDENTIAL_PATTERNS, ...additionalPatterns];

  return {
    detectCredentials: function(content) {
      if (!content || typeof content !== 'string') {
        return [];
      }

      const detectedTypes = new Set();

      for (const cred of allPatterns) {
        const regex = new RegExp(cred.pattern.source, cred.pattern.flags);
        if (regex.test(content)) {
          detectedTypes.add(cred.type);
        }
      }

      return Array.from(detectedTypes);
    },
    
    extractCredentials: function(content) {
      if (!content || typeof content !== 'string') {
        return [];
      }

      const extracted = [];

      for (const cred of allPatterns) {
        const regex = new RegExp(cred.pattern.source, cred.pattern.flags);
        let match;
        
        while ((match = regex.exec(content)) !== null) {
          extracted.push({
            type: cred.type,
            name: cred.name,
            value: match[0].substring(0, 50) + (match[0].length > 50 ? '...' : ''),
            index: match.index
          });
        }
      }

      return extracted;
    }
  };
}

module.exports = {
  detectCredentials,
  scanForDomains,
  extractCredentials,
  createScanner,
  CREDENTIAL_PATTERNS
};

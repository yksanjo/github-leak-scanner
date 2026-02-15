const fs = require('fs');
const path = require('path');

/**
 * Load configuration from a JSON file
 * @param {string} configPath - Path to config file
 * @returns {object} Configuration object
 */
function loadConfig(configPath) {
  const defaultConfig = {
    domains: [],
    interval: 30,
    verbose: false,
    alerts: {
      console: true,
      email: null
    }
  };

  try {
    if (fs.existsSync(configPath)) {
      const fileContent = fs.readFileSync(configPath, 'utf8');
      const userConfig = JSON.parse(fileContent);
      return { ...defaultConfig, ...userConfig };
    }
  } catch (error) {
    console.warn(`Warning: Could not load config from ${configPath}: ${error.message}`);
  }

  return defaultConfig;
}

/**
 * Validate and normalize domain list
 * @param {string[]} domains - Array of domain strings
 * @returns {string[]} Validated domains
 */
function validateDomains(domains) {
  if (!Array.isArray(domains)) {
    return [];
  }

  return domains
    .map(d => {
      // Remove protocol if present
      d = d.replace(/^https?:\/\//, '');
      // Remove trailing slash
      d = d.replace(/\/$/, '');
      // Remove path if present
      d = d.split('/')[0];
      // Convert to lowercase
      return d.toLowerCase();
    })
    .filter(d => d.length > 0 && isValidDomain(d));
}

/**
 * Check if a string is a valid domain
 * @param {string} domain - Domain string
 * @returns {boolean} True if valid domain
 */
function isValidDomain(domain) {
  // Basic domain validation regex
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

/**
 * Save configuration to a file
 * @param {string} configPath - Path to save config
 * @param {object} config - Configuration object
 */
function saveConfig(configPath, config) {
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
}

module.exports = {
  loadConfig,
  validateDomains,
  isValidDomain,
  saveConfig
};

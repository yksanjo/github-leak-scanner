const axios = require('axios');
const { detectCredentials, scanForDomains } = require('./scanner');

class Monitor {
  constructor(domains, options = {}) {
    this.domains = domains;
    this.interval = options.interval || 30 * 60 * 1000;
    this.verbose = options.verbose || false;
    this.once = options.once || false;
    this.token = options.token;
    this.isRunning = false;
    this.lastCheck = null;
    this.findings = [];
    
    this.github = axios.create({
      baseURL: 'https://api.github.com',
      headers: this.token ? {
        'Authorization': `token ${this.token}`,
        'Accept': 'application/vnd.github.v3+json'
      } : {
        'Accept': 'application/vnd.github.v3+json'
      }
    });
  }

  async start() {
    this.isRunning = true;
    console.log('🚀 Starting GitHub scanning...\n');

    await this.check();

    if (this.once) {
      console.log('\n✅ Single scan completed');
      this.printSummary();
      return;
    }

    console.log(`\n⏳ Continuous monitoring active. Checking every ${this.interval / 60000} minutes...`);
    console.log('Press Ctrl+C to stop.\n');

    this.intervalId = setInterval(async () => {
      await this.check();
    }, this.interval);
  }

  stop() {
    this.isRunning = false;
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
  }

  async check() {
    this.lastCheck = new Date();
    console.log(`\n[${this.lastCheck.toISOString()}] Scanning GitHub...`);

    let totalScanned = 0;
    let threatsFound = 0;

    // Scan GitHub Code Search
    try {
      if (this.verbose) {
        console.log('  📂 Searching GitHub code...');
      }
      const codeResults = await this.scanCodeSearch();
      totalScanned += codeResults.length;
      
      for (const result of codeResults) {
        const findings = await this.analyzeContent(result);
        if (findings.length > 0) {
          threatsFound += findings.length;
          this.findings.push(...findings);
          this.alert(findings);
        }
      }
    } catch (error) {
      console.error(`  ❌ Error scanning code: ${error.message}`);
    }

    // Scan Gists
    try {
      if (this.verbose) {
        console.log('  📂 Scanning public gists...');
      }
      const gists = await this.scanGists();
      totalScanned += gists.length;
      
      for (const gist of gists) {
        const findings = await this.analyzeContent(gist);
        if (findings.length > 0) {
          threatsFound += findings.length;
          this.findings.push(...findings);
          this.alert(findings);
        }
      }
    } catch (error) {
      console.error(`  ❌ Error scanning gists: ${error.message}`);
    }

    console.log(`  ✅ Scanned ${totalScanned} items, found ${threatsFound} potential leak(s)`);
  }

  async scanCodeSearch() {
    const results = [];
    
    for (const domain of this.domains) {
      try {
        // Search for the domain in code
        const query = `${domain} password`;
        const response = await this.github.get('/search/code', {
          params: { q: query, per_page: 30 }
        });
        
        for (const item of response.data.items || []) {
          results.push({
            type: 'code',
            repository: item.repository.full_name,
            path: item.path,
            url: item.html_url,
            contentUrl: item.url
          });
        }
        
        // Also search for API keys
        const apiQuery = `${domain} api_key`;
        const apiResponse = await this.github.get('/search/code', {
          params: { q: apiQuery, per_page: 30 }
        });
        
        for (const item of apiResponse.data.items || []) {
          results.push({
            type: 'code',
            repository: item.repository.full_name,
            path: item.path,
            url: item.html_url,
            contentUrl: item.url
          });
        }
      } catch (error) {
        if (this.verbose) {
          console.error(`    Search error for ${domain}: ${error.message}`);
        }
      }
    }
    
    return results;
  }

  async scanGists() {
    const results = [];
    
    try {
      // Get public gists (paginated)
      const response = await this.github.get('/gists/public', {
        params: { per_page: 30 }
      });
      
      for (const gist of response.data) {
        for (const [filename, fileData] of Object.entries(gist.files)) {
          results.push({
            type: 'gist',
            id: gist.id,
            filename: filename,
            url: gist.html_url,
            content: fileData.content
          });
        }
      }
    } catch (error) {
      if (this.verbose) {
        console.error(`    Gists error: ${error.message}`);
      }
    }
    
    return results;
  }

  async analyzeContent(item) {
    const findings = [];
    
    try {
      let content = '';
      
      if (item.type === 'code' && item.contentUrl) {
        // Fetch file content
        const response = await this.github.get(item.contentUrl);
        content = response.data.content || '';
      } else if (item.type === 'gist') {
        content = item.content || '';
      }
      
      // Check for domain matches
      const domainMatches = scanForDomains(content, this.domains);
      
      if (domainMatches.length > 0 || (item.url && this.domains.some(d => item.url.includes(d)))) {
        const credentials = detectCredentials(content);
        
        if (credentials.length > 0) {
          findings.push({
            timestamp: new Date().toISOString(),
            type: item.type,
            source: item.repository || item.id,
            path: item.path || item.filename,
            url: item.url,
            matchedDomains: domainMatches,
            credentials: credentials,
            snippet: content.substring(0, 200)
          });
        }
      }
    } catch (error) {
      // Silently ignore
    }
    
    return findings;
  }

  alert(findings) {
    for (const finding of findings) {
      console.log('\n🚨 ALERT: Potential Credential Leak Detected!');
      console.log('='.repeat(50));
      console.log(`Type: ${finding.type}`);
      console.log(`Source: ${finding.source}`);
      console.log(`Path: ${finding.path}`);
      console.log(`URL: ${finding.url}`);
      console.log(`Matched Domains: ${finding.matchedDomains.join(', ')}`);
      console.log(`Credential Types: ${finding.credentials.join(', ')}`);
      console.log(`\nSnippet: ${finding.snippet}...`);
      console.log('='.repeat(50));
    }
  }

  printSummary() {
    console.log('\n📊 Summary');
    console.log('='.repeat(30));
    console.log(`Total findings: ${this.findings.length}`);
    
    if (this.findings.length > 0) {
      console.log('\nDetails:');
      for (const finding of this.findings) {
        console.log(`  - [${finding.timestamp}] ${finding.type}: ${finding.source}`);
      }
    }
  }
}

module.exports = Monitor;

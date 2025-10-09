// Define a whitelist of trusted origins
const TRUSTED_ORIGINS = [
    window.location.origin, // Same origin
    'https://ai-gha-scanner-f53106.gitlab.io'
  ];
  
  // Helper function to check if an origin is trusted
  function isOriginTrusted(origin) {
    return TRUSTED_ORIGINS.includes(origin);
  }
  
  // Helper function to validate events for security
  function validateEvent(event, expectedTarget = null) {
    // Check if event is undefined or null
    if (!event) {
      console.warn('Event object is null or undefined');
      return false;
    }

    // For programmatically created events used in our own code, allow them
    if (event.isTrusted === false && event._isCustomEvent === true) {
      return true;
    }
    
    // Check if the event is trusted (created by user action, not programmatically)
    if (event.isTrusted === false && !event._isCustomEvent) {
      console.warn('Untrusted event detected');
      return false;
    }
    
    // Validate the event target if one is expected
    if (expectedTarget && event.target !== expectedTarget) {
      // Check if the target is a child of the expected target
      // This allows clicks on child elements within containers to work properly
      if (expectedTarget.contains && expectedTarget.contains(event.target)) {
        return true;
      }
      console.warn('Event target mismatch');
      return false;
    }
    
    // Validate that the event origin is from a trusted source
    if (event.origin && !isOriginTrusted(event.origin)) {
      console.warn('Event from untrusted origin');
      return false;
    }
    
    // If we're in an iframe, validate that the parent is trusted
    if (window.top !== window.self) {
      try {
        const parentOrigin = new URL(document.referrer).origin;
        if (!isOriginTrusted(parentOrigin)) {
          console.warn('Parent frame has untrusted origin');
          return false;
        }
      } catch (e) {
        console.warn('Cannot validate parent frame origin');
        return false;
      }
    }
    
    return true;
  }
  
  document.addEventListener('DOMContentLoaded', function(event) {
    // Validate the event
    if (!validateEvent(event)) {
      console.error('Invalid DOMContentLoaded event');
      return;
    }
    
    console.log('DOMContentLoaded triggered - initializing app');
    
    // Make window.allScanNames globally accessible for search functionality
    window.allScanNames = window.allScanNames || [];
    
    // Set up search input event listener immediately
    setupSearchFunctionality();
    
    // Load the security overview data
    loadSecurityOverview();
  });
  
  // Function to set up search functionality
  function setupSearchFunctionality() {
    console.log('Setting up search functionality');
    
    const securitySearch = document.getElementById('security-search');
    if (!securitySearch) {
      console.error('Search input element not found with ID "security-search"');
      // Try checking if there are any search inputs on the page
      const searchInputs = document.querySelectorAll('input[type="text"]');
      console.log(`Found ${searchInputs.length} text inputs on page:`, 
                 Array.from(searchInputs).map(el => `#${el.id} .${el.className}`).join(', '));
      return;
    }
    
    console.log('Found search input element:', securitySearch.id);
    
    // Initialize global search names array if not already done
    if (!window.allScanNames) {
      window.allScanNames = [];
      console.log('Initialized empty allScanNames array');
    }
    
    securitySearch.addEventListener('input', function(e) {
      // Validate the event with target check
      if (!validateEvent(e, securitySearch)) {
        console.warn('Invalid search event detected');
        return;
      }
      
      console.log('Search input event triggered');
      
      // Apply rate limiting to search
      rateLimiter.limit('security-search', () => {
        const searchValue = sanitizeSearchInput(this.value.toLowerCase());
        console.log(`Searching for: "${searchValue}"`);
        
        const scans = document.querySelectorAll('.security-scan');
        console.log(`Found ${scans.length} scan elements`);
        
        const suggestions = document.getElementById('search-suggestions');
        if (!suggestions) {
          console.error('Search suggestions element not found');
          return;
        }
        
        if (searchValue === '') {
          // Show all scans when search is empty
          scans.forEach(scan => {
            scan.style.display = 'block';
          });
          
          // Clear suggestions
          while (suggestions.firstChild) {
            suggestions.removeChild(suggestions.firstChild);
          }
          suggestions.classList.remove('active');
          return;
        }
        
        // Filter the scans based on search value
        let matchFound = false;
        scans.forEach(scan => {
          const searchText = scan.getAttribute('data-search');
          if (searchText && searchText.includes(searchValue)) {
            scan.style.display = 'block';
            matchFound = true;
          } else {
            scan.style.display = 'none';
          }
        });
        
        console.log(`Search matches found: ${matchFound}`);
        
        // We may not have any suggestions until data is loaded
        if (!window.allScanNames || window.allScanNames.length === 0) {
          console.log('No scan names available for suggestions');
          return;
        }
        
        console.log(`Available scan names for suggestions: ${window.allScanNames.length}`);
        
        // Show search suggestions
        const matchingSuggestions = window.allScanNames.filter(name => 
          name.toLowerCase().includes(searchValue)
        );
        
        console.log(`Matching suggestions: ${matchingSuggestions.length}`);
        
        if (matchingSuggestions.length > 0) {
          // First clear existing suggestions
          while (suggestions.firstChild) {
            suggestions.removeChild(suggestions.firstChild);
          }
          
          // Then add each suggestion using safe DOM methods
          matchingSuggestions.forEach(name => {
            const item = createSafeElement('div', { class: 'suggestion-item' }, escapeHTML(name));
            item.addEventListener('click', function(e) {
              // Validate the event with target check
              if (!validateEvent(e, item)) {
                return;
              }
              
              securitySearch.value = name; // Use the original, unescaped name for the input value
              suggestions.classList.remove('active');
              
              // Manually trigger filtering based on selected suggestion
              const searchEvent = new Event('input', {
                bubbles: true,
                cancelable: true
              });
              // Mark as custom event so our validator accepts it
              searchEvent._isCustomEvent = true;
              securitySearch.dispatchEvent(searchEvent);
            });
            
            suggestions.appendChild(item);
          });
          suggestions.classList.add('active');
        } else {
          while (suggestions.firstChild) {
            suggestions.removeChild(suggestions.firstChild);
          }
          const noSuggestions = createSafeElement('div', { class: 'no-suggestions' }, 'No matching security scans');
          suggestions.appendChild(noSuggestions);
          suggestions.classList.add('active');
        }
      });
    });
    
    // Add escape key handling for better UX
    securitySearch.addEventListener('keydown', function(e) {
      // Validate the event with target check
      if (!validateEvent(e, securitySearch)) {
        return;
      }
      
      // Clear search when pressing Escape
      if (e.key === 'Escape') {
        this.value = '';
        const suggestions = document.getElementById('search-suggestions');
        if (suggestions) {
          while (suggestions.firstChild) {
            suggestions.removeChild(suggestions.firstChild);
          }
          suggestions.classList.remove('active');
        }
        
        // Show all scans
        const scans = document.querySelectorAll('.security-scan');
        scans.forEach(scan => {
          scan.style.display = 'block';
        });
      }
    });
    
    console.log('Search functionality setup complete');
  }
  
  // Global handler function for scan header clicks
  window.handleScanHeaderClick = function(headerElement) {
    console.log('Scan header click detected', headerElement);
    
    // Create a fake event object for validation that marks it as custom
    const fakeEvent = { 
      isTrusted: true, 
      target: headerElement,
      _isCustomEvent: true // Mark as custom event
    };
    
    // Validate the context
    if (!validateEvent(fakeEvent, headerElement)) {
      console.warn('Invalid scan header click event');
      return;
    }
    
    const scanElement = headerElement.closest('.security-scan');
    if (!scanElement) {
      console.error('Could not find parent security-scan element');
      return;
    }
    
    scanElement.classList.toggle('expanded');
    console.log('Toggled expanded state:', scanElement.classList.contains('expanded'));
    
    // If this is the first time expanding and details aren't loaded yet, load them
    if (scanElement.classList.contains('expanded') && scanElement.getAttribute('data-loaded') === 'false') {
      const file = scanElement.getAttribute('data-file');
      console.log('Loading file details:', file);
      
      // Sanitize file path to prevent injection
      const sanitizedFile = sanitizeFilePath(file);
      
      if (!sanitizedFile) {
        console.error('Invalid file path detected and blocked');
        return;
      }
      
      const container = scanElement.querySelector('.scan-content');
      if (!container) {
        console.error('Could not find scan-content container');
        return;
      }
      
      loadSecurityDetails(sanitizedFile, container)
        .then(() => {
          scanElement.setAttribute('data-loaded', 'true');
          console.log('Successfully loaded scan details');
        })
        .catch(error => {
          console.error('Error loading security details:', error);
          if (container) {
            // Use DOM methods for error message
            while (container.firstChild) {
              container.removeChild(container.firstChild);
            }
            const errorElement = createSafeElement('p', { class: 'error' }, 
                                                  `Error loading security details: ${error.message}`);
            container.appendChild(errorElement);
          }
        });
    }
  };
  
  // Simple rate limiting for search operations
  const rateLimiter = {
    operations: {},
    limit: function(operation, callback, delay = 500) {
      if (this.operations[operation]) {
        clearTimeout(this.operations[operation]);
      }
      this.operations[operation] = setTimeout(() => {
        callback();
        delete this.operations[operation];
      }, delay);
    }
  };
  
  // Improved sanitizeSearchInput function
  function sanitizeSearchInput(input) {
      if (typeof input !== 'string') return '';
      
      // Trim whitespace and limit length
      input = input.trim().slice(0, 100);
      
      // Replace potentially harmful characters
      return input.replace(/[<>'"&]/g, '') // Remove dangerous characters
             .replace(/javascript:/gi, '')  // Remove javascript: protocol
             .replace(/on\w+=/gi, '');      // Remove event handlers
  }
  
  // Add HTML escaping function to prevent XSS
  function escapeHTML(str) {
      if (typeof str !== 'string') return '';
      return str
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#039;');
  }
  
  // Improved validateJsonData function
  function validateJsonData(data, type) {
      try {
          if (!data || typeof data !== 'object') return false;
          
          if (type === 'security') {
              // More thorough validation for security data
              const requiredKeys = ['repo-name', 'action-name', 'Security-Issues', 'issues'];
              const hasAtLeastOneRequiredKey = requiredKeys.some(key => data.hasOwnProperty(key));
              
              if (!hasAtLeastOneRequiredKey) return false;
              
              // Ensure arrays are actually arrays and don't exceed reasonable sizes
              const maxArrayLength = 1000; // Reasonable limit for array length
              
              const validateArray = (arr) => Array.isArray(arr) && arr.length <= maxArrayLength;
              
              const safeArrays = 
                  (!data["Security-Issues"] || validateArray(data["Security-Issues"])) &&
                  (!data.issues || validateArray(data.issues)) &&
                  (!data.checks || validateArray(data.checks)) &&
                  (!data.Recommendations || validateArray(data.Recommendations)) &&
                  (!data["mitigation-stratagy"] || validateArray(data["mitigation-stratagy"]));
              
              return hasAtLeastOneRequiredKey && safeArrays;
          } else if (type === 'repository') {
              // Validate repository data
              return data.hasOwnProperty('repository') && 
                     typeof data.repository === 'object' &&
                     data.hasOwnProperty('releases') &&
                     typeof data.releases === 'object';
          }
          return true;
      } catch (e) {
          console.error('JSON validation error:', e);
          return false;
      }
  }
  
  // Safe JSON parsing function
  function safeJSONParse(text, defaultValue = null) {
      if (!text || typeof text !== 'string') {
          return defaultValue;
      }
      
      // Check for unreasonably large inputs
      if (text.length > 5 * 1024 * 1024) { // 5MB limit for parsing (increased from 100KB)
          console.warn('Rejecting large JSON string for parsing');
          return defaultValue;
      }
      
      try {
          return JSON.parse(text);
      } catch (error) {
          console.error('JSON parsing error:', error.message);
          return defaultValue;
      }
  }
  
  // Enhance file path sanitization
  function sanitizeFilePath(path) {
      if (typeof path !== 'string') return '';
      
      // Remove directory traversal and other potentially harmful characters
      return path
          .replace(/\.\.\//g, '') // Prevent directory traversal
          .replace(/[<>"'&;]/g, '') // Remove dangerous characters
          .replace(/\s+/g, '-'); // Replace spaces with hyphens
  }
  
  // Helper function to get security files from index.json
  async function getSecurityFilesFromIndex() {
      try {
          // Add timeout for fetch operations
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000);
          
          const indexResp = await fetch('output/index.json', { signal: controller.signal });
          clearTimeout(timeoutId);
          
          if (!indexResp.ok) throw new Error(`Failed to load index file: ${indexResp.status}`);
          
          let indexData;
          try {
              const rawData = await indexResp.text();
              
              // Check for unreasonably large payloads
              if (rawData.length > 5 * 1024 * 1024) { // 5MB limit
                  throw new Error('Index data is too large');
              }
              
              indexData = JSON.parse(rawData);
          } catch (parseError) {
              throw new Error(`Invalid JSON in index file: ${parseError.message}`);
          }
          
          // Validate the index data structure
          if (!indexData || !Array.isArray(indexData.files)) {
              throw new Error('Invalid index file format: missing files array');
          }
          
          if (indexData.files.length > 0) {
              console.log('Found files from index.json:', indexData.files);
              // Sanitize file paths to prevent path traversal
              return indexData.files
                  .filter(file => typeof file === 'string' && file.endsWith('.json'))
                  .map(file => {
                      // Enhanced sanitization of file paths
                      const safeFile = sanitizeFilePath(file);
                      return `output/${safeFile}`;
                  });
          }
          
          throw new Error('No files found in index.json');
      } catch (error) {
          console.warn('Could not load files from index.json:', error.message);
          return [];
      }
  }
  
  // Load the security overview file
  async function loadSecurityOverview() {
      const securityIssuesDiv = document.getElementById('security-issues');
  
      if (securityIssuesDiv) {
          // Use textContent instead of innerHTML for better security
          while (securityIssuesDiv.firstChild) {
              securityIssuesDiv.removeChild(securityIssuesDiv.firstChild);
          }
          
          const loadingText = document.createTextNode('Loading security overview...');
          securityIssuesDiv.appendChild(loadingText);
          securityIssuesDiv.className = 'loading';
      }
  
      try {
          // Fetch the security overview file
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 10000);
          
          let overviewData;
          try {
          const overviewResp = await fetch('output/security-overview.json', { signal: controller.signal });
          clearTimeout(timeoutId);
          
              if (!overviewResp.ok) {
                  console.warn(`Failed to load security overview: ${overviewResp.status}. Using empty data.`);
                  overviewData = createEmptySecurityOverview();
              } else {
          try {
              const rawData = await overviewResp.text();
              
              // Check for unreasonably large payloads
              if (rawData.length > 10 * 1024 * 1024) { // 10MB limit
                  throw new Error('Security overview data is too large');
              }
              
              overviewData = JSON.parse(rawData);
              
              // Validate parsed data is an array
              if (!Array.isArray(overviewData)) {
                          console.warn('Security overview data is not in the expected format. Using empty data.');
                          overviewData = createEmptySecurityOverview();
              }
          } catch (parseError) {
                      console.warn(`Invalid JSON in security overview: ${parseError.message}. Using empty data.`);
                      overviewData = createEmptySecurityOverview();
                  }
              }
          } catch (fetchError) {
              console.warn(`Error fetching security overview: ${fetchError.message}. Using empty data.`);
              overviewData = createEmptySecurityOverview();
          }
  
          // Create elements safely using DOM methods instead of innerHTML
          if (securityIssuesDiv) {
              // Clear the loading message
              while (securityIssuesDiv.firstChild) {
                  securityIssuesDiv.removeChild(securityIssuesDiv.firstChild);
              }
              securityIssuesDiv.className = '';
              
              // Create header section
              const sectionHeader = createSafeElement('div', { class: 'section-header' });
              const heading = createSafeElement('h2', {}, 'Actions Analysis');
              sectionHeader.appendChild(heading);
              securityIssuesDiv.appendChild(sectionHeader);
              
              // Calculate total issues by severity
              const totalStats = calculateTotalSecurityIssues(overviewData);
              
              // Display total issues summary if there are any issues
              if (totalStats.totalIssues > 0) {
                  const totalIssuesSummary = createSafeElement('div', { class: 'total-issues-summary' });
                  
                  const summaryTitle = createSafeElement('h3', {}, 'Total Issues:');
                  totalIssuesSummary.appendChild(summaryTitle);
                  
                  // Create a container for better visual layout of severity cards
                  const severityCardsContainer = createSafeElement('div', { class: 'severity-cards-container' });
                  
                  // Create individual cards for each severity level
                  const createSeverityCard = (count, label, severityClass) => {
                      const card = createSafeElement('div', { class: `severity-card ${severityClass}` });
                      const countElement = createSafeElement('div', { class: 'severity-count' }, count.toString());
                      const labelElement = createSafeElement('div', { class: 'severity-label' }, label);
                      card.appendChild(countElement);
                      card.appendChild(labelElement);
                      return card;
                  };
                  
                  // Create cards for each severity
                  severityCardsContainer.appendChild(createSeverityCard(totalStats.criticalCount, 'CRITICAL', 'critical'));
                  severityCardsContainer.appendChild(createSeverityCard(totalStats.highCount, 'HIGH', 'high'));
                  severityCardsContainer.appendChild(createSeverityCard(totalStats.mediumCount, 'MEDIUM', 'medium'));
                  severityCardsContainer.appendChild(createSeverityCard(totalStats.lowCount, 'LOW', 'low'));
                  
                  // Create total issues card
                  const totalCard = createSafeElement('div', { class: 'severity-card total' });
                  const totalCountElement = createSafeElement('div', { class: 'severity-count' }, totalStats.totalIssues.toString());
                  const totalLabelElement = createSafeElement('div', { class: 'severity-label' }, 'TOTAL');
                  totalCard.appendChild(totalCountElement);
                  totalCard.appendChild(totalLabelElement);
                  severityCardsContainer.appendChild(totalCard);
                  
                  totalIssuesSummary.appendChild(severityCardsContainer);
                  securityIssuesDiv.appendChild(totalIssuesSummary);
              }
              
              // Clear and reset global search names array
              console.log('Clearing allScanNames array for fresh data');
              window.allScanNames = [];
              
              // Create security scans container
              const scansContainer = createSafeElement('div', { class: 'security-scans' });
              
              // Sort by unsafe checks (highest count first)
              overviewData.sort((a, b) => {
                  const unsafeA = a.unsafeChecks || 0;
                  const unsafeB = b.unsafeChecks || 0;
                  return unsafeB - unsafeA; // Sort in descending order
              });
              
              // Add each security scan
              overviewData.forEach(scan => {
                  // Validate scan data
                  if (!scan || typeof scan !== 'object') return;
                  
                  // Add to searchable items
                  const scanName = `${scan.actionName || 'Unknown'} - ${scan.repoName || 'Unknown Repo'}`;
                  window.allScanNames.push(scanName);
                  console.log(`Added to searchable items: ${scanName}`);
                  
                  const scanDiv = createSafeElement('div', {
                      class: 'security-scan',
                      'data-file': scan.file || '',
                      'data-loaded': 'false',
                      'data-search': scanName.toLowerCase()
                  });
                  
                  // Create scan header
                  const scanHeader = createSafeElement('div', { class: 'scan-header' });
                  scanHeader.addEventListener('click', function(e) {
                      // Use expanded validation to handle clicks on child elements too
                      if (validateEvent(e, scanHeader)) {
                      handleScanHeaderClick(this);
                      }
                  });
                  
                  // Create scan title area with improved structure
                  const scanTitle = createSafeElement('div', { class: 'scan-title' });
                  
                  // Title group (repo name and badge area)
                  const titleGroup = createSafeElement('div', { class: 'title-group' });
                  
                  // Repository name with enhanced styling
                  const titleH3 = createSafeElement('h3', {}, `${scan.actionName || 'Unknown'} - ${scan.repoName || 'Unknown Repo'}`);
                  titleGroup.appendChild(titleH3);
                  
                  // Badge area for better visual organization
                  const badgeArea = createSafeElement('div', { class: 'badge-area' });
                  
                  // SHA with copy feature
                  const shaWrapper = createSafeElement('div', { class: 'sha-wrapper', title: 'SHA Hash' });
                  const shaSpan = createSafeElement('span', { class: 'sha' }, scan.sha || 'Unknown');
                  shaWrapper.appendChild(shaSpan);
                  badgeArea.appendChild(shaWrapper);
                  
                  // Group checks summary badges in a container
                  const checksSummary = createSafeElement('div', { class: 'checks-summary' });
                  
                  const safeChecks = createSafeElement('span', {
                      class: 'check-count safe',
                      title: 'Safe checks'
                  }, `${scan.safeChecks || 0} ✓`);
                  
                  const unsafeChecks = createSafeElement('span', {
                      class: 'check-count unsafe',
                      title: 'Unsafe checks'
                  }, `${scan.unsafeChecks || 0} ⚠️`);
                  
                  // Add checks summary elements
                  checksSummary.appendChild(safeChecks);
                  checksSummary.appendChild(unsafeChecks);
                  badgeArea.appendChild(checksSummary);
                  
                  // Create severity counts with improved visual design
                  const severityCounts = createSafeElement('div', { class: 'severity-counts' });
                  
                  // Add severity counts conditionally with color coding and better display
                  const addSeverityCount = (count, label, className) => {
                      if (count > 0) {
                          const badge = createSafeElement('span', {
                              class: `severity-count ${className}`,
                              title: `${label} issues`
                          }, `${label.charAt(0)}:${count}`);
                          severityCounts.appendChild(badge);
                      }
                  };
                  
                  addSeverityCount(scan.criticalIssues || 0, 'Critical', 'critical');
                  addSeverityCount(scan.highIssues || 0, 'High', 'high');
                  addSeverityCount(scan.mediumIssues || 0, 'Medium', 'medium');
                  addSeverityCount(scan.lowIssues || 0, 'Low', 'low');
                  
                  badgeArea.appendChild(severityCounts);
                  titleGroup.appendChild(badgeArea);
                  
                  // Add title group to scan title
                  scanTitle.appendChild(titleGroup);
                  
                  // Add issue summary with improved styling
                  const issueSummary = createSafeElement('div', { class: 'issue-summary' });
                  
                  const totalIssues = (scan.criticalIssues || 0) + (scan.highIssues || 0) + 
                                     (scan.mediumIssues || 0) + (scan.lowIssues || 0);
                  
                  const issueCount = createSafeElement('span', { class: 'issue-count' }, 
                      `${totalIssues} ${totalIssues === 1 ? 'issue' : 'issues'}`);
                  
                  const expandIcon = createSafeElement('span', { class: 'expand-icon' }, '▼');
                  
                  issueSummary.appendChild(issueCount);
                  issueSummary.appendChild(expandIcon);
                  
                  // Add components to header
                  scanHeader.appendChild(scanTitle);
                  scanHeader.appendChild(issueSummary);
                  
                  scanDiv.appendChild(scanHeader);
                  
                  // Create scan content div (empty, to be filled when expanded)
                  const scanContent = createSafeElement('div', { class: 'scan-content' });
                  
                  scanDiv.appendChild(scanContent);
                  
                  scansContainer.appendChild(scanDiv);
              });
              
              securityIssuesDiv.appendChild(scansContainer);
              
              console.log(`Security data loaded - prepared ${window.allScanNames.length} searchable items`);
          }
      } catch (error) {
          console.error('Error loading security overview:', error);
          if (securityIssuesDiv) {
              // Use DOM methods to create error message
              while (securityIssuesDiv.firstChild) {
                  securityIssuesDiv.removeChild(securityIssuesDiv.firstChild);
              }
              
              const errorElement = createSafeElement('p', { class: 'error' }, 
                                                    `Error loading security overview: ${error.message}`);
              securityIssuesDiv.appendChild(errorElement);
          }
      }
  }
  
  // Load details for a specific security scan
  async function loadSecurityDetails(file, container) {
      try {
          // Show loading state
          while (container.firstChild) {
              container.removeChild(container.firstChild);
          }
          const loadingElement = createSafeElement('div', { class: 'loading' }, 'Loading details...');
          container.appendChild(loadingElement);
  
          // Validate and sanitize file path
          const sanitizedFile = sanitizeFilePath(file);
          if (!sanitizedFile) {
              throw new Error('Invalid file path');
          }
  
          // Fetch data with timeout
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
          
          const resp = await fetch(sanitizedFile, { signal: controller.signal });
          clearTimeout(timeoutId);
          
          if (!resp.ok) throw new Error(`Failed to load details: ${resp.status}`);
          
          // Parse JSON safely
          let data;
          try {
              const rawData = await resp.text();
              
              // Check for unreasonably large payloads
              if (rawData.length > 5 * 1024 * 1024) { // 5MB limit
                  throw new Error('Security details data is too large');
              }
              
              data = JSON.parse(rawData);
              
              // Validate the structure
              if (!validateJsonData(data, 'security')) {
                  throw new Error('Invalid security data format');
              }
          } catch (parseError) {
              throw new Error(`Invalid JSON in security details: ${parseError.message}`);
          }
  
          // Build details DOM safely using document.createElement instead of innerHTML
          while (container.firstChild) {
              container.removeChild(container.firstChild);
          }
          
          // Create metadata section with card-based design
          const metaSection = createSafeElement('div', { class: 'scan-meta card-container' });
          
          // Create metadata card
          const metaCard = createSafeElement('div', { class: 'meta-card' });
          
          // Add card header
          const metaHeader = createSafeElement('div', { class: 'meta-header' });
          const metaTitle = createSafeElement('h4', { class: 'meta-title' }, 'Repository Details');
          metaHeader.appendChild(metaTitle);
          metaCard.appendChild(metaHeader);
          
          // Add card content
          const metaContent = createSafeElement('div', { class: 'meta-content' });
          
          // Helper function to add fields with an improved look
          function addMetaField(parent, label, value) {
              if (value) {
                  const field = createSafeElement('div', { class: 'meta-field' });
                  const labelElem = createSafeElement('div', { class: 'meta-label' }, label);
                  const valueElem = createSafeElement('div', { class: 'meta-value' }, value);
                  field.appendChild(labelElem);
                  field.appendChild(valueElem);
                  parent.appendChild(field);
              }
          }
          
          // Add metadata fields with better organization
          addMetaField(metaContent, 'Repository', data["repo-name"] || "Unknown Repo");
          addMetaField(metaContent, 'Action Name', data["action-name"] || data.repository || "Unknown Action");
          addMetaField(metaContent, 'Version', data.version || "Unknown Version");
          
          // Add SHA with copy functionality
          if (data.SHA) {
              const shaField = createSafeElement('div', { class: 'meta-field' });
              const shaLabel = createSafeElement('div', { class: 'meta-label' }, 'SHA');
              
              const shaValueWrapper = createSafeElement('div', { class: 'sha-value-wrapper' });
              const shaValue = createSafeElement('code', { class: 'meta-value sha-value' }, data.SHA);
              
              // Add copy button
              const copyBtn = createSafeElement('button', { 
                  class: 'copy-btn',
                  title: 'Copy SHA to clipboard' 
              }, '📋');
              
              copyBtn.addEventListener('click', function(e) {
                  e.stopPropagation(); // Prevent event bubbling
                  navigator.clipboard.writeText(data.SHA)
                      .then(() => {
                          // Visual feedback
                          copyBtn.textContent = '✓';
                          setTimeout(() => {
                              copyBtn.textContent = '📋';
                          }, 2000);
                      })
                      .catch(err => {
                          console.error('Failed to copy:', err);
                      });
              });
              
              shaValueWrapper.appendChild(shaValue);
              shaValueWrapper.appendChild(copyBtn);
              
              shaField.appendChild(shaLabel);
              shaField.appendChild(shaValueWrapper);
              metaContent.appendChild(shaField);
          }
          
          // Add latest SHA if different
          if (data.latest && data.latest !== data.SHA) {
              const latestField = createSafeElement('div', { class: 'meta-field' });
              const latestLabel = createSafeElement('div', { class: 'meta-label' }, 'Latest SHA');
              
              const latestValueWrapper = createSafeElement('div', { class: 'sha-value-wrapper' });
              const latestValue = createSafeElement('code', { class: 'meta-value sha-value' }, data.latest);
              
              // Add copy button
              const copyBtn = createSafeElement('button', { 
                  class: 'copy-btn',
                  title: 'Copy latest SHA to clipboard' 
              }, '📋');
              
              copyBtn.addEventListener('click', function(e) {
                  e.stopPropagation(); // Prevent event bubbling
                  navigator.clipboard.writeText(data.latest)
                      .then(() => {
                          // Visual feedback
                          copyBtn.textContent = '✓';
                          setTimeout(() => {
                              copyBtn.textContent = '📋';
                          }, 2000);
                      })
                      .catch(err => {
                          console.error('Failed to copy:', err);
                      });
              });
              
              latestValueWrapper.appendChild(latestValue);
              latestValueWrapper.appendChild(copyBtn);
              
              latestField.appendChild(latestLabel);
              latestField.appendChild(latestValueWrapper);
              metaContent.appendChild(latestField);
          }
          
          // Add risk assessment with visual cue based on severity
          if (data["risk-assessment"]) {
              const riskField = createSafeElement('div', { class: 'meta-field' });
              const riskLabel = createSafeElement('div', { class: 'meta-label' }, 'Risk Assessment');
              
              // Determine risk level for color coding
              let riskLevel = 'medium';
            //   const riskText = data["risk-assessment"].toLowerCase();
            //   if (riskText.includes('critical') || riskText.includes('severe')) {
            //       riskLevel = 'critical';
            //   } else if (riskText.includes('high')) {
            //       riskLevel = 'high';
            //   } else if (riskText.includes('medium') || riskText.includes('moderate')) {
            //       riskLevel = 'medium';
            //   } else if (riskText.includes('low') || riskText.includes('minor')) {
            //       riskLevel = 'low';
            //   } else if (riskText.includes('safe') || riskText.includes('no risk') || riskText.includes('none')) {
            //       riskLevel = 'safe';
            //   }
              
              const riskValue = createSafeElement('div', { 
                  class: `meta-value risk-text ${riskLevel}` 
              }, data["risk-assessment"]);
              
              riskField.appendChild(riskLabel);
              riskField.appendChild(riskValue);
              metaContent.appendChild(riskField);
          }
          
          metaCard.appendChild(metaContent);
          metaSection.appendChild(metaCard);
          container.appendChild(metaSection);
          
          // Get security issues from the data
          const securityIssues = data["Security-Issues"] || data.issues || [];
          
          // Create severity summary card with improved visualization
          if (securityIssues.length > 0) {
              // Create issues section
              const issuesSection = createSafeElement('div', { class: 'issues-section card-container' });
              
              // Add section header
              const issuesHeader = createSafeElement('div', { class: 'section-header' });
              const issuesTitle = createSafeElement('h4', {}, 'Issues Summary');
              issuesHeader.appendChild(issuesTitle);
              issuesSection.appendChild(issuesHeader);
              
              // Create severity summary with better visual representation
          const severitySummary = createSafeElement('div', { class: 'severity-summary' });
          
          // Count issues by severity
          const criticalCount = securityIssues.filter(issue => issue.severity?.toLowerCase() === 'critical').length;
          const highCount = securityIssues.filter(issue => issue.severity?.toLowerCase() === 'high').length;
          const mediumCount = securityIssues.filter(issue => issue.severity?.toLowerCase() === 'medium').length;
          const lowCount = securityIssues.filter(issue => issue.severity?.toLowerCase() === 'low').length;
          
              // Create card-style badges for each severity
              const createSeverityBadge = (count, label, className) => {
                  if (count > 0) {
                      const badge = createSafeElement('div', { 
                          class: `severity-badge ${className}`,
                          title: `${count} ${label} ${count === 1 ? 'issue' : 'issues'}`
                      });
                      
                      const countElem = createSafeElement('span', { class: 'badge-count' }, count.toString());
                      const labelElem = createSafeElement('span', { class: 'badge-label' }, label);
                      
                      badge.appendChild(countElem);
                      badge.appendChild(labelElem);
              severitySummary.appendChild(badge);
          }
              };
              
              createSeverityBadge(criticalCount, 'Critical', 'critical');
              createSeverityBadge(highCount, 'High', 'high');
              createSeverityBadge(mediumCount, 'Medium', 'medium');
              createSeverityBadge(lowCount, 'Low', 'low');
              
              issuesSection.appendChild(severitySummary);
              
              // Create collapsible issues list
              const issuesListContainer = createSafeElement('div', { class: 'issues-list-container' });
              const issuesList = createSafeElement('ul', { class: 'issues-list' });
              
              securityIssues.forEach((issue, index) => {
                  const issueItem = createSafeElement('li', { 
                      class: `issue ${(issue.severity || '').toLowerCase()}`,
                      'data-issue-id': index
                  });
                  
                  // Create issue header (clickable for expanding/collapsing)
                  const issueHeader = createSafeElement('div', { class: 'issue-header' });
                  
                  // Add severity label
                  const severitySpan = createSafeElement('span', { 
                      class: 'severity' 
                  }, issue.severity || 'Unknown');
                  
                  // Add issue title
                  const titleSpan = createSafeElement('span', { 
                      class: 'issue-title' 
                  }, issue.title || issue.description || 'Unnamed issue');
                  
                  // Add expand/collapse icon
                  const expandIcon = createSafeElement('span', { 
                      class: 'issue-expand-icon' 
                  }, '+');
                  
                  issueHeader.appendChild(severitySpan);
                  issueHeader.appendChild(titleSpan);
                  issueHeader.appendChild(expandIcon);
                  
                  // Make header clickable to toggle details
                  issueHeader.addEventListener('click', function(e) {
                      // Mark as custom event to bypass strict validation
                      e._isCustomEvent = true;
                      issueItem.classList.toggle('expanded');
                      expandIcon.textContent = issueItem.classList.contains('expanded') ? '−' : '+';
                  });
                  
                  // Create issue details (initially collapsed)
                  const issueDetails = createSafeElement('div', { class: 'issue-details' });
                  
                  // Add description if available and not used as title
                  if (issue.description && issue.title && issue.description !== issue.title) {
                      const description = createSafeElement('p', { class: 'description' }, issue.description);
                      issueDetails.appendChild(description);
                  }
                  
                  // Add file location if available
                  if (issue.file) {
                      const location = createSafeElement('div', { class: 'location' });
                      
                      const locationLabel = createSafeElement('span', { class: 'location-label' }, 'File:');
                      
                      const code = createSafeElement('code', {}, `${issue.file}${issue.line ? `:${issue.line}` : ''}`);
                      
                      location.appendChild(locationLabel);
                      location.appendChild(document.createTextNode(' '));
                      location.appendChild(code);
                      
                      issueDetails.appendChild(location);
                  }
                  
                  // Add additional issue metadata if available
                  if (issue.cvss) {
                      const cvssInfo = createSafeElement('div', { class: 'cvss-info' });
                      const cvssLabel = createSafeElement('span', { class: 'info-label' }, 'CVSS Score:');
                      const cvssValue = createSafeElement('span', { class: 'info-value' }, issue.cvss);
                      
                      cvssInfo.appendChild(cvssLabel);
                      cvssInfo.appendChild(document.createTextNode(' '));
                      cvssInfo.appendChild(cvssValue);
                      
                      issueDetails.appendChild(cvssInfo);
                  }
                  
                  // Add remediation suggestion if available
                  if (issue.remediation) {
                      const remediation = createSafeElement('div', { class: 'remediation' });
                      const remediationLabel = createSafeElement('div', { class: 'remediation-label' }, 'Suggested Fix:');
                      const remediationText = createSafeElement('p', { class: 'remediation-text' }, issue.remediation);
                      
                      remediation.appendChild(remediationLabel);
                      remediation.appendChild(remediationText);
                      
                      issueDetails.appendChild(remediation);
                  }
                  
                  issueItem.appendChild(issueHeader);
                  issueItem.appendChild(issueDetails);
                  
                  issuesList.appendChild(issueItem);
              });
              
              issuesListContainer.appendChild(issuesList);
              issuesSection.appendChild(issuesListContainer);
              container.appendChild(issuesSection);
          } else {
              // Create "no issues" card with positive messaging
              const noIssuesCard = createSafeElement('div', { class: 'no-issues-card' });
              
              const checkIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
              checkIcon.setAttribute('width', '24');
              checkIcon.setAttribute('height', '24');
              checkIcon.setAttribute('viewBox', '0 0 24 24');
              checkIcon.setAttribute('fill', 'none');
              checkIcon.setAttribute('stroke', 'currentColor');
              checkIcon.setAttribute('stroke-width', '2');
              checkIcon.setAttribute('stroke-linecap', 'round');
              checkIcon.setAttribute('stroke-linejoin', 'round');
              
              const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
              circle.setAttribute('cx', '12');
              circle.setAttribute('cy', '12');
              circle.setAttribute('r', '10');
              
              const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
              path.setAttribute('d', 'M8 12l2 2 6-6');
              
              checkIcon.appendChild(circle);
              checkIcon.appendChild(path);
              
              const noIssuesText = createSafeElement('p', { class: 'no-issues' }, 'No security issues found in this scan.');
              
              noIssuesCard.appendChild(checkIcon);
              noIssuesCard.appendChild(noIssuesText);
              
              container.appendChild(noIssuesCard);
          }
          
          // Add recommendations section with improved styling
          if (data.Recommendations && data.Recommendations.length > 0) {
              const recommendationsSection = createSafeElement('div', { class: 'recommendations-section card-container' });
              
              const recHeader = createSafeElement('div', { class: 'section-header' });
              const recTitle = createSafeElement('h4', {}, 'Recommendations');
              recHeader.appendChild(recTitle);
              recommendationsSection.appendChild(recHeader);
              
              const recommendationsList = createSafeElement('ul', { class: 'recommendations-list' });
              
              data.Recommendations.forEach(rec => {
                  const recText = rec.description || rec.verdict || rec;
                  if (recText) {
                      const recItem = createSafeElement('li', { class: 'recommendation-item' });
                      
                      // Add recommendation icon
                      const recIcon = createSafeElement('span', { class: 'rec-icon' }, '💡');
                      
                      // Add recommendation text
                      const recContent = createSafeElement('span', { class: 'rec-content' }, recText);
                      
                      recItem.appendChild(recIcon);
                      recItem.appendChild(recContent);
                      
                      recommendationsList.appendChild(recItem);
                  }
              });
              
              recommendationsSection.appendChild(recommendationsList);
              container.appendChild(recommendationsSection);
          }
          
          // Add mitigation strategies section with improved styling
          if (data["mitigation-stratagy"] && data["mitigation-stratagy"].length > 0) {
              const mitigationsSection = createSafeElement('div', { class: 'mitigations-section card-container' });
              
              const mitHeader = createSafeElement('div', { class: 'section-header' });
              const mitTitle = createSafeElement('h4', {}, 'Mitigation Strategy');
              mitHeader.appendChild(mitTitle);
              mitigationsSection.appendChild(mitHeader);
              
              const mitigationsList = createSafeElement('ul', { class: 'mitigations-list' });
              
              data["mitigation-stratagy"].forEach(mit => {
                  const mitText = mit.description || mit;
                  if (mitText) {
                      const mitItem = createSafeElement('li', { class: 'mitigation-item' });
                      
                      // Add mitigation icon
                      const mitIcon = createSafeElement('span', { class: 'mit-icon' }, '🛡️');
                      
                      // Add mitigation text
                      const mitContent = createSafeElement('span', { class: 'mit-content' }, mitText);
                      
                      mitItem.appendChild(mitIcon);
                      mitItem.appendChild(mitContent);
                      
                      mitigationsList.appendChild(mitItem);
                  }
              });
              
              mitigationsSection.appendChild(mitigationsList);
              container.appendChild(mitigationsSection);
          }
          
          // Add security checks section with interactive elements
          if (data.checks && data.checks.length > 0) {
              const checksSection = createSafeElement('div', { class: 'checks-section card-container' });
              
              const checksHeader = createSafeElement('div', { class: 'section-header' });
              const checksTitle = createSafeElement('h4', {}, 'Security Checks');
              checksHeader.appendChild(checksTitle);
              checksSection.appendChild(checksHeader);
              
              const checksList = createSafeElement('div', { class: 'checks-list' });
              
              data.checks.forEach((check, index) => {
                  const checkItem = createSafeElement('div', { 
                      class: `check-item ${(check.status || '').toLowerCase()}`,
                      'data-check-id': index
                  });
                  
                  // Create header for each check (clickable for expanding/collapsing)
                  const checkHeader = createSafeElement('div', { class: 'check-header' });
                  
                  // Title area
                  const titleArea = createSafeElement('div', { class: 'check-title-area' });
                  
                  const idSpan = createSafeElement('span', { class: 'check-id' }, `#${check.id || "N/A"}`);
                  
                  const titleSpan = createSafeElement('span', { class: 'check-title' }, check.title || "Untitled Check");
                  
                  titleArea.appendChild(idSpan);
                  titleArea.appendChild(titleSpan);
                  
                  // Status area
                  const statusArea = createSafeElement('div', { class: 'check-status-area' });
                  
                  const statusSpan = createSafeElement('span', { class: 'check-status' }, check.status || "Unknown");
                  
                  const scoreSpan = createSafeElement('span', { class: 'check-score' }, check.score || "N/A");
                  
                  // Add expand/collapse icon
                  const expandCheck = createSafeElement('span', { class: 'check-expand-icon' }, '+');
                  
                  statusArea.appendChild(statusSpan);
                  statusArea.appendChild(scoreSpan);
                  statusArea.appendChild(expandCheck);
                  
                  // Add title and status areas to header
                  checkHeader.appendChild(titleArea);
                  checkHeader.appendChild(statusArea);
                  
                  // Make header clickable to toggle analysis
                  checkHeader.addEventListener('click', function(e) {
                      // Mark as custom event to bypass strict validation
                      e._isCustomEvent = true;
                      checkItem.classList.toggle('expanded');
                      expandCheck.textContent = checkItem.classList.contains('expanded') ? '−' : '+';
                  });
                  
                  // Add analysis content (initially collapsed)
                  const analysisDiv = createSafeElement('div', { class: 'check-analysis' }, 
                                                         check.analysis || "No analysis provided");
                  
                  // Assemble the check item
                  checkItem.appendChild(checkHeader);
                  checkItem.appendChild(analysisDiv);
                  
                  checksList.appendChild(checkItem);
              });
              
              checksSection.appendChild(checksList);
              container.appendChild(checksSection);
          }
      } catch (error) {
          console.error('Error loading security details:', error);
          while (container.firstChild) {
              container.removeChild(container.firstChild);
          }
          const errorElement = createSafeElement('p', { class: 'error' }, 
                                                `Error loading details: ${error.message}`);
          container.appendChild(errorElement);
      }
  }
  
  // Enhanced createSafeElement function
  function createSafeElement(tag, attributes = {}, textContent = '') {
      if (!/^[a-zA-Z0-9-]+$/.test(tag)) {
          console.error('Invalid tag name:', tag);
          return document.createDocumentFragment();
      }
      
      const element = document.createElement(tag);
      
      // Set attributes safely
      for (const [key, value] of Object.entries(attributes)) {
          // Skip unsafe properties
          if (['innerHTML', 'outerHTML', 'onclick', 'onmouseover', 'onload'].includes(key) || 
              /^on\w+$/.test(key)) continue;
          
          if (key === 'style' && typeof value === 'string') {
              // Apply style properties individually for better safety
              const safeStyles = value.split(';').filter(Boolean);
              for (const styleItem of safeStyles) {
                  const [prop, val] = styleItem.split(':').map(s => s.trim());
                  if (prop && val) {
                      element.style[prop] = val;
                  }
              }
          } else {
              element.setAttribute(key, value);
          }
      }
      
      // Set text content safely
      if (textContent) {
          element.textContent = textContent;
      }
      
      return element;
  }
  
  // Add CSRF token generation
  function generateCSRFToken() {
      // Generate a random token
      const array = new Uint8Array(16);
      window.crypto.getRandomValues(array);
      const token = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
      
      // Store in sessionStorage
      sessionStorage.setItem('csrfToken', token);
      return token;
  }
  
  // Use the token when making fetch requests to your server
  async function fetchWithCSRF(url, options = {}) {
      const csrfToken = sessionStorage.getItem('csrfToken') || generateCSRFToken();
      
      const headers = options.headers || {};
      headers['X-CSRF-Token'] = csrfToken;
      
      return fetch(url, {
          ...options,
          headers
      });
  }
  
  // Keep only one document click handler outside of other event handlers
  document.addEventListener('click', function(e) {
    // Basic validation - accept trusted events or our custom marked events
    if (!e || (e.isTrusted === false && !e._isCustomEvent)) {
      console.warn('Skipping document click due to invalid event');
      return;
    }
    
    const suggestions = document.getElementById('search-suggestions');
    if (suggestions && !e.target.closest('.search-wrapper')) {
      suggestions.classList.remove('active');
    }
  });
  
  // Calculate total security issues by severity
  function calculateTotalSecurityIssues(overviewData) {
      if (!Array.isArray(overviewData)) {
          return { 
              criticalCount: 0, 
              highCount: 0, 
              mediumCount: 0, 
              lowCount: 0,
              totalIssues: 0
          };
      }
      
      const totalStats = {
          criticalCount: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          totalIssues: 0
      };
      
      overviewData.forEach(scan => {
          if (scan && typeof scan === 'object') {
              totalStats.criticalCount += scan.criticalIssues || 0;
              totalStats.highCount += scan.highIssues || 0;
              totalStats.mediumCount += scan.mediumIssues || 0;
              totalStats.lowCount += scan.lowIssues || 0;
          }
      });
      
      totalStats.totalIssues = totalStats.criticalCount + totalStats.highCount + 
                              totalStats.mediumCount + totalStats.lowCount;
      
      return totalStats;
  }
  
  // Create an empty security overview data structure
  function createEmptySecurityOverview() {
      return [
          {
              repoName: "example/example-action",
              actionName: "example-action",
              file: "output/example-action.json",
              sha: "0000000000000000000000000000000000000000",
              safeChecks: 3,
              unsafeChecks: 0,
              criticalIssues: 0,
              highIssues: 0,
              mediumIssues: 0,
              lowIssues: 0
          }
      ];
  }
  
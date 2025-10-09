// Add frame protection at the top of the file
(function() {
  // Prevent this page from being embedded in iframes from other origins
  if (window.top !== window.self) {
    try {
      // Check if parent is from a different origin
      window.top.location.origin;
    } catch (e) {
      // If error occurs, parent is from different origin
      // Replace entire page with error message using safe DOM methods
      while (document.body.firstChild) {
        document.body.removeChild(document.body.firstChild);
      }
      
      const errorHeading = document.createElement('h1');
      errorHeading.textContent = 'Security Error';
      
      const errorMessage = document.createElement('p');
      errorMessage.textContent = 'This page cannot be displayed in a frame from a different origin.';
      
      document.body.appendChild(errorHeading);
      document.body.appendChild(errorMessage);
      
      throw new Error('X-Frame-Options: This page cannot be framed by a different origin');
    }
  }
})();

// Add these security helper functions at the top of the file
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

// Helper function to safely set HTML content
function createSafeElement(tag, attributes = {}, textContent = '') {
    const element = document.createElement(tag);
    
    // Set attributes
    for (const [key, value] of Object.entries(attributes)) {
        if (key !== 'innerHTML' && key !== 'outerHTML') {
            element.setAttribute(key, value);
        }
    }
    
    // Set text content safely
    if (textContent) {
        element.textContent = textContent;
    }
    
    return element;
}

// Ensure JSON is properly structured
function validateRepositoryData(data) {
    if (!data || typeof data !== 'object') return false;
    
    // Check if at least one key has valid repository property
    const hasValidKeys = Object.keys(data).some(key => {
        const entry = data[key];
        // Check if the entry is an object with a repository property
        if (entry && typeof entry === 'object' && entry.repository) {
            // At minimum, we need a name
            return entry.repository.name || entry.repository.full_name;
        }
        return false;
    });
    
    return hasValidKeys;
}

// Define a whitelist of trusted origins
const TRUSTED_ORIGINS = [
  window.location.origin, // Same origin
  'https://ai-gha-scanner-f53106.gitlab.io'
];

// Helper function to check if an origin is trusted
function isOriginTrusted(origin) {
  return TRUSTED_ORIGINS.includes(origin);
}

// Add a safe JSON parsing function
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

// Helper function to validate events for security
function validateEvent(event, expectedTarget = null) {
  // Check if the event is trusted (created by user action, not programmatically)
  if (event.isTrusted === false) {
    console.warn('Untrusted event detected');
    return false;
  }
  
  // Validate the event target if one is expected
  if (expectedTarget && event.target !== expectedTarget) {
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

// Update the DOMContentLoaded event handler
document.addEventListener('DOMContentLoaded', function(event) {
  // Validate the event
  if (!validateEvent(event)) {
    console.error('Invalid DOMContentLoaded event');
    return;
  }
  
  // Check if we're in the expected origin
  if (window.location.origin !== TRUSTED_ORIGINS[0] && 
      !TRUSTED_ORIGINS.includes(window.location.origin)) {
    console.warn('Running in untrusted origin:', window.location.origin);
  }
  
  // Proceed with app initialization
  loadData();
});

async function loadData() {
  const metadataDiv = document.getElementById('metadata');
  const securityIssuesDiv = document.getElementById('security-issues');
  const searchInput = document.getElementById('action-search');
  const searchSuggestions = document.getElementById('search-suggestions');
  
  // Show loading indicators
  while (metadataDiv.firstChild) {
    metadataDiv.removeChild(metadataDiv.firstChild);
  }
  
  const loadingDiv = createSafeElement('div', { class: 'loading' }, 'Loading repository data...');
  metadataDiv.appendChild(loadingDiv);
  
  try {
    // Add timeout for fetch operations
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
    
    let statsData;
    try {
    const statsResp = await fetch('action-stats.json', { signal: controller.signal });
    clearTimeout(timeoutId);
    
      if (!statsResp.ok) {
        console.warn(`Failed to load metadata: ${statsResp.status}. Using empty data structure.`);
        statsData = createEmptyDataStructure();
      } else {
    // Safely parse JSON
    try {
        const rawData = await statsResp.text();
        
        // Check for unreasonably large payloads
        if (rawData.length > 10 * 1024 * 1024) { // 10MB limit
            throw new Error('Response too large');
        }
        
          try {
        statsData = JSON.parse(rawData);
          } catch (jsonError) {
            console.error('JSON parse error details:', jsonError);
            // Try to identify specific syntax errors in the JSON
            const errorMatch = jsonError.message.match(/at position (\d+)/);
            if (errorMatch && errorMatch[1]) {
              const errorPos = parseInt(errorMatch[1]);
              const errorContext = rawData.substring(
                Math.max(0, errorPos - 50), 
                Math.min(rawData.length, errorPos + 50)
              );
              console.error(`JSON error near position ${errorPos}:`, errorContext);
            }
            
            console.warn(`Failed to parse response: ${jsonError.message}. Using empty data structure.`);
            statsData = createEmptyDataStructure();
          }
          
          if (!statsData) {
            console.warn('Invalid JSON response (null or undefined). Using empty data structure.');
            statsData = createEmptyDataStructure();
          }
        } catch (jsonError) {
          console.warn(`Failed to process response: ${jsonError.message}. Using empty data structure.`);
          statsData = createEmptyDataStructure();
        }
      }
    } catch (fetchError) {
      console.warn(`Fetch error: ${fetchError.message}. Using empty data structure.`);
      statsData = createEmptyDataStructure();
    }
    
    // Validate the data structure
    if (!validateRepositoryData(statsData)) {
      console.warn('Invalid data structure. Using empty data structure.');
      statsData = createEmptyDataStructure();
    }
    
    // Remove loading indicator
    metadataDiv.removeChild(loadingDiv);
    
    // Create summary section
    const summarySection = createSafeElement('section', { class: 'summary-section' });
    const summaryTitle = createSafeElement('h2', {}, 'Security Overview');
    summarySection.appendChild(summaryTitle);
    
    // Calculate totals for summary statistics
    let totalActions = 0;
    let totalReleases = 0;
    let totalScanned = 0;
    let totalSafe = 0;
    let totalUnsafe = 0;
    let criticalIssues = 0;
    let highIssues = 0;
    let mediumIssues = 0;
    let lowIssues = 0;
    
    // Process data to get totals
    Object.keys(statsData).forEach(key => {
      const repoData = statsData[key];
      if (repoData) {
        totalActions++;
        
        // Ensure releases is always an array
        if (!repoData.releases) {
          repoData.releases = [];
          console.warn(`No releases found for key: ${key}`);
        } else if (!Array.isArray(repoData.releases)) {
          // Handle case where releases is an object but not an array
          // console.warn(`Releases is not an array for key: ${key}. Converting to array.`);
          
          // If it's an object with numeric keys, try to convert it to an array
          if (typeof repoData.releases === 'object') {
            try {
              // Universal approach for all repositories with object-based releases
              const tags = Object.keys(repoData.releases);
              const releaseArray = [];
              
              // Convert each key-value pair to a proper release object
              tags.forEach(tag => {
                const releaseData = repoData.releases[tag];
                // Skip null or undefined entries
                if (!releaseData) return;
                
                // Create a properly structured release object with explicit fields
                const release = {
                  version: tag,
                  published_at: releaseData.published_date || new Date().toISOString(),
                  scanned: releaseData.scanned || false,
                  latest: releaseData.latest || "",
                  sha: Array.isArray(releaseData.sha) ? releaseData.sha : [releaseData.sha || ""],
                  safe: releaseData.safe || false,
                  scan_report: releaseData.scan_report || null,
                  securityData: {
                    status: releaseData.safe ? 'safe' : 'not-scanned',
                    issues: []
                  }
                };
                
                releaseArray.push(release);
              });
              
              if (releaseArray.length > 0) {
                // Sort by published date (newest first)
                releaseArray.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
                repoData.releases = releaseArray;
              } else {
                repoData.releases = [];
              }
            } catch (e) {
              console.error(`Failed to convert releases for ${key} to array:`, e);
              repoData.releases = [];
            }
          } else {
            repoData.releases = [];
          }
        }
        
        // Now we can safely work with releases as an array
        totalReleases += repoData.releases.length;
        
        repoData.releases.forEach(release => {
          if (release && release.scanned) {
            totalScanned++;
            if (release.safe) {
              totalSafe++;
            } else {
              totalUnsafe++;
            }
          }
        });
      }
    });
    
    // Create summary stats
    const summaryStats = createSafeElement('div', { class: 'summary-stats' });
    
    const statItems = [
      { label: 'Actions Scanned', value: totalActions, class: 'info' },
      { label: 'Total Releases', value: totalReleases, class: 'info' },
      { label: 'Releases Analyzed', value: totalSafe, class: 'low' },
      // { label: 'Unsafe Actions', value: totalUnsafe, class: 'critical' },
      // { label: 'Critical Issues', value: criticalIssues, class: 'critical' },
      // { label: 'High Issues', value: highIssues, class: 'high' },
      // { label: 'Medium Issues', value: mediumIssues, class: 'medium' },
      // { label: 'Low Issues', value: lowIssues, class: 'low' }
    ];
    
    statItems.forEach(item => {
      const statItem = createSafeElement('div', { class: `stat-item ${item.class}` });
      const statLabel = createSafeElement('div', { class: 'stat-label' }, item.label);
      const statValue = createSafeElement('div', { class: 'stat-value' }, String(item.value));
      
      statItem.appendChild(statLabel);
      statItem.appendChild(statValue);
      summaryStats.appendChild(statItem);
    });
    
    summarySection.appendChild(summaryStats);
    metadataDiv.appendChild(summarySection);
    
    // Setup search functionality
    if (searchInput) {
      // Create an array of all actions for searching
      const allActions = [];
      
      Object.keys(statsData).forEach(key => {
        const actionData = statsData[key];
        const actionName = actionData && actionData.repository ? actionData.repository.full_name : key;
        const fullName = actionData && actionData.repository ? actionData.repository.full_name : key;
        
        allActions.push({
          id: key,
          name: actionName || key,
          fullName: fullName || actionName || key
        });
      });
      
      // Setup search input event listeners
      searchInput.addEventListener('input', function(event) {
        if (!validateEvent(event, searchInput)) return;
        
        const query = sanitizeSearchInput(searchInput.value).toLowerCase();
        
        if (query.length < 2) {
          searchSuggestions.classList.remove('active');
          return;
        }
        
        // Filter actions matching the query
        const filteredActions = allActions.filter(action => 
          (action.name && action.name.toLowerCase().includes(query)) || 
          (action.fullName && action.fullName.toLowerCase().includes(query))
        ).slice(0, 10); // Limit to 10 results
        
        // Clear previous suggestions
        while (searchSuggestions.firstChild) {
          searchSuggestions.removeChild(searchSuggestions.firstChild);
        }
        
        if (filteredActions.length === 0) {
          const noResults = createSafeElement('div', { class: 'no-suggestions' }, 'No matching actions found');
          searchSuggestions.appendChild(noResults);
        } else {
          filteredActions.forEach(action => {
            const suggestionItem = createSafeElement('div', { 
              class: 'suggestion-item',
              'data-id': action.id
            }, action.fullName || action.name || action.id);
            
            suggestionItem.addEventListener('click', function(clickEvent) {
              if (!validateEvent(clickEvent, suggestionItem)) return;
              
              searchInput.value = action.fullName || action.name || action.id;
              searchSuggestions.classList.remove('active');
              
              // Scroll to the action card
              const actionCard = document.querySelector(`.card[data-id="${action.id}"]`);
              if (actionCard) {
                actionCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
                // Highlight the card briefly
                actionCard.classList.add('highlight');
                setTimeout(() => {
                  actionCard.classList.remove('highlight');
                }, 2000);
              }
            });
            
            searchSuggestions.appendChild(suggestionItem);
          });
        }
        
        searchSuggestions.classList.add('active');
      });
      
      // Handle click outside to close suggestions
      document.addEventListener('click', function(event) {
        if (!validateEvent(event)) return;
        
        if (!searchInput.contains(event.target) && !searchSuggestions.contains(event.target)) {
          searchSuggestions.classList.remove('active');
        }
      });
      
      // Handle escape key to close suggestions
      searchInput.addEventListener('keydown', function(event) {
        if (!validateEvent(event, searchInput)) return;
        
        if (event.key === 'Escape') {
          searchSuggestions.classList.remove('active');
        }
      });
    }
    
    // Create action cards container
    const actionCardsContainer = createSafeElement('div', { class: 'actions-grid' });
    
    // Build the action cards
    Object.keys(statsData).forEach(key => {
      try {
        const actionData = statsData[key];
        
        // Ensure the repository object exists
        if (!actionData.repository || typeof actionData.repository !== 'object') {
          actionData.repository = {
            name: key,
            full_name: key,
            description: 'No repository information available',
            stars: 0,
            issues: 0,
            contributors: 0,
            owner: { login: 'unknown' }
          };
        } else {
          // Map to consistent property names
          actionData.repository.stars = actionData.repository.stars || 
                                        actionData.repository.stargazers_count || 0;
          actionData.repository.issues = actionData.repository.issues || 
                                         actionData.repository.open_issues_count || 
                                         actionData.repository.issues_count || 0;
          actionData.repository.contributors = actionData.repository.contributors || 
                                                actionData.repository.contributors_count || 0;
        }
        
        const repository = actionData.repository;
        
        // Ensure releases is always an array
        if (!actionData.releases) {
          actionData.releases = [];
        } else if (!Array.isArray(actionData.releases)) {
          // If releases is an object but not an array, convert it
          if (typeof actionData.releases === 'object') {
            try {
              // Universal approach for all repositories with object-based releases
              const tags = Object.keys(actionData.releases);
              const releaseArray = [];
              
              // Convert each key-value pair to a proper release object
              tags.forEach(tag => {
                const releaseData = actionData.releases[tag];
                // Skip null or undefined entries
                if (!releaseData) return;
                
                // Create a properly structured release object
                const release = {
                  version: tag,
                  published_at: releaseData.published_date || new Date().toISOString(),
                  scanned: releaseData.scanned || false,
                  latest: releaseData.latest || "",
                  sha: Array.isArray(releaseData.sha) ? releaseData.sha : [releaseData.sha || ""],
                  safe: releaseData.safe || false,
                  scan_report: releaseData.scan_report || null,
                  securityData: {
                    status: releaseData.safe ? 'safe' : 'not-scanned',
                    issues: []
                  }
                };
                
                releaseArray.push(release);
              });
              
              if (releaseArray.length > 0) {
                // Sort by published date (newest first)
                releaseArray.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
                actionData.releases = releaseArray;
              } else {
                actionData.releases = [];
              }
            } catch (e) {
              console.error(`Failed to convert releases for ${key} to array in card building:`, e);
              actionData.releases = [];
            }
          } else {
            actionData.releases = [];
          }
        }
        
        const releases = actionData.releases;
        
        // Skip if missing essential data
        if (!repository.name) return;
        
        // Create card element
        const card = createSafeElement('div', { 
          class: 'card action-card',
          'data-id': key
        });
        
        // Card header
        const cardHeader = createSafeElement('div', { class: 'card-header' });
        
        // Repository title and stars in first row
        const headerFirstRow = createSafeElement('div', { class: 'header-row' });
        
        // Repository name
        const repoName = createSafeElement('h3', { class: 'card-title' }, 
          repository.full_name || key
        );
        headerFirstRow.appendChild(repoName);
        
        // Stars badge if available
        if (repository.stars !== undefined) {
          const starsContainer = createSafeElement('div', { class: 'stars' });
          
          // Star icon
          const starIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
          starIcon.setAttribute('width', '16');
          starIcon.setAttribute('height', '16');
          starIcon.setAttribute('viewBox', '0 0 16 16');
          starIcon.setAttribute('fill', 'currentColor');
          
          const starPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          starPath.setAttribute('d', 'M8 0.25a0.75 0.75 0 0 1 0.673 0.418l1.882 3.815 4.21 0.612a0.75 0.75 0 0 1 0.416 1.279l-3.046 2.97 0.719 4.192a0.75 0.75 0 0 1-1.088 0.791L8 12.347l-3.766 1.98a0.75 0.75 0 0 1-1.088-0.79l0.72-4.194-3.047-2.969a0.75 0.75 0 0 1 0.416-1.28l4.21-0.61 1.883-3.815A0.75 0.75 0 0 1 8 0.25z');
          
          starIcon.appendChild(starPath);
          starsContainer.appendChild(starIcon);
          
          const starsCount = createSafeElement('span', { class: 'count' }, 
            repository.stars.toLocaleString()
          );
          starsContainer.appendChild(starsCount);
          
          headerFirstRow.appendChild(starsContainer);
        }
        
        cardHeader.appendChild(headerFirstRow);
        
        // Repository metadata
        const repoMetadata = createSafeElement('div', { class: 'repo-metadata' });
        
        // Owner information
        if (repository.owner) {
          const ownerInfo = createSafeElement('div', { class: 'repo-info-item' });
          const ownerLabel = createSafeElement('span', { class: 'info-label' }, 'Owner:');
          const ownerValue = createSafeElement('span', { class: 'info-value' }, 
            typeof repository.owner === 'string' ? repository.owner : repository.owner.login || repository.owner || 'unknown'
          );
          
          ownerInfo.appendChild(ownerLabel);
          ownerInfo.appendChild(ownerValue);
          repoMetadata.appendChild(ownerInfo);
        }
        
        // Created date
        if (repository.created_at) {
          try {
            const createdDate = new Date(repository.created_at);
            if (!isNaN(createdDate)) {
              const createdInfo = createSafeElement('div', { class: 'repo-info-item' });
              const createdLabel = createSafeElement('span', { class: 'info-label' }, 'Created:');
              
              // Format date as DD/MM/YYYY for consistency
              const day = createdDate.getDate();
              const month = createdDate.getMonth() + 1;
              const year = createdDate.getFullYear();
              const formattedDate = `${day}/${month}/${year}`;
              
              // Create date span with significant margin-left for spacing
              const dateText = createSafeElement('span', { 
                class: 'date'
              }, formattedDate);
              
              createdInfo.appendChild(createdLabel);
              createdInfo.appendChild(dateText);
              repoMetadata.appendChild(createdInfo);
            }
          } catch (e) {
            console.warn(`Error parsing created_at date for ${key}`);
          }
        }
        
        // Issues count
        if (repository.issues !== undefined) {
          const issuesInfo = createSafeElement('div', { class: 'repo-info-item' });
          const issuesLabel = createSafeElement('span', { class: 'info-label' }, 'Issues:');
          const issuesValue = createSafeElement('span', { class: 'info-value' }, 
            repository.issues.toString()
          );
          
          issuesInfo.appendChild(issuesLabel);
          issuesInfo.appendChild(issuesValue);
          repoMetadata.appendChild(issuesInfo);
        }
        
        // Contributors count
        if (repository.contributors !== undefined) {
          const contributorsInfo = createSafeElement('div', { class: 'repo-info-item' });
          const contributorsLabel = createSafeElement('span', { class: 'info-label' }, 'Contributors:');
          const contributorsValue = createSafeElement('span', { class: 'info-value' }, 
            repository.contributors.toString()
          );
          
          contributorsInfo.appendChild(contributorsLabel);
          contributorsInfo.appendChild(contributorsValue);
          repoMetadata.appendChild(contributorsInfo);
        }
        
        cardHeader.appendChild(repoMetadata);
        
        // Description if available
        if (repository.description) {
          const description = createSafeElement('div', { class: 'repo-description' }, repository.description);
          cardHeader.appendChild(description);
        }
        
        card.appendChild(cardHeader);
        
        // Card body
        const cardBody = createSafeElement('div', { class: 'card-body' });
        
        // Security statistics section
        const securityStats = createSafeElement('div', { class: 'security-stats' });
        
        // Count releases by security status
        let safeCount = 0;
        let unsafeCount = 0;
        let notScannedCount = 0;
        
        releases.forEach(release => {
          if (release.scanned) {
            if (release.safe) safeCount++;
            else unsafeCount++;
                    } else {
            notScannedCount++;
          }
        });
        
        // Release count information
        const releasesInfo = createSafeElement('div', { class: 'd-flex justify-between mb-md' });
        const releasesLabel = createSafeElement('div', { class: 'section-title' }, 'Releases');
        const releasesCount = createSafeElement('div', { class: 'count' }, 
          `${releases.length} total`
        );
        
        releasesInfo.appendChild(releasesLabel);
        releasesInfo.appendChild(releasesCount);
        
        cardBody.appendChild(releasesInfo);
        
        // Add scan status indicators
        const scanCount = safeCount + unsafeCount;
        const scanDisplay = createSafeElement('div', { class: 'scan-count' }, 
          `${scanCount}/${releases.length} SCANNED`
        );
        
        cardBody.appendChild(scanDisplay);
        
        // Releases section
        const releasesSection = createSafeElement('div', { class: 'releases-section' });
        
        // Sort releases to have scanned releases first, then by date
        const sortedReleases = [...releases].sort((a, b) => {
          // First sort by scan status
          if (a.scanned && !b.scanned) return -1;
          if (!a.scanned && b.scanned) return 1;
          
          // Then sort by date (newest first)
          return new Date(b.published_at) - new Date(a.published_at);
        });
        
        // Create scrollable container for all releases
        const releasesList = createSafeElement('ul', { class: 'releases-list scrollable' });
        
        // Display all releases in the scrollable container
        sortedReleases.forEach(release => {
          // Skip if release is null or undefined
          if (!release) return;
          
          // Create a CSS class based on security status
          let statusClass = release.scanned ? (release.safe ? 'safe' : 'unsafe') : 'not-scanned';
          let statusText = release.scanned ? 'SCANNED' : 'NOT SCANNED';
          
          const releaseItem = createSafeElement('li', { 
            class: `release-item ${statusClass}`,
            'data-id': `${key}-${release.version || 'unknown'}`
          });
          
          const releaseInfo = createSafeElement('div', { class: 'release-info' });
          
          // Version and release date
          const versionInfo = createSafeElement('div', { class: 'version-info' });
          const versionText = createSafeElement('span', { 
            class: 'version',
            title: 'View release details'
          }, release.version || 'Unknown version');
          
          versionInfo.appendChild(versionText);
          
          if (release.published_at) {
            const publishDate = new Date(release.published_at);
            if (!isNaN(publishDate)) {
              // Format date as DD/MM/YYYY for consistency
              const day = publishDate.getDate();
              const month = publishDate.getMonth() + 1;
              const year = publishDate.getFullYear();
              const formattedDate = `${day}/${month}/${year}`;
              
              // Create date span with significant margin-left for spacing
              const dateText = createSafeElement('span', { 
                class: 'date'
              }, formattedDate);
              
              // Directly append the date without text node separator
              versionInfo.appendChild(dateText);
            }
          }
          
          releaseInfo.appendChild(versionInfo);
          releaseItem.appendChild(releaseInfo);
          
          // Status indicator
          const statusIndicator = createSafeElement('div', { class: 'status-indicator' });
          
          // Add status badge
          const statusBadge = createSafeElement('span', { 
            class: `badge badge-${statusClass}`
          }, statusText);
          
          statusIndicator.appendChild(statusBadge);
          
          // Add details button
          const detailsBtn = createSafeElement('button', { 
            class: 'btn btn-icon details-btn',
            title: 'View details',
            'aria-label': 'View release details'
          });
          
          // Info icon
          const infoIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
          infoIcon.setAttribute('width', '16');
          infoIcon.setAttribute('height', '16');
          infoIcon.setAttribute('viewBox', '0 0 24 24');
          infoIcon.setAttribute('fill', 'none');
          infoIcon.setAttribute('stroke', 'currentColor');
          infoIcon.setAttribute('stroke-width', '2');
          infoIcon.setAttribute('stroke-linecap', 'round');
          infoIcon.setAttribute('stroke-linejoin', 'round');
          
          const circlePath = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
          circlePath.setAttribute('cx', '12');
          circlePath.setAttribute('cy', '12');
          circlePath.setAttribute('r', '10');
          
          const line1 = document.createElementNS('http://www.w3.org/2000/svg', 'line');
          line1.setAttribute('x1', '12');
          line1.setAttribute('y1', '16');
          line1.setAttribute('x2', '12');
          line1.setAttribute('y2', '12');
          
          const line2 = document.createElementNS('http://www.w3.org/2000/svg', 'line');
          line2.setAttribute('x1', '12');
          line2.setAttribute('y1', '8');
          line2.setAttribute('x2', '12.01');
          line2.setAttribute('y2', '8');
          
          infoIcon.appendChild(circlePath);
          infoIcon.appendChild(line1);
          infoIcon.appendChild(line2);
          
          detailsBtn.appendChild(infoIcon);
          statusIndicator.appendChild(detailsBtn);
          
          // Add release details modal handler
          detailsBtn.addEventListener('click', function(event) {
            // Don't validate the event target here, just check if it's trusted
            if (!event.isTrusted) return;
            
            event.preventDefault();
            event.stopPropagation();
            
            // Create modal
            const modal = createSafeElement('div', { class: 'modal-overlay' });
            
            // Create modal content
            const modalContent = createSafeElement('div', { class: 'modal' });
            
            // Modal header
            const modalHeader = createSafeElement('div', { class: 'modal-header' });
            const modalTitle = createSafeElement('h4', { class: 'modal-title' }, 
              `Release: ${release.version}`
            );
            const closeBtn = createSafeElement('button', { 
              class: 'modal-close',
              'aria-label': 'Close'
            }, '×');
            
            modalHeader.appendChild(modalTitle);
            modalHeader.appendChild(closeBtn);
            modalContent.appendChild(modalHeader);
            
            // Modal body
            const modalBody = createSafeElement('div', { class: 'modal-body' });
            
            // Details list
            const detailsList = createSafeElement('div', { class: 'details-list' });
            
            // Add release info
            if (release.published_at) {
              const publishDate = new Date(release.published_at);
              if (!isNaN(publishDate)) {
                const dateDetail = createSafeElement('div', { class: 'd-flex justify-between mb-sm' });
                const dateLabel = createSafeElement('span', { class: 'text-bold' }, 'Released:');
                
                // Format as shown in screenshot with date and time
                const options = { 
                  year: 'numeric', 
                  month: '2-digit', 
                  day: '2-digit',
                  hour: '2-digit',
                  minute: '2-digit', 
                  hour12: true 
                };
                const dateValue = createSafeElement('span', {}, publishDate.toLocaleString(undefined, options));
                
                dateDetail.appendChild(dateLabel);
                dateDetail.appendChild(dateValue);
                detailsList.appendChild(dateDetail);
              }
            }
            
            // SHA
            if (release.sha && release.sha.length > 0) {
              const shaDetail = createSafeElement('div', { class: 'd-flex flex-wrap mb-sm' });
              const shaLabel = createSafeElement('span', { class: 'text-bold' }, 'SHA:');
              shaDetail.appendChild(shaLabel);
              
              const shaValue = createSafeElement('div', { class: 'sha-box' }, release.sha[0] || '');
              shaDetail.appendChild(shaValue);
              
              detailsList.appendChild(shaDetail);
            }
            
            // Latest SHA if different
            if (release.latest) {
              const latestShaDetail = createSafeElement('div', { class: 'd-flex flex-wrap mb-sm' });
              const latestShaLabel = createSafeElement('span', { class: 'text-bold' }, 'Latest SHA:');
              latestShaDetail.appendChild(latestShaLabel);
              
              const latestShaValue = createSafeElement('div', { class: 'sha-box' }, release.latest || '');
              latestShaDetail.appendChild(latestShaValue);
              
              detailsList.appendChild(latestShaDetail);
            }
            
            // Status
            const statusDetail = createSafeElement('div', { class: 'd-flex justify-between mb-sm' });
            const statusLabel = createSafeElement('span', { class: 'text-bold' }, 'Status:');
            
            let statusValue;
            if (release.scanned) {
              if (release.safe) {
                statusValue = createSafeElement('span', { class: 'text-success' }, 'Safe version - verified');
            } else {
                statusValue = createSafeElement('span', { class: 'text-danger' }, 'Potentially unsafe');
              }
            } else {
              statusValue = createSafeElement('span', { class: 'text-tertiary' }, 'Not scanned');
            }
            
            statusDetail.appendChild(statusLabel);
            statusDetail.appendChild(statusValue);
            detailsList.appendChild(statusDetail);
            
            // Scanned status
            const scannedDetail = createSafeElement('div', { class: 'd-flex justify-between mb-sm' });
            const scannedLabel = createSafeElement('span', { class: 'text-bold' }, 'Scanned:');
            const scannedValue = createSafeElement('span', {}, release.scanned ? 'Yes' : 'No');
            
            scannedDetail.appendChild(scannedLabel);
            scannedDetail.appendChild(scannedValue);
            detailsList.appendChild(scannedDetail);
            
            // Add scan report link if available
            if (release.scan_report && release.scanned) {
              const scanReportDetail = createSafeElement('div', { class: 'd-flex justify-between mb-sm' });
              const scanReportLabel = createSafeElement('span', { class: 'text-bold' }, 'Scan Report:');
              
              // Create a link to view the detailed analysis
              const reportUrl = new URL('action-report.html', window.location.href);
              reportUrl.searchParams.set('report', release.scan_report);
              reportUrl.searchParams.set('name', actionData.name || key);

              const reportLink = createSafeElement('a', {
                href: reportUrl.toString(),
                class: 'view-report-link',
                target: '_blank'
              }, 'View detailed analysis');
              
              scanReportDetail.appendChild(scanReportLabel);
              scanReportDetail.appendChild(reportLink);
              detailsList.appendChild(scanReportDetail);
            }
            
            modalBody.appendChild(detailsList);
            modalContent.appendChild(modalBody);
            
            // Add modal to body
            modal.appendChild(modalContent);
            document.body.appendChild(modal);
            
            // Close button functionality
            closeBtn.addEventListener('click', function(closeEvent) {
              // Don't validate event target, just check if it's trusted
              if (!closeEvent.isTrusted) return;
              document.body.removeChild(modal);
            });
            
            // Close on outside click
            modal.addEventListener('click', function(outsideClick) {
              // Don't validate event target, just check if it's trusted
              if (!outsideClick.isTrusted) return;
              
              if (outsideClick.target === modal) {
                document.body.removeChild(modal);
              }
            });
            
            // Activate modal with animation (wait a tick for DOM to update)
            setTimeout(() => {
              modal.classList.add('active');
            }, 10);
          });
          
          releaseItem.appendChild(statusIndicator);
          releasesList.appendChild(releaseItem);
        });
        
        releasesSection.appendChild(releasesList);
        
        cardBody.appendChild(releasesSection);
        
        // Add card body to card
        card.appendChild(cardBody);
        
        // Add the card to the container
        actionCardsContainer.appendChild(card);
          } catch (error) {
        console.error(`Error building card for ${key}:`, error);
        
        // Create a fallback error card
        const errorCard = createSafeElement('div', { 
          class: 'card action-card error-card',
          'data-id': key
        });
        
        // Card header
        const cardHeader = createSafeElement('div', { class: 'card-header' });
        
        // Repository title area
        const repoTitleArea = createSafeElement('div', { class: 'repo-title-area' });
        
        // Repository name
        const cardTitle = createSafeElement('h3', { class: 'card-title' }, key);
        repoTitleArea.appendChild(cardTitle);
        
        cardHeader.appendChild(repoTitleArea);
        
        // Error message
        const errorDescription = createSafeElement('div', { class: 'error-description' }, 
          'There was an error loading this repository data. Please check the console for details.'
        );
        cardHeader.appendChild(errorDescription);
        
        // Card body
        const cardBody = createSafeElement('div', { class: 'card-body' });
        
        // Add retry button
        const retryButton = createSafeElement('button', { 
          class: 'btn btn-primary',
          'data-repo': key
        }, 'Retry Loading');
        
        retryButton.addEventListener('click', async function() {
          try {
            const statsResp = await fetch('action-stats.json');
            if (statsResp.ok) {
              const rawData = await statsResp.text();
              const statsData = JSON.parse(rawData);
              
              if (statsData[key]) {
                // Replace this card with a properly built one
                actionCardsContainer.removeChild(errorCard);
                loadRepositoryCard(key, statsData[key], actionCardsContainer);
              }
            }
          } catch (e) {
            console.error('Failed to retry loading:', e);
          }
        });
        
        cardBody.appendChild(retryButton);
        
        errorCard.appendChild(cardHeader);
        errorCard.appendChild(cardBody);
        actionCardsContainer.appendChild(errorCard);
      }
    });
    
    // Add action cards to the security issues div
    securityIssuesDiv.appendChild(actionCardsContainer);

  } catch (error) {
    console.error('Error loading data:', error);
    // Clear existing content
    while (metadataDiv.firstChild) {
      metadataDiv.removeChild(metadataDiv.firstChild);
    }
    const errorParagraph = createSafeElement('div', { class: 'error' }, 
                                           `Error loading metadata: ${escapeHTML(error.message)}`);
    metadataDiv.appendChild(errorParagraph);
  }
}

// Add this helper function
function buildSafeElement(tagName, attributes = {}, children = []) {
    const element = createSafeElement(tagName, attributes);
    
    if (Array.isArray(children)) {
        children.forEach(child => {
            if (typeof child === 'string') {
                element.appendChild(document.createTextNode(child));
            } else if (child instanceof Node) {
                element.appendChild(child);
            }
        });
    } else if (typeof children === 'string') {
        element.textContent = children;
    } else if (children instanceof Node) {
        element.appendChild(children);
    }
    
    return element;
}

// Create empty data structure function
function createEmptyDataStructure() {
    return {
        'example-action': {
            repository: {
                name: 'example-action',
                full_name: 'example/example-action',
                stargazers_count: 0,
                description: 'Example GitHub Action',
                created_at: new Date().toISOString(),
                owner: {
                    login: 'example'
                }
            },
            releases: [
                {
                    version: '1.0.0',
                    published_at: new Date().toISOString(),
                    sha: '0000000000000000000000000000000000000000',
                    securityData: {
                        status: 'safe',
                        issues: []
                    }
                }
            ]
        }
    };
}

// Helper function to load a single repository card
function loadRepositoryCard(key, actionData, container) {
  try {
    // Ensure the repository object exists
    if (!actionData.repository || typeof actionData.repository !== 'object') {
      actionData.repository = {
        name: key,
        full_name: key,
        description: 'No repository information available',
        stars: 0,
        issues: 0,
        contributors: 0,
        owner: { login: 'unknown' }
      };
    } else {
      // Map to consistent property names
      actionData.repository.stars = actionData.repository.stars || 
                                    actionData.repository.stargazers_count || 0;
      actionData.repository.issues = actionData.repository.issues || 
                                     actionData.repository.open_issues_count || 
                                     actionData.repository.issues_count || 0;
      actionData.repository.contributors = actionData.repository.contributors || 
                                                actionData.repository.contributors_count || 0;
    }
    
    const repository = actionData.repository;
    
    // Ensure releases is always an array
    if (!actionData.releases) {
      actionData.releases = [];
    } else if (!Array.isArray(actionData.releases)) {
      // If releases is an object but not an array, convert it
      if (typeof actionData.releases === 'object') {
        try {
          // Universal approach for all repositories with object-based releases
          const tags = Object.keys(actionData.releases);
          const releaseArray = [];
          
          // Convert each key-value pair to a proper release object
          tags.forEach(tag => {
            const releaseData = actionData.releases[tag];
            // Skip null or undefined entries
            if (!releaseData) return;
            
            // Create a properly structured release object
            const release = {
              version: tag,
              published_at: releaseData.published_date || new Date().toISOString(),
              scanned: releaseData.scanned || false,
              latest: releaseData.latest || "",
              sha: Array.isArray(releaseData.sha) ? releaseData.sha : [releaseData.sha || ""],
              safe: releaseData.safe || false,
              scan_report: releaseData.scan_report || null,
              securityData: {
                status: releaseData.safe ? 'safe' : 'not-scanned',
                issues: []
              }
            };
            
            releaseArray.push(release);
          });
          
          if (releaseArray.length > 0) {
            // Sort by published date (newest first)
            releaseArray.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
            actionData.releases = releaseArray;
          } else {
            actionData.releases = [];
          }
        } catch (e) {
          console.error(`Failed to convert releases for ${key} to array in card building:`, e);
          actionData.releases = [];
        }
      } else {
        actionData.releases = [];
      }
    }
    
    const releases = actionData.releases;
    
    // Skip if missing essential data
    if (!repository.name) return;
    
    // Create card element
    const card = createSafeElement('div', { 
      class: 'card action-card',
      'data-id': key
    });
    
    // Card header
    const cardHeader = createSafeElement('div', { class: 'card-header' });
    
    // Repository title and stars in first row
    const headerFirstRow = createSafeElement('div', { class: 'header-row' });
    
    // Repository name
    const repoName = createSafeElement('h3', { class: 'card-title' }, 
      repository.full_name || repository.name || key
    );
    headerFirstRow.appendChild(repoName);
    
    // Stars badge if available
    if (repository.stars !== undefined) {
      const starsContainer = createSafeElement('div', { class: 'stars' });
      
      // Star icon
      const starIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      starIcon.setAttribute('width', '16');
      starIcon.setAttribute('height', '16');
      starIcon.setAttribute('viewBox', '0 0 16 16');
      starIcon.setAttribute('fill', 'currentColor');
      
      const starPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      starPath.setAttribute('d', 'M8 0.25a0.75 0.75 0 0 1 0.673 0.418l1.882 3.815 4.21 0.612a0.75 0.75 0 0 1 0.416 1.279l-3.046 2.97 0.719 4.192a0.75 0.75 0 0 1-1.088 0.791L8 12.347l-3.766 1.98a0.75 0.75 0 0 1-1.088-0.79l0.72-4.194-3.047-2.969a0.75 0.75 0 0 1 0.416-1.28l4.21-0.61 1.883-3.815A0.75 0.75 0 0 1 8 0.25z');
      
      starIcon.appendChild(starPath);
      starsContainer.appendChild(starIcon);
      
      const starsCount = createSafeElement('span', { class: 'count' }, 
        repository.stars.toLocaleString()
      );
      starsContainer.appendChild(starsCount);
      
      headerFirstRow.appendChild(starsContainer);
    }
    
    cardHeader.appendChild(headerFirstRow);
    
    // Repository metadata
    const repoMetadata = createSafeElement('div', { class: 'repo-metadata' });
    
    // Owner information
    if (repository.owner) {
      const ownerInfo = createSafeElement('div', { class: 'repo-info-item' });
      const ownerLabel = createSafeElement('span', { class: 'info-label' }, 'Owner:');
      const ownerValue = createSafeElement('span', { class: 'info-value' }, 
        typeof repository.owner === 'string' ? repository.owner : repository.owner.login || repository.owner || 'unknown'
      );
      
      ownerInfo.appendChild(ownerLabel);
      ownerInfo.appendChild(ownerValue);
      repoMetadata.appendChild(ownerInfo);
    }
    
    // Created date
    if (repository.created_at) {
      try {
        const createdDate = new Date(repository.created_at);
        if (!isNaN(createdDate)) {
          const createdInfo = createSafeElement('div', { class: 'repo-info-item' });
          const createdLabel = createSafeElement('span', { class: 'info-label' }, 'Created:');
          
          // Format date as DD/MM/YYYY for consistency
          const day = createdDate.getDate();
          const month = createdDate.getMonth() + 1;
          const year = createdDate.getFullYear();
          const formattedDate = `${day}/${month}/${year}`;
          
          // Create date span with significant margin-left for spacing
          const dateText = createSafeElement('span', { 
            class: 'date'
          }, formattedDate);
          
          createdInfo.appendChild(createdLabel);
          createdInfo.appendChild(dateText);
          repoMetadata.appendChild(createdInfo);
        }
      } catch (e) {
        console.warn(`Error parsing created_at date for ${key}`);
      }
    }
    
    // Issues count
    if (repository.issues !== undefined) {
      const issuesInfo = createSafeElement('div', { class: 'repo-info-item' });
      const issuesLabel = createSafeElement('span', { class: 'info-label' }, 'Issues:');
      const issuesValue = createSafeElement('span', { class: 'info-value' }, 
        repository.issues.toString()
      );
      
      issuesInfo.appendChild(issuesLabel);
      issuesInfo.appendChild(issuesValue);
      repoMetadata.appendChild(issuesInfo);
    }
    
    // Contributors count
    if (repository.contributors !== undefined) {
      const contributorsInfo = createSafeElement('div', { class: 'repo-info-item' });
      const contributorsLabel = createSafeElement('span', { class: 'info-label' }, 'Contributors:');
      const contributorsValue = createSafeElement('span', { class: 'info-value' }, 
        repository.contributors.toString()
      );
      
      contributorsInfo.appendChild(contributorsLabel);
      contributorsInfo.appendChild(contributorsValue);
      repoMetadata.appendChild(contributorsInfo);
    }
    
    cardHeader.appendChild(repoMetadata);
    
    // Description if available
    if (repository.description) {
      const description = createSafeElement('div', { class: 'repo-description' }, repository.description);
      cardHeader.appendChild(description);
    }
    
    card.appendChild(cardHeader);
    
    // Card body
    const cardBody = createSafeElement('div', { class: 'card-body' });
    
    // Security statistics section
    const securityStats = createSafeElement('div', { class: 'security-stats' });
    
    // Count releases by security status
    let safeCount = 0;
    let unsafeCount = 0;
    let notScannedCount = 0;
    
    releases.forEach(release => {
      if (release.scanned) {
        if (release.safe) safeCount++;
        else unsafeCount++;
      } else {
        notScannedCount++;
      }
    });
    
    // Release count information
    const releasesInfo = createSafeElement('div', { class: 'd-flex justify-between mb-md' });
    const releasesLabel = createSafeElement('div', { class: 'section-title' }, 'Releases');
    const releasesCount = createSafeElement('div', { class: 'count' }, 
      `${releases.length} total`
    );
    
    releasesInfo.appendChild(releasesLabel);
    releasesInfo.appendChild(releasesCount);
    
    cardBody.appendChild(releasesInfo);
    
    // Add scan status indicators
    const scanCount = safeCount + unsafeCount;
    const scanDisplay = createSafeElement('div', { class: 'scan-count' }, 
      `${scanCount}/${releases.length} SCANNED`
    );
    
    cardBody.appendChild(scanDisplay);
    
    // Releases section
    const releasesSection = createSafeElement('div', { class: 'releases-section' });
    
    // Sort releases to have scanned releases first, then by date
    const sortedReleases = [...releases].sort((a, b) => {
      // First sort by scan status
      if (a.scanned && !b.scanned) return -1;
      if (!a.scanned && b.scanned) return 1;
      
      // Then sort by date (newest first)
      return new Date(b.published_at) - new Date(a.published_at);
    });
    
    // Create scrollable container for all releases
    const releasesList = createSafeElement('ul', { class: 'releases-list scrollable' });
    
    // Display all releases in the scrollable container
    sortedReleases.forEach(release => {
      // Skip if release is null or undefined
      if (!release) return;
      
      // Create a CSS class based on security status
      let statusClass = release.scanned ? (release.safe ? 'safe' : 'unsafe') : 'not-scanned';
      let statusText = release.scanned ? 'SCANNED' : 'NOT SCANNED';
      
      const releaseItem = createSafeElement('li', { 
        class: `release-item ${statusClass}`,
        'data-id': `${key}-${release.version || 'unknown'}`
      });
      
      const releaseInfo = createSafeElement('div', { class: 'release-info' });
      
      // Version and release date
      const versionInfo = createSafeElement('div', { class: 'version-info' });
      const versionText = createSafeElement('span', { 
        class: 'version',
        title: 'View release details'
      }, release.version || 'Unknown version');
      
      versionInfo.appendChild(versionText);
      
      if (release.published_at) {
        const publishDate = new Date(release.published_at);
        if (!isNaN(publishDate)) {
          // Format date as DD/MM/YYYY for consistency
          const day = publishDate.getDate();
          const month = publishDate.getMonth() + 1;
          const year = publishDate.getFullYear();
          const formattedDate = `${day}/${month}/${year}`;
          
          // Create date span with significant margin-left for spacing
          const dateText = createSafeElement('span', { 
            class: 'date'
          }, formattedDate);
          
          // Directly append the date without text node separator
          versionInfo.appendChild(dateText);
        }
      }
      
      releaseInfo.appendChild(versionInfo);
      releaseItem.appendChild(releaseInfo);
      
      // Status indicator
      const statusIndicator = createSafeElement('div', { class: 'status-indicator' });
      
      // Add status badge
      const statusBadge = createSafeElement('span', { 
        class: `badge badge-${statusClass}`
      }, statusText);
      
      statusIndicator.appendChild(statusBadge);
      
      // Add details button
      const detailsBtn = createSafeElement('button', { 
        class: 'btn btn-icon details-btn',
        title: 'View details',
        'aria-label': 'View release details'
      });
      
      // Info icon
      const infoIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      infoIcon.setAttribute('width', '16');
      infoIcon.setAttribute('height', '16');
      infoIcon.setAttribute('viewBox', '0 0 24 24');
      infoIcon.setAttribute('fill', 'none');
      infoIcon.setAttribute('stroke', 'currentColor');
      infoIcon.setAttribute('stroke-width', '2');
      infoIcon.setAttribute('stroke-linecap', 'round');
      infoIcon.setAttribute('stroke-linejoin', 'round');
      
      const circlePath = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circlePath.setAttribute('cx', '12');
      circlePath.setAttribute('cy', '12');
      circlePath.setAttribute('r', '10');
      
      const line1 = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line1.setAttribute('x1', '12');
      line1.setAttribute('y1', '16');
      line1.setAttribute('x2', '12');
      line1.setAttribute('y2', '12');
      
      const line2 = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line2.setAttribute('x1', '12');
      line2.setAttribute('y1', '8');
      line2.setAttribute('x2', '12.01');
      line2.setAttribute('y2', '8');
      
      infoIcon.appendChild(circlePath);
      infoIcon.appendChild(line1);
      infoIcon.appendChild(line2);
      
      detailsBtn.appendChild(infoIcon);
      statusIndicator.appendChild(detailsBtn);
      
      // Add release details modal handler
      detailsBtn.addEventListener('click', function(event) {
        // Don't validate the event target here, just check if it's trusted
        if (!event.isTrusted) return;
        
        event.preventDefault();
        event.stopPropagation();
        
        // Create modal
        const modal = createSafeElement('div', { class: 'modal-overlay' });
        
        // Create modal content
        const modalContent = createSafeElement('div', { class: 'modal' });
        
        // Modal header
        const modalHeader = createSafeElement('div', { class: 'modal-header' });
        const modalTitle = createSafeElement('h4', { class: 'modal-title' }, 
          `Release: ${release.version}`
        );
        const closeBtn = createSafeElement('button', { 
          class: 'modal-close',
          'aria-label': 'Close'
        }, '×');
        
        modalHeader.appendChild(modalTitle);
        modalHeader.appendChild(closeBtn);
        modalContent.appendChild(modalHeader);
        
        // Modal body
        const modalBody = createSafeElement('div', { class: 'modal-body' });
        
        // Details list
        const detailsList = createSafeElement('div', { class: 'details-list' });
        
        // Add release info
        if (release.published_at) {
          const publishDate = new Date(release.published_at);
          if (!isNaN(publishDate)) {
            const dateDetail = createSafeElement('div', { class: 'd-flex justify-between mb-sm' });
            const dateLabel = createSafeElement('span', { class: 'text-bold' }, 'Released:');
            
            // Format as shown in screenshot with date and time
            const options = { 
              year: 'numeric', 
              month: '2-digit', 
              day: '2-digit',
              hour: '2-digit',
              minute: '2-digit', 
              hour12: true 
            };
            const dateValue = createSafeElement('span', {}, publishDate.toLocaleString(undefined, options));
            
            dateDetail.appendChild(dateLabel);
            dateDetail.appendChild(dateValue);
            detailsList.appendChild(dateDetail);
          }
        }
        
        // SHA
        if (release.sha && release.sha.length > 0) {
          const shaDetail = createSafeElement('div', { class: 'd-flex flex-wrap mb-sm' });
          const shaLabel = createSafeElement('span', { class: 'text-bold' }, 'SHA:');
          shaDetail.appendChild(shaLabel);
          
          const shaValue = createSafeElement('div', { class: 'sha-box' }, release.sha[0] || '');
          shaDetail.appendChild(shaValue);
          
          detailsList.appendChild(shaDetail);
        }
        
        // Latest SHA if different
        if (release.latest) {
          const latestShaDetail = createSafeElement('div', { class: 'd-flex flex-wrap mb-sm' });
          const latestShaLabel = createSafeElement('span', { class: 'text-bold' }, 'Latest SHA:');
          latestShaDetail.appendChild(latestShaLabel);
          
          const latestShaValue = createSafeElement('div', { class: 'sha-box' }, release.latest || '');
          latestShaDetail.appendChild(latestShaValue);
          
          detailsList.appendChild(latestShaDetail);
        }
        
        // Status
        const statusDetail = createSafeElement('div', { class: 'd-flex justify-between mb-sm' });
        const statusLabel = createSafeElement('span', { class: 'text-bold' }, 'Status:');
        
        let statusValue;
        if (release.scanned) {
          if (release.safe) {
            statusValue = createSafeElement('span', { class: 'text-success' }, 'Safe version - verified');
          } else {
            statusValue = createSafeElement('span', { class: 'text-danger' }, 'Potentially unsafe');
          }
        } else {
          statusValue = createSafeElement('span', { class: 'text-tertiary' }, 'Not scanned');
        }
        
        statusDetail.appendChild(statusLabel);
        statusDetail.appendChild(statusValue);
        detailsList.appendChild(statusDetail);
        
        // Scanned status
        const scannedDetail = createSafeElement('div', { class: 'd-flex justify-between mb-sm' });
        const scannedLabel = createSafeElement('span', { class: 'text-bold' }, 'Scanned:');
        const scannedValue = createSafeElement('span', {}, release.scanned ? 'Yes' : 'No');
        
        scannedDetail.appendChild(scannedLabel);
        scannedDetail.appendChild(scannedValue);
        detailsList.appendChild(scannedDetail);
        
        // Add scan report link if available
        if (release.scan_report && release.scanned) {
          const scanReportDetail = createSafeElement('div', { class: 'd-flex justify-between mb-sm' });
          const scanReportLabel = createSafeElement('span', { class: 'text-bold' }, 'Scan Report:');
          
          // Create a link to view the detailed analysis
          const reportLink = createSafeElement('a', { 
            href: `action-report.html?report=${encodeURIComponent(release.scan_report)}&name=${encodeURIComponent(actionData.name || key)}`,
            class: 'view-report-link',
            target: '_blank'
          }, 'View detailed analysis');
          
          scanReportDetail.appendChild(scanReportLabel);
          scanReportDetail.appendChild(reportLink);
          detailsList.appendChild(scanReportDetail);
        }
        
        modalBody.appendChild(detailsList);
        modalContent.appendChild(modalBody);
        
        // Add modal to body
        modal.appendChild(modalContent);
        document.body.appendChild(modal);
        
        // Close button functionality
        closeBtn.addEventListener('click', function(closeEvent) {
          // Don't validate event target, just check if it's trusted
          if (!closeEvent.isTrusted) return;
          document.body.removeChild(modal);
        });
        
        // Close on outside click
        modal.addEventListener('click', function(outsideClick) {
          // Don't validate event target, just check if it's trusted
          if (!outsideClick.isTrusted) return;
          
          if (outsideClick.target === modal) {
            document.body.removeChild(modal);
          }
        });
        
        // Activate modal with animation (wait a tick for DOM to update)
        setTimeout(() => {
          modal.classList.add('active');
        }, 10);
      });
      
      releaseItem.appendChild(statusIndicator);
      releasesList.appendChild(releaseItem);
    });
    
    releasesSection.appendChild(releasesList);
    
    cardBody.appendChild(releasesSection);
    
    // Add card body to card
    card.appendChild(cardBody);
    
    // Add the card to the container
    container.appendChild(card);
    
    return card;
  } catch (error) {
    console.error(`Error in loadRepositoryCard for ${key}:`, error);
    return null;
  }
}

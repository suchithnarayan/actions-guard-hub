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

// Initialize on page load
document.addEventListener('DOMContentLoaded', function(event) {
  // Validate the event
  if (!validateEvent(event)) {
    console.error('Invalid DOMContentLoaded event');
    return;
  }
  
  console.log('DOMContentLoaded triggered - initializing action report page');
  
  // Load the action report
  loadActionReport();
});

// Load the action report based on URL parameters
async function loadActionReport() {
  const urlParams = new URLSearchParams(window.location.search);
  const reportPath = urlParams.get('report');
  const actionName = urlParams.get('name');
  
  // Update the page title and header if action name is provided
  if (actionName) {
    document.title = `${actionName} - Analysis Report | ActionsGuardHub`;
    const actionNameElement = document.getElementById('action-name');
    if (actionNameElement) {
      actionNameElement.textContent = `${actionName} - Analysis Report`;
    }
  }
  
  // If no report path is provided, show an error
  if (!reportPath) {
    showError('No report path specified. Please provide a report parameter in the URL.');
    return;
  }
  
  // Sanitize the file path to prevent directory traversal
  const sanitizedPath = sanitizeFilePath(reportPath);
  if (!sanitizedPath) {
    showError('Invalid report path specified.');
    return;
  }
  
  // Normalize path to avoid duplicate 'frontend/' when page is already under /frontend/
  let fetchPath = sanitizedPath.replace(/^\/?/, ''); // drop leading slash for normalization
  if (fetchPath.startsWith('frontend/')) {
    fetchPath = fetchPath.replace(/^frontend\//, '');
  }
  // Make it relative to current directory (frontend/) so it resolves to /frontend/output/...
  fetchPath = `./${fetchPath}`;
  
  try {
    // Show loading state
    const reportContainer = document.getElementById('action-report');
    if (!reportContainer) {
      console.error('Report container element not found');
      return;
    }
    
    // Load the report data
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
    
    try {
      const response = await fetch(fetchPath, { signal: controller.signal });
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        throw new Error(`Failed to load report: ${response.status}`);
      }
      
      const reportData = await response.json();
      
      // Validate the report data
      if (!validateReportData(reportData)) {
        throw new Error('Invalid report data format');
      }
      
      // Display the report
      displayReport(reportData, reportContainer);
      
    } catch (fetchError) {
      console.error('Error fetching report:', fetchError);
      showError(`Error loading report: ${fetchError.message}`);
    }
  } catch (error) {
    console.error('Error loading action report:', error);
    showError(`Error loading report: ${error.message}`);
  }
}

// Sanitize file path to prevent directory traversal
function sanitizeFilePath(path) {
  if (typeof path !== 'string') return '';
  
  // Remove directory traversal and other potentially harmful characters
  return path
    .replace(/\.\.\//g, '') // Prevent directory traversal
    .replace(/[<>"'&;]/g, '') // Remove dangerous characters
    .replace(/\s+/g, '-'); // Replace spaces with hyphens
}

// Validate report data structure
function validateReportData(data) {
  if (!data || typeof data !== 'object') return false;
  
  // Check for required fields
  const hasRequiredFields = 
    (data["repo-name"] || data.repository) && 
    (data["action-name"] || data["action-name"] === null);
  
  return hasRequiredFields;
}

// Show error message
function showError(message) {
  const reportContainer = document.getElementById('action-report');
  if (reportContainer) {
    // Clear the container
    while (reportContainer.firstChild) {
      reportContainer.removeChild(reportContainer.firstChild);
    }
    
    // Add error message
    const errorElement = createSafeElement('div', { class: 'error' }, message);
    reportContainer.appendChild(errorElement);
  }
}

// Display the report
function displayReport(data, container) {
  // Clear the container
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }
  
  // Create metadata section
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
  
  // Add metadata fields
  addMetaField(metaContent, 'Repository', data["repo-name"] || data.repository || "Unknown Repo");
  addMetaField(metaContent, 'Action Name', data["action-name"] || "Unknown Action");
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
  
  // Add recommendations section if available
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
  
  // Add security checks section if available
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
}

// Helper function to add metadata fields
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
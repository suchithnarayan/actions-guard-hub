// Data validator for ActionsGuardHub
// This script can be manually run to validate the action-stats.json file

function validateActionStats(filePath = 'action-stats.json') {
    console.log(`Validating ${filePath}...`);
    
    fetch(filePath)
        .then(response => response.text())
        .then(data => {
            try {
                // Basic JSON parse validation
                console.log(`File size: ${(data.length / 1024 / 1024).toFixed(2)} MB`);
                
                // Try to parse JSON
                const statsData = JSON.parse(data);
                console.log(`✅ JSON is valid and can be parsed`);
                
                // Check overall structure
                if (!statsData || typeof statsData !== 'object') {
                    console.error('❌ JSON is not an object');
                    return;
                }
                
                console.log(`Number of repositories: ${Object.keys(statsData).length}`);
                
                // Inspect repositories
                let validRepos = 0;
                let missingRepoField = 0;
                let releasesNotArray = 0;
                let releasesNotPresent = 0;
                let emptyReleases = 0;
                let missingVersions = 0;
                
                Object.keys(statsData).forEach(key => {
                    const repoData = statsData[key];
                    
                    // Check repository field
                    if (!repoData.repository || typeof repoData.repository !== 'object') {
                        missingRepoField++;
                        console.warn(`⚠️ Repository field missing for ${key}`);
                    } else {
                        validRepos++;
                    }
                    
                    // Check releases
                    if (!repoData.releases) {
                        releasesNotPresent++;
                        console.warn(`⚠️ No releases field for ${key}`);
                    } else if (!Array.isArray(repoData.releases)) {
                        releasesNotArray++;
                        console.warn(`⚠️ Releases is not an array for ${key}`);
                        
                        // Check if it's an object with numeric keys
                        if (typeof repoData.releases === 'object') {
                            const releaseKeys = Object.keys(repoData.releases);
                            console.log(`  Object keys: ${releaseKeys.slice(0, 5).join(', ')}${releaseKeys.length > 5 ? '...' : ''}`);
                        }
                    } else if (repoData.releases.length === 0) {
                        emptyReleases++;
                    } else {
                        // Check releases for missing versions
                        repoData.releases.forEach(release => {
                            if (!release.version) {
                                missingVersions++;
                            }
                        });
                    }
                });
                
                // Summary
                console.log('\n--- Validation Summary ---');
                console.log(`Total repositories: ${Object.keys(statsData).length}`);
                console.log(`Valid repositories: ${validRepos}`);
                console.log(`Missing repository field: ${missingRepoField}`);
                console.log(`Releases not present: ${releasesNotPresent}`);
                console.log(`Releases not array: ${releasesNotArray}`);
                console.log(`Empty releases arrays: ${emptyReleases}`);
                console.log(`Releases missing version: ${missingVersions}`);
                
            } catch (error) {
                console.error('❌ Error parsing JSON:', error);
                
                // Try to find the specific location of the JSON error
                const errorMatch = error.message.match(/at position (\d+)/);
                if (errorMatch && errorMatch[1]) {
                    const errorPos = parseInt(errorMatch[1]);
                    const errorContext = data.substring(
                        Math.max(0, errorPos - 50), 
                        Math.min(data.length, errorPos + 50)
                    );
                    console.error(`Error near position ${errorPos}:`, errorContext);
                }
            }
        })
        .catch(error => {
            console.error('❌ Error fetching file:', error);
        });
}

// Run validation on page load
document.addEventListener('DOMContentLoaded', function() {
    const btnValidate = document.createElement('button');
    btnValidate.textContent = 'Validate Data';
    btnValidate.style.position = 'fixed';
    btnValidate.style.top = '10px';
    btnValidate.style.right = '10px';
    btnValidate.style.zIndex = '9999';
    btnValidate.className = 'btn btn-primary';
    
    btnValidate.addEventListener('click', function() {
        validateActionStats();
    });
    
    document.body.appendChild(btnValidate);
}); 
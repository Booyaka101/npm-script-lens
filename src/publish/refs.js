'use strict';
// How the reports print the external references they cite.

// 'https://github.com/npm/documentation/issues/1960' → 'npm/documentation#1960'
const shortIssue = (url) => {
  const m = String(url).match(/github\.com\/([^/]+\/[^/]+)\/issues\/(\d+)/);
  return m ? `${m[1]}#${m[2]}` : url;
};

const registryHost = (url) => String(url).replace(/^\w+:\/\//, '').replace(/\/+$/, '');

module.exports = { shortIssue, registryHost };

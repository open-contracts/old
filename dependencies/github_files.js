(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.GITHUB_FILES = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
// this file is not used by the website, it serves as an input to to create cose.js with:
// browserify github_files_source.js --standalone GITHUB_FILES > github_files.js

var listContent = require('list-github-dir-content');

async function content_links_json(user, repo, ref, dir) {
    files = await listContent.viaContentsApi({user: user, repository: repo, ref: ref, directory: dir});
    links = Object.fromEntries(files.map(f => [f.slice(dir.length+1, f.length), "https://raw.githubusercontent.com/" + user + "/" + repo + "/" + ref + "/" + f]))
    return links
}

module.exports = {content_links_json}


},{"list-github-dir-content":3}],2:[function(require,module,exports){
module.exports = fetch;

},{}],3:[function(require,module,exports){
const fetch = require('node-fetch'); // Automatically excluded in browser bundles

async function api(endpoint, token) {
	const response = await fetch(`https://api.github.com/repos/${endpoint}`, {
		headers: token ? {
			Authorization: `Bearer ${token}`
		} : undefined
	});
	return response.json();
}

// Great for downloads with few sub directories on big repos
// Cons: many requests if the repo has a lot of nested dirs
async function viaContentsApi({
	user,
	repository,
	ref = 'HEAD',
	directory,
	token,
	getFullData = false
}) {
	const files = [];
	const requests = [];
	const contents = await api(`${user}/${repository}/contents/${directory}?ref=${ref}`, token);

	if (contents.message === 'Not Found') {
		return [];
	}

	if (contents.message) {
		throw new Error(contents.message);
	}

	for (const item of contents) {
		if (item.type === 'file') {
			files.push(getFullData ? item : item.path);
		} else if (item.type === 'dir') {
			requests.push(viaContentsApi({
				user,
				repository,
				ref,
				directory: item.path,
				token,
				getFullData
			}));
		}
	}

	return files.concat(...await Promise.all(requests));
}

// Great for downloads with many sub directories
// Pros: one request + maybe doesn't require token
// Cons: huge on huge repos + may be truncated
async function viaTreesApi({
	user,
	repository,
	ref = 'HEAD',
	directory,
	token,
	getFullData = false
}) {
	if (!directory.endsWith('/')) {
		directory += '/';
	}

	const files = [];
	const contents = await api(`${user}/${repository}/git/trees/${ref}?recursive=1`, token);
	if (contents.message) {
		throw new Error(contents.message);
	}

	for (const item of contents.tree) {
		if (item.type === 'blob' && item.path.startsWith(directory)) {
			files.push(getFullData ? item : item.path);
		}
	}

	files.truncated = contents.truncated;
	return files;
}

module.exports.viaContentsApi = viaContentsApi;
module.exports.viaContentApi = viaContentsApi;
module.exports.viaTreesApi = viaTreesApi;
module.exports.viaTreeApi = viaTreesApi;

},{"node-fetch":2}]},{},[1])(1)
});

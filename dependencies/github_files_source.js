// this file is not used by the website, it serves as an input to to create cose.js with:
// browserify github_files_source.js --standalone GITHUB_FILES > github_files.js

var listContent = require('list-github-dir-content');

async function content_links_json(user, repo, ref, dir) {
    files = await listContent.viaContentsApi({user: user, repository: repo, ref: ref, directory: dir});
    links = Object.fromEntries(files.map(f => [f.slice(dir.length+1, f.length), "https://raw.githubusercontent.com/" + user + "/" + repo + "/" + ref + "/" + f]))
    return links
}

module.exports = {content_links_json}


'use strict';

const ChildProcess = require('child_process');
const Crypto = require('crypto');
const Fs = require('fs');
const Os = require('os');
const Path = require('path');
const Util = require('util');

const Hoek = require('hoek');
const Wreck = require('wreck');


const internals = {
    shaMismatch: Symbol('sha-mismatch'),
    shaMissing: Symbol('sha-missing')
};


internals.exec = async function (command, ...args) {

    let options = { maxBuffer: 4 * 1024 * 1024 };
    if (args.length && typeof args[args.length - 1] === 'object') {
        options = Object.assign(options, args.pop());
    }

    const { stdout } = await Util.promisify(ChildProcess.execFile)(command, args, options);
    return stdout;
};


internals.packageHash = function (info) {

    if (info.dist.integrity) {
        const [alg, hash] = info.dist.integrity.split('-', 2);
        return { alg, hash: Buffer.from(hash, 'base64').toString('hex') };
    }

    if (info.dist.shasum) {
        return { alg: 'sha1', hash: info.dist.shasum };
    }

    throw new Error('No package hash');
}


internals.ValidationError = class ValidationError extends Error {

    constructor(message, { pkg, version, diff } = {}) {

        super(message);

        this.details = { pkg, version, diff };
    }
};


internals.Taint = class {

    constructor(reason, details) {

        this.reason = reason;
        this.details = details;
    }

    clean() {

        return this === internals.Taint.none;
    }
}


internals.Taint.none = new internals.Taint();


module.exports = class Validator {

    constructor(packageName, version, options) {

        Hoek.assert(packageName && typeof packageName === 'string', 'Bad package name');
        Hoek.assert(version && typeof version === 'string', 'Bad package version');

        this.package = packageName;
        this.version = version;
        this.options = Object.assign({}, options);

        this._details = null;
    }

    async fetchDetails() {

        if (!this._details) {
            const json = await internals.exec('npm', 'view', '-json', `${this.package}@${this.version}`);
            if (!this._details) {
                this._details = json ? JSON.parse(json) : {};
            }
        }

        if (Array.isArray(this._details)) {
            if (!this.options.loose) {
                throw new Error('Version specifier is too loose');
            }

            this._details = this._details.pop();
        }

        if (!this._details.name) {
            throw new Error('Failed to find package / version');
        }

        return this._details;
    }

    async fetchPackageSource(dst) {

        Hoek.assert(dst && typeof dst === 'string' && dst !== '/', 'Invalid dst path');

        const info = await this.fetchDetails();

        Hoek.assert(info.dist.tarball, 'Missing package url');

        const res = await Wreck.request('GET', info.dist.tarball);
        if (res.statusCode !== 200) {
            throw new Error(`Bad server response: ${res.statusCode}`);
        }
        const fetchDone = new Promise((resolve, reject) => {

            res.on('error', reject);
            res.on('aborted', () => reject(new Error('Aborted request')));
            res.on('end', resolve);
        });

        dst = Path.resolve(dst);
        await Util.promisify(Fs.mkdir)(dst);

        // TODO: validate that tar handles duplicate files similar to npm - remember case insensitive fs's
        const tar = ChildProcess.spawn('tar', ['zx', '--strip=1'], { cwd: dst, stdio: ['pipe', 'ignore', 'ignore'] });
        const tarDone = new Promise((resolve, reject) => {

            tar.on('error', reject);
            tar.on('exit', (code) => {

                return code === 0 ? resolve() : reject(new Error(`Abnormal exit, code: ${code}`));
            });
        });

        res.pipe(tar.stdin);

        const packageHash = internals.packageHash(info);
        const hasher = Crypto.createHash(packageHash.alg);
        res.on('data', hasher.update.bind(hasher));

        await Promise.all([fetchDone, tarDone]);

        const digest = hasher.digest('hex');
        if (digest !== packageHash.hash) {
            throw new Error('Bad package hash');
        }

        return internals.Taint.none;
    }

    async fetchGitSource(dst) {

        Hoek.assert(dst && typeof dst === 'string' && dst !== '/', 'Invalid dst path');

        const info = await this.fetchDetails();

        const repo = info.repository || {};

        Hoek.assert(repo.type === 'git' && repo.url, 'Did not find git repo url');

        let repoUrl = repo.url;
        const parts = repoUrl.split(':', 2);
        const isGithub = parts.length === 2 && parts[1].startsWith('//github.com/');

        if (isGithub &&
            (parts[0] === 'git+https' || parts[0] === 'git')) {

            repoUrl = 'https:' + parts[1];
        }

        dst = Path.resolve(dst);

        try {
            try {
                await internals.exec('git', 'clone', '--depth', '1', '--single-branch', repoUrl, '-b', `v${info.version}`, dst);
            }
            catch (err) {
                // Retry without 'v' prefix to tag

                try {
                    await internals.exec('git', 'clone', '--depth', '1', '--single-branch', repoUrl, '-b', info.version, dst);
                }
                catch (ignoredErr) {
                    throw err;
                }
            }

            const gitRev = (await internals.exec('git', 'rev-parse', '--verify', 'HEAD', { cwd: dst })).trim();
            if (!gitRev || gitRev !== info.gitHead) {
                return new internals.Taint(info.gitHead ? 'sha-mismatch' : 'sha-missing', { expected: info.gitHead, found: gitRev });
            }
        }
        catch (err) {
            if (!isGithub || !info.gitHead) {
                throw err;
            }

            // Retry with sha instead

            const execOptions = { cwd: dst };

            await internals.exec('rm', '-rf', dst);
            await Util.promisify(Fs.mkdir)(dst);

            await internals.exec('git', 'init', execOptions);
            await internals.exec('git', 'remote', 'add', 'origin', repoUrl, execOptions);
            await internals.exec('git', 'fetch', '--depth', '1', 'origin', info.gitHead, execOptions);
            await internals.exec('git', 'checkout', 'FETCH_HEAD', execOptions);

            return new internals.Taint('tag-missing', { expected: [`v${info.version}`, info.version] });
        }

        return internals.Taint.none;
    }

    async check() {

        const tmpDir = Hoek.uniqueFilename(Os.tmpdir());
        const pkgPath = Path.join(tmpDir, 'package');
        const gitPath = Path.join(tmpDir, 'git');

        await Util.promisify(Fs.mkdir)(tmpDir);

        try {
            await this.fetchDetails();
            const [, git] = await Promise.all([
                this.fetchPackageSource(pkgPath),
                this.fetchGitSource(gitPath)
            ]);

            if (!git.clean()) {
                console.error(`git checkout tainted due to "${git.reason}": ${Util.inspect(git.details)}`);
            }

            try {
                await internals.exec('diff', '-r', '-u', '--strip-trailing-cr', 'git', 'package', { cwd: tmpDir });
            }
            catch (err) {
                if ((err.code === 1 || err.code === 2) &&
                    err.stdout) {

                    const lines = err.stdout.split('\n');
                    const filtered = lines.filter((line) => !line.startsWith('Only in git'));
                    const diff = filtered.join('\n').trim();

                    if (diff) {
                        throw new internals.ValidationError('Mismatch', { pkg: this.pkg, version: this.version, diff, taint: git });
                    }

                    return git;
                }

                throw err;
            }

            return git;
        }
        finally {
            await internals.exec('rm', '-rf', tmpDir);
        }
    }
};

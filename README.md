# Validate

Validate is a tool to validate that a published npm package matches the version on the associated git repository.

This is intended to simplify code-level security reviews, allowing only the git repo to be reviewed, trusting
that no new malicious code has been introduced into the published package.

_Note that succesful validation does not mean that a package is safe to use, only that it has not been tampered with_.

### Caveats

* The validated git repo is the one specified in the published `package.json`, meaning that if the package
  has been compromised it is controlled by the attacker. Eg. it could be made to point to another git repo
  than has been reviewed, invalidating the review.

* The current version only does file-level checks, which means that any package that adds or modifies
  files when published, will trigger as invalid.

* Git tags are used to find the matching repo. This has security issues, since it is easy to change a tag.
  Thus a published git hash is required to match the tag reference.

* We trust that git hashes can't be manipulated, which is only [partly true](https://blog.github.com/2017-03-20-sha-1-collision-detection-on-github-com/).

* Recursive mode does not respect shrinkwraps.

# Third-party notices

The [MIT License](LICENSE) covers this project's original code and documentation. It does
not replace licenses or terms for dependencies, external data, or third-party material.
Preserve upstream copyright and license notices when redistributing such material.

## Python dependencies

Dependencies are installed from their upstream distributions rather than copied into this
repository. Their distributions carry the authoritative license texts and notices.

| Direct dependency | Upstream license | Upstream project |
| --- | --- | --- |
| Requests | Apache-2.0 | [Requests](https://github.com/psf/requests) |
| PyYAML | MIT | [PyYAML](https://github.com/yaml/pyyaml) |
| packaging | Apache-2.0 OR BSD-2-Clause | [packaging](https://github.com/pypa/packaging) |
| pytest (development) | MIT | [pytest](https://github.com/pytest-dev/pytest) |
| pytest-cov (development) | MIT | [pytest-cov](https://github.com/pytest-dev/pytest-cov) |
| Ruff (development) | MIT | [Ruff](https://github.com/astral-sh/ruff) |
| mypy (development) | MIT | [mypy](https://github.com/python/mypy) |
| Mermaid (development) | MIT | [Mermaid](https://github.com/mermaid-js/mermaid) |
| jsdom (development) | MIT | [jsdom](https://github.com/jsdom/jsdom) |
| types-PyYAML and types-requests (development) | Apache-2.0 | [typeshed](https://github.com/python/typeshed) |

This table describes the direct dependencies at the time of review; it is not an inventory
of all transitive dependencies or build tools. When distributing a bundle containing installed
packages, include the notices required by every included package, including its dependencies.

## External data

- **NVD:** This product uses the NVD API but is not endorsed or certified by the NVD.
  See [NVD's API terms](https://nvd.nist.gov/developers/terms-of-use).
- **FIRST EPSS:** Scores are supplied by [FIRST's EPSS project](https://www.first.org/epss/).
  See its [usage and attribution guidance](https://www.first.org/epss/faq).
- **CISA KEV:** Known exploitation information is supplied by the
  [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

API responses, quoted vulnerability descriptions and vendor advisory material remain subject
to their applicable source terms. Generated matching decisions and project fix windows are
this project's analysis, not official determinations by those sources.

## Documentation frameworks

The project uses [C4](https://c4model.com/diagrams),
[Diataxis](https://diataxis.fr/) and
[Open Knowledge Format](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md)
to organise its own descriptions and domain notes. Referencing or following these frameworks
does not make their publications part of this project's MIT license. Any future copied or
adapted framework text or artwork must retain its applicable attribution and license notices.

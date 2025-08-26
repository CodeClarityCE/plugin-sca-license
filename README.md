<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
  <img alt="codeclarity-logo" src="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
</picture>
<br>
<br>

Secure your software empower your team.

[![License](https://img.shields.io/github/license/codeclarityce/codeclarity-dev)](LICENSE.txt)

<details open="open">
<summary>Table of Contents</summary>

- [CodeClarity Plugin - SCA License Finder](#codeclarity-plugin---sca-license-finder)
  - [Contributing](#contributing)
  - [Reporting Issues](#reporting-issues)
  - [Purpose](#purpose)
  - [How to add support for a new language?](#how-to-add-support-for-a-new-language)
  - [Acknowledgement of Copyright and Co-Authorship](#acknowledgement-of-copyright-and-co-authorship)


</details>

---

# CodeClarity Plugin - SCA License Finder

## Contributing

If you'd like to contribute code or documentation, please see [CONTRIBUTING.md](https://github.com/CodeClarityCE/codeclarity-dev/blob/main/CONTRIBUTING.md) for guidelines on how to do so.

## Reporting Issues

Please report any issues with the setup process or other problems encountered while using this repository by opening a new issue in this project's GitHub page.

## Purpose

The licenses service finds liceneses for the dependencies in a source code project. 

<br> It is the third stage of the Software Composition Analysis process.

1. Identify dependencies (SBOM)
2. Identify known vulnerabile dependencies (This service)
3. Identify licenses & license compliance
4. Compute and verify upgrades to the application

<br>


## How to add support for a new language?

Although the service is written in a language-agnostic fashion, adding a new language requires adding a little bit of code.

In run.go:Start(), you must create a new license matcher instance for your language (example for js):
```go
// Check which language was requested
if languageId == "JS" {
    licenseMatcher = &licenseMatcherManager.LicenseMatcher{
        LicenseDataSource:   licenseMatcherManager.LICENSE_DATA_SOURCE_DB,
        PackageRepository:   &npmRepository.NpmPackageRepository,
        PostProcessLicenses: true,
    }
}
```
1. In `LicenseDataSource` you define where the license matcher should retrieve the license data from. In some cases the license information can be found in the lock files that are parsed in the sbom service, in which case the sbom service attaches that information to the sbom stored in our database. 
   An example of this are composer lock files.
   - In case the license information is stored in the sbom, set `LicenseDataSource` to `licenseMatcherManager.LICENSE_DATA_SOURCE_SBOM`.
   - Otherwise, set `LicenseDataSource` to `licenseMatcherManager.LICENSE_DATA_SOURCE_DB`, in which case the license matcher retrieves the information from the package / dependency metadata stored in our knowledge base.
2. In `PostProcessLicenses` you define whether or not the license matcher should post process licenses. 

   - If `LicenseDataSource == licenseMatcherManager.LICENSE_DATA_SOURCE_DB`:<br>
   During the database import valid SPDX license are automatically linked. 
   If however a non-spdx identifier is found then no link is created. Setting PostProcessLicenses to true forces the licenses matcher to process those unlinked license identifiers, in which is uses hash and similarity matching to figure out the exact SPDX license id of the unlinked license.
        - In case a package repository takes over the burden of validating license ids then there is no need to post process the licenses
        - In case a package repository DOEST NOT take over the burden of validating license ids then we need to post process the licenses
          Npm is an example of a package repository that does NOT validate anything really.
          So users can supply license ids such as "BSD" which is a non-existant license.
          There are BSD-2-Clause, BSD-3-Clause, etc... but no license called "BSD".
   - If `LicenseDataSource == licenseMatcherManager.LICENSE_DATA_SOURCE_SBOM`:<br>
   During the sbom creation, the sbom service is is not required to validate that the licenses denoted are valid spdx licenses (as this is the task of this service).
        - In case the package manager validate that the license ids are valid spdx licenses, then set `PostProcessLicenses` to false
        - In case the package manager does NOT validate that the license ids are valid spdx licenses, then set `PostProcessLicenses` to true


3. In `PackageRepository` you define - a to-be implemented the package repository abstraction - for the language/ecosystem to be analyzed.
 

This `PackageRepository` must provide 2 simple functions:
1. `GetPackageDenotedLicenseIds func(depName string, depVersion string, scoped bool) ([]string, error)` get all license identifiers (including non spdx identifiers) from the package data. (Example: `['MIT','BSD']`)
2. `GetPackageLicenseText func(depName string, depVersion string, scoped bool) (string, error)` get the license text of the package (if any)

If `LicenseDataSource == licenseMatcherManager.LICENSE_DATA_SOURCE_SBOM`, you must still implement this package repository abstraction. In `GetPackageDenotedLicenseIds` you may simply return an empty list, since the license list is retrieved from the sbom and not the db. But `GetPackageLicenseText` must be implemented correctly.

## Acknowledgement of Copyright and Co-Authorship

This software was developed as part of the research project “FNR JUMP SecuBox”, funded by the Luxembourg National Research Fund (FNR), grant number JUMP21/16693582/SecuBox (hereafter the “Project”).
The software was developed at the University of Luxembourg (hereafter the “University”) and is subject to its intellectual property policy. Accordingly, the copyright of this software is held by the University of Luxembourg.
The development of this software involved contributions from several researchers affiliated with the University during the Project period. Their work was instrumental in achieving the technical and scientific objectives of the Project.
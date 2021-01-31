use std::sync::Arc;

use rustsec::{
    cargo_lock,
    database::{self, Database},
};
use semver::Version;

use crate::models::crates::{
    AnalyzedDependencies, AnalyzedDependency, CrateDeps, CrateName, CrateRelease,
};

pub struct DependencyAnalyzer {
    deps: AnalyzedDependencies,
    advisory_db: Option<Arc<Database>>,
}

impl DependencyAnalyzer {
    pub fn new(deps: &CrateDeps, advisory_db: Option<Arc<Database>>) -> DependencyAnalyzer {
        DependencyAnalyzer {
            deps: AnalyzedDependencies::new(deps),
            advisory_db,
        }
    }

    fn process_single(_name: &CrateName, dep: &mut AnalyzedDependency, ver: &Version) {
        if dep.required.matches(&ver) {
            if let Some(ref mut current_latest_that_matches) = dep.latest_that_matches {
                if *current_latest_that_matches < *ver {
                    *current_latest_that_matches = ver.clone();
                }
            } else {
                dep.latest_that_matches = Some(ver.clone());
            }
        }
        if !ver.is_prerelease() {
            if let Some(ref mut current_latest) = dep.latest {
                if *current_latest < *ver {
                    *current_latest = ver.clone();
                }
            } else {
                dep.latest = Some(ver.clone());
            }
        }
    }

    pub fn process<I: IntoIterator<Item = CrateRelease>>(&mut self, releases: I) {
        for release in releases.into_iter().filter(|r| !r.yanked) {
            if let Some(main_dep) = self.deps.main.get_mut(&release.name) {
                DependencyAnalyzer::process_single(&release.name, main_dep, &release.version)
            }
            if let Some(dev_dep) = self.deps.dev.get_mut(&release.name) {
                DependencyAnalyzer::process_single(&release.name, dev_dep, &release.version)
            }
            if let Some(build_dep) = self.deps.build.get_mut(&release.name) {
                DependencyAnalyzer::process_single(&release.name, build_dep, &release.version)
            }
        }
    }

    fn process_advisory(&mut self) {
        let advisory_db = self.advisory_db.as_ref().map(|r| r.as_ref());

        // query advisory database for all latest matching dependencies
        let main_deps = self.deps.main.iter_mut();
        let dev_deps = self.deps.dev.iter_mut();
        let build_deps = self.deps.build.iter_mut();
        let deps = main_deps
            .chain(dev_deps)
            .chain(build_deps)
            .filter_map(|(name, dep)| dep.latest_that_matches.clone().map(|v| (name, dep, v)));

        for (name, dep, version) in deps {
            let name: cargo_lock::Name = name.as_ref().parse().unwrap();
            let version: cargo_lock::Version = version.to_string().parse().unwrap();
            let query = database::Query::new().package_version(name, version);

            if let Some(db) = advisory_db {
                let vulnerabilities = db.query(&query);
                if !vulnerabilities.is_empty() {
                    dep.vulnerabilities =
                        vulnerabilities.into_iter().map(|v| v.to_owned()).collect();
                }
            }
        }
    }

    pub fn finalize(mut self) -> AnalyzedDependencies {
        self.process_advisory();
        self.deps
    }
}

#[cfg(test)]
mod tests {
    use crate::models::crates::{CrateDep, CrateDeps, CrateRelease};

    use super::*;

    #[test]
    fn tracks_latest_without_matching() {
        let mut deps = CrateDeps::default();
        deps.main.insert(
            "hyper".parse().unwrap(),
            CrateDep::External("^0.11.0".parse().unwrap()),
        );

        let mut analyzer = DependencyAnalyzer::new(&deps, None);
        analyzer.process(vec![
            CrateRelease {
                name: "hyper".parse().unwrap(),
                version: "0.10.0".parse().unwrap(),
                deps: Default::default(),
                yanked: false,
            },
            CrateRelease {
                name: "hyper".parse().unwrap(),
                version: "0.10.1".parse().unwrap(),
                deps: Default::default(),
                yanked: false,
            },
        ]);

        let analyzed = analyzer.finalize();

        assert_eq!(
            analyzed.main.get("hyper").unwrap().latest_that_matches,
            None
        );
        assert_eq!(
            analyzed.main.get("hyper").unwrap().latest,
            Some("0.10.1".parse().unwrap())
        );
    }

    #[test]
    fn tracks_latest_that_matches() {
        let mut deps = CrateDeps::default();
        deps.main.insert(
            "hyper".parse().unwrap(),
            CrateDep::External("^0.10.0".parse().unwrap()),
        );

        let mut analyzer = DependencyAnalyzer::new(&deps, None);
        analyzer.process(vec![
            CrateRelease {
                name: "hyper".parse().unwrap(),
                version: "0.10.0".parse().unwrap(),
                deps: Default::default(),
                yanked: false,
            },
            CrateRelease {
                name: "hyper".parse().unwrap(),
                version: "0.10.1".parse().unwrap(),
                deps: Default::default(),
                yanked: false,
            },
            CrateRelease {
                name: "hyper".parse().unwrap(),
                version: "0.11.0".parse().unwrap(),
                deps: Default::default(),
                yanked: false,
            },
        ]);

        let analyzed = analyzer.finalize();

        assert_eq!(
            analyzed.main.get("hyper").unwrap().latest_that_matches,
            Some("0.10.1".parse().unwrap())
        );
        assert_eq!(
            analyzed.main.get("hyper").unwrap().latest,
            Some("0.11.0".parse().unwrap())
        );
    }

    #[test]
    fn skips_yanked_releases() {
        let mut deps = CrateDeps::default();
        deps.main.insert(
            "hyper".parse().unwrap(),
            CrateDep::External("^0.10.0".parse().unwrap()),
        );

        let mut analyzer = DependencyAnalyzer::new(&deps, None);
        analyzer.process(vec![
            CrateRelease {
                name: "hyper".parse().unwrap(),
                version: "0.10.0".parse().unwrap(),
                deps: Default::default(),
                yanked: false,
            },
            CrateRelease {
                name: "hyper".parse().unwrap(),
                version: "0.10.1".parse().unwrap(),
                deps: Default::default(),
                yanked: true,
            },
        ]);

        let analyzed = analyzer.finalize();

        assert_eq!(
            analyzed.main.get("hyper").unwrap().latest_that_matches,
            Some("0.10.0".parse().unwrap())
        );
        assert_eq!(
            analyzed.main.get("hyper").unwrap().latest,
            Some("0.10.0".parse().unwrap())
        );
    }

    #[test]
    fn skips_prereleases() {
        let mut deps = CrateDeps::default();
        deps.main.insert(
            "hyper".parse().unwrap(),
            CrateDep::External("^0.10.0".parse().unwrap()),
        );

        let mut analyzer = DependencyAnalyzer::new(&deps, None);
        analyzer.process(vec![
            CrateRelease {
                name: "hyper".parse().unwrap(),
                version: "0.10.0".parse().unwrap(),
                deps: Default::default(),
                yanked: false,
            },
            CrateRelease {
                name: "hyper".parse().unwrap(),
                version: "0.10.1-alpha".parse().unwrap(),
                deps: Default::default(),
                yanked: false,
            },
        ]);

        let analyzed = analyzer.finalize();

        assert_eq!(
            analyzed.main.get("hyper").unwrap().latest_that_matches,
            Some("0.10.0".parse().unwrap())
        );
        assert_eq!(
            analyzed.main.get("hyper").unwrap().latest,
            Some("0.10.0".parse().unwrap())
        );
    }
}
